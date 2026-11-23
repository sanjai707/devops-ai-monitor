"""Optional OpenTelemetry instrumentation for the FastAPI service."""
import logging
import os
import threading
import time
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)
_runtime = None

class TelemetryRuntime:
    def __init__(self, tracer_provider, meter_provider, httpx_instrumentor):
        self.tracer_provider = tracer_provider
        self.meter_provider = meter_provider
        self.httpx_instrumentor = httpx_instrumentor
        self._container_lock = threading.Lock()
        self._container_observations = {}
        self._stale_after_seconds = max(
            35.0, float(os.getenv("MONITOR_POLL_INTERVAL_SECONDS", "10")) * 3
        )

    def observe_container(self, container_id, container_name, running, restart_count, metrics):
        """Keep the latest bounded Docker snapshot for observable gauges."""
        with self._container_lock:
            self._container_observations[container_id] = {
                "name": container_name,
                "running": 1 if running else 0,
                "restart_count": int(restart_count or 0),
                "cpu_percent": metrics.get("cpu_percent"),
                "memory_percent": metrics.get("memory_percent"),
                "observed_at": time.monotonic(),
            }

    def container_observations(self, field):
        from opentelemetry.metrics import Observation

        now = time.monotonic()
        with self._container_lock:
            stale_ids = [
                container_id
                for container_id, snapshot in self._container_observations.items()
                if now - snapshot["observed_at"] > self._stale_after_seconds
            ]
            for container_id in stale_ids:
                self._container_observations.pop(container_id, None)
            snapshots = list(self._container_observations.items())
        observations = []
        for container_id, snapshot in snapshots:
            value = snapshot.get(field)
            if value is None:
                continue
            observations.append(Observation(value, {
                "container.name": snapshot["name"],
                "container.id": container_id[:12],
            }))
        return observations

    def shutdown(self):
        global _runtime
        try:
            self.httpx_instrumentor.uninstrument()
        except Exception:
            logger.debug("HTTPX telemetry uninstrument failed", exc_info=True)
        for provider in (self.tracer_provider, self.meter_provider):
            try:
                provider.force_flush(timeout_millis=5000)
            except Exception:
                logger.debug("OpenTelemetry force flush failed", exc_info=True)
            try:
                provider.shutdown()
            except Exception:
                logger.debug("OpenTelemetry provider shutdown failed", exc_info=True)
        _runtime = None

def record_container_observation(container_id, container_name, running, restart_count, metrics=None):
    """Update optional Docker container gauges; no-op when telemetry is disabled."""
    if _runtime is not None:
        _runtime.observe_container(
            container_id, container_name, running, restart_count, metrics or {}
        )

def _sanitize_server_request(span, scope):
    """Keep query-string values out of server spans."""
    if not span or not span.is_recording():
        return
    headers = {
        key.decode("latin1").lower(): value.decode("latin1")
        for key, value in scope.get("headers", [])
    }
    server = scope.get("server") or ("localhost", None)
    host = headers.get("host") or server[0]
    scheme = scope.get("scheme", "http")
    path = scope.get("path", "/")
    span.set_attribute("url.full", f"{scheme}://{host}{path}")
    span.set_attribute("url.query", "[REDACTED]" if scope.get("query_string") else "")

def _sanitize_client_request(span, request):
    """Remove query values from outbound HTTP span URLs."""
    if not span or not span.is_recording():
        return
    safe_url = request.url.copy_with(query=None, fragment=None)
    span.set_attribute("url.full", str(safe_url))
    span.set_attribute("url.query", "[REDACTED]" if request.url.query else "")

def configure_telemetry(app):
    """Enable FastAPI traces/metrics only when explicitly requested."""
    global _runtime
    enabled = os.getenv("OTEL_ENABLED", "false").strip().lower() in {
        "1", "true", "yes", "on"
    }
    if not enabled:
        return None
    endpoint = os.getenv(
        "OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4318"
    ).strip().rstrip("/")
    parsed = urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(
            "OTEL_EXPORTER_OTLP_ENDPOINT must be an absolute http:// or https:// URL"
        )
    try:
        from opentelemetry import metrics, trace
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as exc:
        raise RuntimeError(
            "OpenTelemetry is enabled but its Python packages are not installed"
        ) from exc

    service_name = os.getenv("OTEL_SERVICE_NAME", "devops-ai-monitor-api")
    resource = Resource.create({
        "service.name": service_name,
        "service.version": "0.4.0",
        "deployment.environment": os.getenv("OTEL_DEPLOYMENT_ENVIRONMENT", "local"),
    })
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(BatchSpanProcessor(
        OTLPSpanExporter(endpoint=endpoint + "/v1/traces", timeout=5)
    ))
    metric_reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(endpoint=endpoint + "/v1/metrics", timeout=5),
        export_interval_millis=15000,
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
    trace.set_tracer_provider(tracer_provider)
    metrics.set_meter_provider(meter_provider)

    FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=tracer_provider,
        meter_provider=meter_provider,
        server_request_hook=_sanitize_server_request,
        excluded_urls="/health,/telemetry/status",
    )
    httpx_instrumentor = HTTPXClientInstrumentor()
    httpx_instrumentor.instrument(
        tracer_provider=tracer_provider,
        request_hook=_sanitize_client_request,
    )

    runtime = TelemetryRuntime(tracer_provider, meter_provider, httpx_instrumentor)
    meter = metrics.get_meter("devops-ai-monitor.docker")
    meter.create_observable_gauge(
        "devops_ai_monitor.container.cpu_usage_percent",
        callbacks=[lambda options: runtime.container_observations("cpu_percent")],
        unit="%",
        description="Latest Docker container CPU utilization percentage",
    )
    meter.create_observable_gauge(
        "devops_ai_monitor.container.memory_usage_percent",
        callbacks=[lambda options: runtime.container_observations("memory_percent")],
        unit="%",
        description="Latest Docker container memory utilization percentage",
    )
    meter.create_observable_gauge(
        "devops_ai_monitor.container.running",
        callbacks=[lambda options: runtime.container_observations("running")],
        unit="1",
        description="Whether a recently observed Docker container is running",
    )
    meter.create_observable_gauge(
        "devops_ai_monitor.container.restart_count",
        callbacks=[lambda options: runtime.container_observations("restart_count")],
        unit="1",
        description="Latest Docker container restart count",
    )

    _runtime = runtime
    logger.info(
        "OpenTelemetry enabled for %s; exporting OTLP/HTTP to %s",
        service_name, endpoint,
    )
    return runtime

def get_telemetry_status(runtime):
    enabled = runtime is not None
    return {
        "enabled": enabled,
        "service_name": os.getenv("OTEL_SERVICE_NAME", "devops-ai-monitor-api"),
        "signals": ["traces", "metrics"] if enabled else [],
        "protocol": "otlp_http" if enabled else None,
        "endpoint": os.getenv(
            "OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4318"
        ).strip().rstrip("/") if enabled else None,
    }
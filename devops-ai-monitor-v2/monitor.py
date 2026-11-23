import threading
import time
import logging
import sqlite3
from datetime import datetime, timezone

import docker

from telemetry import record_container_observation

from incident_manager import IncidentManager
from thresholds import (
    CPU_WARNING_PERCENT,
    CPU_CRITICAL_PERCENT,
    MEMORY_WARNING_PERCENT,
    MEMORY_CRITICAL_PERCENT,
    MONITOR_POLL_INTERVAL_SECONDS,
)

logger = logging.getLogger(__name__)


class DockerMonitor:
    def __init__(self, database, on_incident=None):
        self.database = database
        self.on_incident = on_incident
        self.incidents = IncidentManager(database, on_incident=self._queue_investigation)
        self.poll_interval = MONITOR_POLL_INTERVAL_SECONDS
        self.stop_event = threading.Event()
        self.status_lock = threading.Lock()
        self.thread = None
        self.baseline = {}
        self.initialized = False
        self.status = {
            "running": False,
            "poll_interval_seconds": self.poll_interval,
            "poll_count": 0,
            "last_poll_at": None,
            "last_error": None,
            "containers_observed": 0,
        }

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name="docker-monitor", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=5)

    def get_status(self):
        with self.status_lock:
            return dict(self.status)

    def _queue_investigation(self, incident_id, force=False):
        if not self.on_incident:
            return
        try:
            self.on_incident(incident_id, force=force)
        except Exception as exc:
            with self.status_lock:
                self.status["last_error"] = (
                    f"Could not queue investigation for incident {incident_id}: {exc}"
                )

    def _run(self):
        self.status["running"] = True
        while not self.stop_event.is_set():
            try:
                self._poll()
            except Exception as exc:
                self.status["last_error"] = str(exc)
            self.stop_event.wait(self.poll_interval)
        self.status["running"] = False

    def _poll(self):
        self.status["last_error"] = None
        client = docker.from_env()
        try:
            client.ping()
            containers = client.containers.list(all=True)
            current_ids = set()

            for container in containers:
                container.reload()
                container_id = container.short_id
                current_ids.add(container_id)
                state = container.attrs.get("State", {})
                status = state.get("Status", container.status)
                restart_count = container.attrs.get("RestartCount", 0)
                health = state.get("Health") or {}
                health_status = health.get("Status")

                prior = self.baseline.get(container_id)

                if prior is not None:
                    prior_running = prior["running"]
                    prior_status = prior["status"]
                    stopped_fingerprint = f"{container_id}:unexpected_stop"

                    if prior_running and status in ("exited", "dead"):
                        self.incidents.open_or_update(
                            stopped_fingerprint,
                            container_id,
                            container.name,
                            "container_stopped",
                            "critical",
                            f"Container {container.name} stopped unexpectedly",
                            {"status": status, "exit_code": state.get("ExitCode"),
                             "oom_killed": state.get("OOMKilled")},
                        )
                    elif status == "running" and prior_status in ("exited", "dead"):
                        self.incidents.resolve(stopped_fingerprint)

                    if restart_count > prior["restart_count"]:
                        fingerprint = f"{container_id}:restart:{restart_count}"
                        self.incidents.open_or_update(
                            fingerprint,
                            container_id,
                            container.name,
                            "restart_count_increased",
                            "warning",
                            f"Container {container.name} restarted",
                            {"previous_restart_count": prior["restart_count"],
                             "current_restart_count": restart_count},
                        )

                if health_status == "unhealthy":
                    fingerprint = f"{container_id}:health_unhealthy"
                    self.incidents.open_or_update(
                        fingerprint,
                        container_id,
                        container.name,
                        "container_unhealthy",
                        "critical",
                        f"Container {container.name} is unhealthy",
                        {"health_status": health_status,
                         "failing_streak": health.get("FailingStreak", 0)},
                    )
                elif health_status in ("healthy", None):
                    self.incidents.resolve(f"{container_id}:health_unhealthy")

                if status == "running":
                    self._evaluate_resource_metrics(
                        container, container_id, restart_count, health_status
                    )
                else:
                    self._record_metric_sample(
                        container,
                        status,
                        restart_count,
                        health_status,
                    )
                    self.incidents.resolve(f"{container_id}:cpu_warning")
                    self.incidents.resolve(f"{container_id}:cpu_critical")
                    self.incidents.resolve(f"{container_id}:memory_warning")
                    self.incidents.resolve(f"{container_id}:memory_critical")

                self.baseline[container_id] = {
                    "running": status == "running",
                    "status": status,
                    "restart_count": restart_count,
                }

            self.status["containers_observed"] = len(current_ids)
            self.status["poll_count"] += 1
            self.status["last_poll_at"] = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            self.initialized = True
        finally:
            client.close()

    def _evaluate_resource_metrics(
        self, container, container_id, restart_count=0, health_status=None
    ):
        try:
            stats = container.stats(stream=False)
        except docker.errors.APIError as exc:
            self.status["last_error"] = f"Metrics unavailable for {container.name}: {exc}"
            self._record_metric_sample(
                container, "running", restart_count, health_status
            )
            return

        cpu = self._cpu_percent(stats)
        memory_usage, memory_limit, memory_percent = self._memory(stats)
        networks = stats.get("networks", {}) or {}
        self._record_metric_sample(
            container,
            "running",
            restart_count,
            health_status,
            {
                "cpu_percent": cpu,
                "memory_usage_bytes": memory_usage,
                "memory_limit_bytes": memory_limit,
                "memory_percent": memory_percent,
                "network_rx_bytes": sum(
                    item.get("rx_bytes", 0) for item in networks.values()
                ),
                "network_tx_bytes": sum(
                    item.get("tx_bytes", 0) for item in networks.values()
                ),
            },
        )

        cpu_warning = f"{container_id}:cpu_warning"
        cpu_critical = f"{container_id}:cpu_critical"
        if cpu >= CPU_CRITICAL_PERCENT:
            self.incidents.resolve(cpu_warning)
            self.incidents.open_or_update(
                cpu_critical, container_id, container.name, "cpu_usage",
                "critical", f"Critical CPU usage on {container.name}",
                {"cpu_percent": cpu, "threshold_percent": CPU_CRITICAL_PERCENT},
            )
        elif cpu >= CPU_WARNING_PERCENT:
            self.incidents.resolve(cpu_critical)
            self.incidents.open_or_update(
                cpu_warning, container_id, container.name, "cpu_usage",
                "warning", f"High CPU usage on {container.name}",
                {"cpu_percent": cpu, "threshold_percent": CPU_WARNING_PERCENT},
            )
        else:
            self.incidents.resolve(cpu_warning)
            self.incidents.resolve(cpu_critical)

        memory_warning = f"{container_id}:memory_warning"
        memory_critical = f"{container_id}:memory_critical"
        if memory_percent >= MEMORY_CRITICAL_PERCENT:
            self.incidents.resolve(memory_warning)
            self.incidents.open_or_update(
                memory_critical, container_id, container.name, "memory_usage",
                "critical", f"Critical memory usage on {container.name}",
                {"memory_usage_bytes": memory_usage, "memory_limit_bytes": memory_limit,
                 "memory_percent": memory_percent,
                 "threshold_percent": MEMORY_CRITICAL_PERCENT},
            )
        elif memory_percent >= MEMORY_WARNING_PERCENT:
            self.incidents.resolve(memory_critical)
            self.incidents.open_or_update(
                memory_warning, container_id, container.name, "memory_usage",
                "warning", f"High memory usage on {container.name}",
                {"memory_usage_bytes": memory_usage, "memory_limit_bytes": memory_limit,
                 "memory_percent": memory_percent,
                 "threshold_percent": MEMORY_WARNING_PERCENT},
            )
        else:
            self.incidents.resolve(memory_warning)
            self.incidents.resolve(memory_critical)

    def _record_metric_sample(
        self, container, status, restart_count, health_status, metrics=None
    ):
        record_container_observation(
            container.id,
            container.name,
            status == "running",
            restart_count,
            metrics or {},
        )
        try:
            self.database.record_metric_sample(
                {
                    "container_id": container.id,
                    "container_name": container.name,
                    "observed_at": datetime.now(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                    "running": status == "running",
                    "restart_count": restart_count,
                    "health_status": health_status,
                    **(metrics or {}),
                }
            )
        except sqlite3.Error as exc:
            self.status["last_error"] = (
                f"Could not persist metrics for {container.name}: {type(exc).__name__}"
            )
            logger.error(
                "Could not persist metric sample for container %s (%s)",
                container.short_id,
                type(exc).__name__,
            )

    def _cpu_percent(self, stats):
        cpu_stats = stats.get("cpu_stats", {})
        precpu_stats = stats.get("precpu_stats", {})
        cpu_usage = cpu_stats.get("cpu_usage", {})
        precpu_usage = precpu_stats.get("cpu_usage", {})
        cpu_delta = cpu_usage.get("total_usage", 0) - precpu_usage.get("total_usage", 0)
        system_delta = cpu_stats.get("system_cpu_usage", 0) - precpu_stats.get("system_cpu_usage", 0)
        online_cpus = cpu_stats.get("online_cpus") or len(cpu_usage.get("percpu_usage") or []) or 1
        if cpu_delta > 0 and system_delta > 0:
            return round((cpu_delta / system_delta) * online_cpus * 100.0, 2)
        return 0.0

    def _memory(self, stats):
        memory_stats = stats.get("memory_stats", {})
        usage = memory_stats.get("usage", 0)
        cache = memory_stats.get("stats", {}).get("cache", 0)
        usage = max(0, usage - cache)
        limit = memory_stats.get("limit", 0)
        percent = round((usage / limit * 100.0) if limit else 0.0, 2)
        return usage, limit, percent
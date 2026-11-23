import os
import unittest
from unittest.mock import patch

from fastapi import FastAPI

from telemetry import configure_telemetry, get_telemetry_status


class TelemetryTests(unittest.TestCase):
    def test_telemetry_is_disabled_by_default(self):
        with patch.dict(os.environ, {"OTEL_ENABLED": "false"}, clear=False):
            runtime = configure_telemetry(FastAPI())
        self.assertIsNone(runtime)
        status = get_telemetry_status(runtime)
        self.assertFalse(status["enabled"])
        self.assertEqual(status["signals"], [])

    def test_invalid_otlp_endpoint_fails_fast_when_enabled(self):
        with patch.dict(os.environ, {
            "OTEL_ENABLED": "true",
            "OTEL_EXPORTER_OTLP_ENDPOINT": "ftp://collector:4318",
        }, clear=False):
            with self.assertRaisesRegex(ValueError, "absolute http"):
                configure_telemetry(FastAPI())

    def test_telemetry_status_does_not_expose_endpoint_when_disabled(self):
        with patch.dict(os.environ, {
            "OTEL_ENABLED": "false",
            "OTEL_EXPORTER_OTLP_ENDPOINT": "http://private-collector:4318",
        }, clear=False):
            status = get_telemetry_status(None)
        self.assertIsNone(status["endpoint"])
        self.assertIsNone(status["protocol"])


if __name__ == "__main__":
    unittest.main()

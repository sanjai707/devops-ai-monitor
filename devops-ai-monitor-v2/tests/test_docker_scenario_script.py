import unittest
from pathlib import Path


class DockerScenarioScriptTests(unittest.TestCase):
    def test_missing_image_detection_does_not_depend_on_erroring_inspect(self):
        script = (
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "run-docker-scenarios.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn('docker image ls --format "{{.Repository}}:{{.Tag}}"', script)
        self.assertIn("$availableImages -notcontains $Image", script)
        self.assertNotIn("docker image inspect $Image", script)

    def test_memory_scenario_uses_bounded_tmpfs_allocation(self):
        script = (
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "run-docker-scenarios.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn('"--memory", "128m"', script)
        self.assertIn('"--tmpfs", "/memory:size=120m"', script)
        self.assertIn("dd if=/dev/zero of=/memory/probe bs=1M count=112", script)

    def test_restart_loop_stays_alive_long_enough_for_monitor_poll(self):
        script = (
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "run-docker-scenarios.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn('"sleep 12; exit 1"', script)


if __name__ == "__main__":
    unittest.main()

import docker

from providers.base import InfrastructureProvider


class DockerProvider(InfrastructureProvider):
    def name(self):
        return "docker"

    def status(self):
        client = None
        try:
            client = docker.from_env()
            client.ping()
            return {"provider": "docker", "enabled": True, "connected": True, "error": None}
        except Exception as exc:
            return {
                "provider": "docker",
                "enabled": True,
                "connected": False,
                "error": type(exc).__name__,
            }
        finally:
            if client is not None:
                client.close()

    def list_resources(self):
        client = docker.from_env()
        try:
            client.ping()
            return [
                {
                    "provider": "docker",
                    "id": container.short_id,
                    "name": container.name,
                    "status": container.status,
                }
                for container in client.containers.list(all=True)
            ]
        finally:
            client.close()

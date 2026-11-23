from abc import ABC, abstractmethod


class InfrastructureProvider(ABC):
    @abstractmethod
    def name(self):
        raise NotImplementedError

    @abstractmethod
    def status(self):
        raise NotImplementedError

    @abstractmethod
    def list_resources(self):
        raise NotImplementedError

from _typeshed import Incomplete
from ipaplatform.base import services as base_services
from ipaplatform.paths import paths as paths

logger: Incomplete
redhat_system_units: Incomplete

class RedHatService(base_services.SystemdService):
    system_units: Incomplete
    def __init__(
        self, service_name, api: Incomplete | None = ...
    ) -> None: ...

class RedHatDirectoryService(RedHatService):
    def is_installed(self, instance_name): ...
    def restart(
        self,
        instance_name: str = ...,
        capture_output: bool = ...,
        wait: bool = ...,
        ldapi: bool = ...,
    ) -> None: ...
    def start(
        self,
        instance_name: str = ...,
        capture_output: bool = ...,
        wait: bool = ...,
        ldapi: bool = ...,
    ) -> None: ...

class RedHatIPAService(RedHatService):
    def enable(self, instance_name: str = ...) -> None: ...

class RedHatCAService(RedHatService):
    def wait_until_running(self) -> None: ...
    def is_running(self, instance_name: str = ..., wait: bool = ...): ...

def redhat_service_class_factory(name, api: Incomplete | None = ...): ...

class RedHatServices(base_services.KnownServices):
    def __init__(self) -> None: ...
    def service_class_factory(self, name, api: Incomplete | None = ...): ...

timedate_services: Incomplete
service = redhat_service_class_factory
knownservices: Incomplete

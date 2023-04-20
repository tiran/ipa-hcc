from _typeshed import Incomplete
from ipaplatform.redhat import services as redhat_services

fedora_system_units: Incomplete

class FedoraService(redhat_services.RedHatService):
    system_units: Incomplete

def fedora_service_class_factory(name, api: Incomplete | None = ...): ...

class FedoraServices(redhat_services.RedHatServices):
    def service_class_factory(self, name, api: Incomplete | None = ...): ...

timedate_services: Incomplete
service = fedora_service_class_factory
knownservices: Incomplete

import abc
from _typeshed import Incomplete
from ipaserver.masters import (
    ENABLED_SERVICE as ENABLED_SERVICE,
    HIDDEN_SERVICE as HIDDEN_SERVICE,
)
from typing import NamedTuple

unicode = str
ENABLED: str
CONFIGURED: str
HIDDEN: str
ABSENT: str

class LDAPBasedProperty:
    attr_name: Incomplete
    name: Incomplete
    attr_name_hidden: Incomplete
    def __init__(self, attr_name, name) -> None: ...

class BaseServerRole(LDAPBasedProperty, metaclass=abc.ABCMeta):
    def create_role_status_dict(self, server, status): ...
    @abc.abstractmethod
    def create_search_params(
        self, ldap, api_instance, server: Incomplete | None = ...
    ): ...
    @abc.abstractmethod
    def get_result_from_entries(self, entries): ...
    def status(
        self, api_instance, server: Incomplete | None = ..., attrs_list=...
    ): ...

class ServerAttribute(LDAPBasedProperty):
    associated_role_name: Incomplete
    associated_service_name: Incomplete
    ipa_config_string_value: Incomplete
    def __init__(
        self,
        attr_name,
        name,
        associated_role_name,
        associated_service_name,
        ipa_config_string_value,
    ) -> None: ...
    @property
    def associated_role(self): ...
    def create_search_filter(self, ldap): ...
    def get(self, api_instance): ...
    def set(self, api_instance, masters) -> None: ...

class SingleValuedServerAttribute(ServerAttribute):
    def set(self, api_instance, masters) -> None: ...
    def get(self, api_instance): ...

class _Service(NamedTuple):
    name: Incomplete
    enabled: Incomplete
    hidden: Incomplete

class ServiceBasedRole(BaseServerRole):
    component_services: Incomplete
    def __init__(self, attr_name, name, component_services) -> None: ...
    def get_result_from_entries(self, entries): ...
    def create_search_params(
        self, ldap, api_instance, server: Incomplete | None = ...
    ): ...
    def status(
        self, api_instance, server: Incomplete | None = ..., attrs_list=...
    ): ...

class ADtrustBasedRole(BaseServerRole):
    def get_result_from_entries(self, entries): ...
    def create_search_params(
        self, ldap, api_instance, server: Incomplete | None = ...
    ): ...

role_instances: Incomplete
attribute_instances: Incomplete

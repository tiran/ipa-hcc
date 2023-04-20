from _typeshed import Incomplete
from ipalib.backend import Backend
from ipaserver.servroles import (
    ENABLED as ENABLED,
    HIDDEN as HIDDEN,
    SingleValuedServerAttribute as SingleValuedServerAttribute,
    attribute_instances as attribute_instances,
    role_instances as role_instances,
)

unicode = str
register: Incomplete

class serverroles(Backend):
    role_names: Incomplete
    attributes: Incomplete
    def __init__(self, api_instance) -> None: ...
    def server_role_search(
        self,
        server_server: Incomplete | None = ...,
        role_servrole: Incomplete | None = ...,
        status: Incomplete | None = ...,
    ): ...
    def server_role_retrieve(self, server_server, role_servrole): ...
    def config_retrieve(self, servrole, include_hidden: bool = ...): ...
    def config_update(self, **attrs_values) -> None: ...

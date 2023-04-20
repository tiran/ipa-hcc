from _typeshed import Incomplete
from collections.abc import Generator
from ipalib.crud import Retrieve, Search
from ipalib.frontend import Object

register: Incomplete

class server_role(Object):
    backend_name: str
    object_name: Incomplete
    object_name_plural: Incomplete
    default_attributes: Incomplete
    label: Incomplete
    label_singular: Incomplete
    takes_params: Incomplete
    def ensure_master_exists(self, fqdn) -> None: ...

class server_role_show(Retrieve):
    __doc__: Incomplete
    obj_name: str
    attr_name: str
    def get_args(self) -> Generator[Incomplete, None, None]: ...
    def execute(self, *keys, **options): ...

class server_role_find(Search):
    __doc__: Incomplete
    obj_name: str
    attr_name: str
    msg_summary: Incomplete
    takes_options: Incomplete
    def execute(self, *keys, **options): ...

class servrole(Object):
    object_name: Incomplete
    object_name_plural: Incomplete
    takes_params: Incomplete

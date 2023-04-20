from _typeshed import Incomplete
from ipalib import plugable as plugable
from ipalib.errors import (
    CommandError as CommandError,
    InternalError as InternalError,
    PublicError as PublicError,
)
from ipalib.request import (
    Connection as Connection,
    context as context,
    destroy_context as destroy_context,
)

logger: Incomplete

class Backend(plugable.Plugin): ...

class Connectible(Backend):
    id: Incomplete
    def __init__(self, api, shared_instance: bool = ...) -> None: ...
    def connect(self, *args, **kw) -> None: ...
    def create_connection(self, *args, **kw) -> None: ...
    def disconnect(self) -> None: ...
    def destroy_connection(self) -> None: ...
    def isconnected(self): ...
    conn: Incomplete

class Executioner(Backend):
    def create_context(
        self,
        ccache: Incomplete | None = ...,
        client_ip: Incomplete | None = ...,
    ) -> None: ...
    def destroy_context(self) -> None: ...
    def execute(self, _name, *args, **options): ...

from _typeshed import Incomplete
from typing import NamedTuple

logger: Incomplete
CONFIGURED_SERVICE: str
ENABLED_SERVICE: str
HIDDEN_SERVICE: str

class service_definition(NamedTuple):
    systemd_name: Incomplete
    startorder: Incomplete
    service_entry: Incomplete

SERVICES: Incomplete
SERVICE_LIST: Incomplete

def find_providing_servers(
    svcname, conn: Incomplete | None = ..., preferred_hosts=..., api=...
): ...
def find_providing_server(
    svcname, conn: Incomplete | None = ..., preferred_hosts=..., api=...
): ...
def get_masters(conn: Incomplete | None = ..., api=...): ...
def is_service_enabled(svcname, conn: Incomplete | None = ..., api=...): ...

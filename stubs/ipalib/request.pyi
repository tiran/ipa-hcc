from _typeshed import Incomplete
from collections.abc import Generator
from ipalib.base import ReadOnly as ReadOnly, lock as lock
from ipalib.constants import CALLABLE_ERROR as CALLABLE_ERROR

context: Incomplete

class _FrameContext: ...

def context_frame() -> Generator[None, None, None]: ...

class Connection(ReadOnly):
    conn: Incomplete
    disconnect: Incomplete
    def __init__(self, conn, disconnect) -> None: ...

def destroy_context() -> None: ...

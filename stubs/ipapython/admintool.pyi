SUCCESS: int
SERVER_INSTALL_ERROR: int
SERVER_NOT_CONFIGURED: int

class ScriptError(Exception):
    rval: int
    def __init__(self, msg: str = ..., rval: int = ...) -> None: ...
    @property
    def msg(self): ...

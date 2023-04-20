def booted() -> bool: ...
def notify(
    status: str,
    unset_environment: bool = ...,
    pid: int = ...,
    fds: list[int] | None = None,
) -> bool: ...

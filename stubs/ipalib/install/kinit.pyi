from _typeshed import Incomplete

logger: Incomplete
KRB5_KDC_UNREACH: int
KRB5KDC_ERR_SVC_UNAVAILABLE: int

def kinit_keytab(
    principal,
    keytab,
    ccache_name,
    config: Incomplete | None = ...,
    attempts: int = ...,
): ...
def kinit_password(
    principal,
    password,
    ccache_name,
    config: Incomplete | None = ...,
    armor_ccache_name: Incomplete | None = ...,
    canonicalize: bool = ...,
    enterprise: bool = ...,
    lifetime: Incomplete | None = ...,
) -> None: ...
def kinit_armor(
    ccache_name, pkinit_anchors: Incomplete | None = ...
) -> None: ...
def kinit_pkinit(
    principal,
    user_identity,
    ccache_name,
    config: Incomplete | None = ...,
    pkinit_anchors: Incomplete | None = ...,
) -> None: ...

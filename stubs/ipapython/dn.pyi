from _typeshed import Incomplete

unicode = str

class AVA:
    def __init__(self, *args) -> None: ...
    attr: Incomplete
    value: Incomplete
    def to_openldap(self): ...
    def __getitem__(self, key): ...
    def __hash__(self): ...
    def __eq__(self, other): ...
    def __ne__(self, other): ...
    def __lt__(self, other): ...

class RDN:
    AVA_type: Incomplete
    def __init__(self, *args, **kwds) -> None: ...
    def to_openldap(self): ...
    def __iter__(self): ...
    def __len__(self): ...
    def __getitem__(self, key): ...
    attr: Incomplete
    value: Incomplete
    def __hash__(self): ...
    def __eq__(self, other): ...
    def __ne__(self, other): ...
    def __lt__(self, other): ...
    def __add__(self, other): ...

class DN:
    AVA_type: Incomplete
    RDN_type: Incomplete
    rdns: Incomplete
    def __init__(self, *args, **kwds) -> None: ...
    def __deepcopy__(self, memo): ...
    def ldap_text(self): ...
    def x500_text(self): ...
    def __iter__(self): ...
    def __len__(self): ...
    def __getitem__(self, key): ...
    def __hash__(self): ...
    def __eq__(self, other): ...
    def __ne__(self, other): ...
    def __lt__(self, other): ...
    def __add__(self, other): ...
    def startswith(self, prefix, start: int = ..., end=...): ...
    def endswith(self, suffix, start: int = ..., end=...): ...
    def __contains__(self, other): ...
    def find(
        self,
        pattern,
        start: Incomplete | None = ...,
        end: Incomplete | None = ...,
    ): ...
    def index(
        self,
        pattern,
        start: Incomplete | None = ...,
        end: Incomplete | None = ...,
    ): ...
    def rfind(
        self,
        pattern,
        start: Incomplete | None = ...,
        end: Incomplete | None = ...,
    ): ...
    def rindex(
        self,
        pattern,
        start: Incomplete | None = ...,
        end: Incomplete | None = ...,
    ): ...

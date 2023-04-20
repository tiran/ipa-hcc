from _typeshed import Incomplete

class _Entity(str):
    def __new__(cls, name): ...
    def __init__(self, name) -> None: ...

class User(_Entity):
    @property
    def entity(self): ...
    @property
    def uid(self): ...
    @property
    def pgid(self): ...
    def chown(self, path, gid: Incomplete | None = ..., **kwargs) -> None: ...

class Group(_Entity):
    @property
    def entity(self): ...
    @property
    def gid(self): ...
    def chgrp(self, path, **kwargs) -> None: ...

class BaseConstantsNamespace:
    IS_64BITS: Incomplete
    DEFAULT_ADMIN_SHELL: str
    DEFAULT_SHELL: str
    IPAAPI_USER: Incomplete
    IPAAPI_GROUP: Incomplete
    DS_USER: Incomplete
    DS_GROUP: Incomplete
    HTTPD_USER: Incomplete
    HTTPD_GROUP: Incomplete
    GSSPROXY_USER: Incomplete
    IPA_ADTRUST_PACKAGE_NAME: str
    IPA_DNS_PACKAGE_NAME: str
    KDCPROXY_USER: Incomplete
    NAMED_USER: Incomplete
    NAMED_GROUP: Incomplete
    NAMED_DATA_DIR: str
    NAMED_OPTIONS_VAR: str
    NAMED_OPENSSL_ENGINE: Incomplete
    NAMED_ZONE_COMMENT: str
    PKI_USER: Incomplete
    PKI_GROUP: Incomplete
    NTPD_OPTS_VAR: str
    NTPD_OPTS_QUOTE: str
    ODS_USER: Incomplete
    ODS_GROUP: Incomplete
    SECURE_NFS_VAR: str
    SELINUX_BOOLEAN_ADTRUST: Incomplete
    SELINUX_BOOLEAN_HTTPD: Incomplete
    SELINUX_BOOLEAN_SMBSERVICE: Incomplete
    SELINUX_MCS_MAX: int
    SELINUX_MCS_REGEX: str
    SELINUX_MLS_MAX: int
    SELINUX_MLS_REGEX: str
    SELINUX_USER_REGEX: str
    SELINUX_USERMAP_DEFAULT: str
    SELINUX_USERMAP_ORDER: str
    SSSD_USER: Incomplete
    MOD_WSGI_PYTHON2: Incomplete
    MOD_WSGI_PYTHON3: Incomplete
    WSGI_PROCESSES: Incomplete
    TLS_HIGH_CIPHERS: str

constants: Incomplete

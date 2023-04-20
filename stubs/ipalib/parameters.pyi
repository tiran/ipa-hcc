from _typeshed import Incomplete
from collections.abc import Generator
from ipalib.base import check_name as check_name
from ipalib.constants import (
    CALLABLE_ERROR as CALLABLE_ERROR,
    LDAP_GENERALIZED_TIME_FORMAT as LDAP_GENERALIZED_TIME_FORMAT,
    TYPE_ERROR as TYPE_ERROR,
)
from ipalib.errors import (
    Base64DecodeError as Base64DecodeError,
    CertificateFormatError as CertificateFormatError,
    CertificateOperationError as CertificateOperationError,
    ConversionError as ConversionError,
    PasswordMismatch as PasswordMismatch,
    RequirementError as RequirementError,
    ValidationError as ValidationError,
)
from ipalib.plugable import ReadOnly as ReadOnly, lock as lock
from ipalib.text import FixMe as FixMe, Gettext as Gettext
from ipalib.util import (
    apirepr as apirepr,
    json_serialize as json_serialize,
    strip_csr_header as strip_csr_header,
    validate_idna_domain as validate_idna_domain,
)
from ipalib.x509 import (
    IPACertificate as IPACertificate,
    default_backend as default_backend,
    load_der_x509_certificate as load_der_x509_certificate,
)

MAX_UINT32: Incomplete
MAX_SAFE_INTEGER: Incomplete
MIN_SAFE_INTEGER: Incomplete
unicode = str

class DefaultFrom(ReadOnly):
    callback: Incomplete
    keys: Incomplete
    def __init__(self, callback, *keys) -> None: ...
    def __call__(self, **kw): ...
    def __json__(self): ...

def parse_param_spec(spec): ...

class Param(ReadOnly):
    type: Incomplete
    type_error: Incomplete
    scalar_error: Incomplete
    password: bool
    kwargs: Incomplete
    @property
    def allowed_types(self): ...
    param_spec: Incomplete
    name: Incomplete
    nice: Incomplete
    class_rules: Incomplete
    rules: Incomplete
    all_rules: Incomplete
    def __init__(self, name, *rules, **kw) -> None: ...
    def __call__(self, value, **kw): ...
    def get_param_name(self): ...
    def kw(self) -> Generator[Incomplete, None, None]: ...
    def use_in_context(self, env): ...
    def safe_value(self, value): ...
    def clone(self, **overrides): ...
    def clone_rename(self, name, **overrides): ...
    def clone_retype(self, name, klass, **overrides): ...
    def normalize(self, value): ...
    def convert(self, value): ...
    def validate(self, value, supplied: Incomplete | None = ...) -> None: ...
    def get_default(self, **kw): ...
    def sort_key(self, value): ...
    def __json__(self): ...

class Bool(Param):
    type: Incomplete
    type_error: Incomplete
    kwargs: Incomplete

class Flag(Bool):
    def __init__(self, name, *rules, **kw) -> None: ...

class Number(Param): ...

class Int(Number):
    type: Incomplete
    allowed_types: Incomplete
    type_error: Incomplete
    MININT: Incomplete
    MAXINT: Incomplete
    MAX_UINT32: Incomplete
    MAX_SAFE_INTEGER: Incomplete
    MIN_SAFE_INTEGER: Incomplete
    kwargs: Incomplete
    @staticmethod
    def convert_int(value): ...
    def __init__(self, name, *rules, **kw) -> None: ...

class Decimal(Number):
    type: Incomplete
    type_error: Incomplete
    kwargs: Incomplete
    def __init__(self, name, *rules, **kw) -> None: ...

class Data(Param):
    kwargs: Incomplete
    re: Incomplete
    re_errmsg: Incomplete
    def __init__(self, name, *rules, **kw) -> None: ...

class Bytes(Data):
    type: Incomplete
    type_error: Incomplete
    kwargs: Incomplete
    re: Incomplete
    re_errmsg: Incomplete
    def __init__(self, name, *rules, **kw) -> None: ...

class Certificate(Param):
    type: Incomplete
    type_error: Incomplete
    allowed_types: Incomplete

class CertificateSigningRequest(Param):
    type: Incomplete
    type_error: Incomplete
    allowed_types: Incomplete

class Str(Data):
    kwargs: Incomplete
    type: Incomplete
    type_error: Incomplete
    re: Incomplete
    re_errmsg: Incomplete
    def __init__(self, name, *rules, **kw) -> None: ...
    def sort_key(self, value): ...

class IA5Str(Str):
    def __init__(self, name, *rules, **kw) -> None: ...

class Password(Str):
    kwargs: Incomplete
    password: bool

class Enum(Param):
    kwargs: Incomplete
    def __init__(self, name, *rules, **kw) -> None: ...

class BytesEnum(Enum):
    type: Incomplete

class StrEnum(Enum):
    type: Incomplete

class IntEnum(Enum):
    type: Incomplete
    allowed_types: Incomplete
    type_error: Incomplete

class Any(Param):
    type: Incomplete

class File(Str):
    open_mode: str
    kwargs: Incomplete

class BinaryFile(Bytes):
    open_mode: str
    kwargs: Incomplete

class DateTime(Param):
    accepted_formats: Incomplete
    type: Incomplete
    type_error: Incomplete

class AccessTime(Str): ...

class DNParam(Param):
    type: Incomplete

def create_param(spec): ...

class DNSNameParam(Param):
    type: Incomplete
    type_error: Incomplete
    kwargs: Incomplete
    def __init__(self, name, *rules, **kw) -> None: ...

class Dict(Param):
    type: Incomplete
    type_error: Incomplete

class Principal(Param):
    type: Incomplete
    type_error: Incomplete
    kwargs: Incomplete
    @property
    def allowed_types(self): ...

def create_signature(command): ...

class SerialNumber(Str):
    type: Incomplete
    allowed_types: Incomplete
    MAX_VALUE: int
    kwargs: Incomplete

from _typeshed import Incomplete
from ipalib import plugable as plugable
from ipalib.backend import Backend as Backend
from ipalib.crud import (
    Create as Create,
    Delete as Delete,
    Retrieve as Retrieve,
    Search as Search,
    Update as Update,
)
from ipalib.errors import SkipPluginModule as SkipPluginModule
from ipalib.frontend import (
    Command as Command,
    LocalOrRemote as LocalOrRemote,
    Method as Method,
    Object as Object,
    Updater as Updater,
)
from ipalib.parameters import (
    AccessTime as AccessTime,
    Bool as Bool,
    Bytes as Bytes,
    BytesEnum as BytesEnum,
    DNParam as DNParam,
    DNSNameParam as DNSNameParam,
    DateTime as DateTime,
    Decimal as Decimal,
    DefaultFrom as DefaultFrom,
    File as File,
    Flag as Flag,
    IA5Str as IA5Str,
    Int as Int,
    IntEnum as IntEnum,
    Password as Password,
    SerialNumber as SerialNumber,
    Str as Str,
    StrEnum as StrEnum,
)
from ipalib.text import (
    GettextFactory as GettextFactory,
    NGettextFactory as NGettextFactory,
    ngettext as ngettext,
)

Registry = plugable.Registry

class API(plugable.API):
    bases: Incomplete
    @property
    def packages(self): ...

def create_api(mode: str = ...): ...

api: Incomplete

_ = str

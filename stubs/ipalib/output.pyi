from _typeshed import Incomplete
from ipalib.capabilities import client_has_capability as client_has_capability
from ipalib.plugable import ReadOnly as ReadOnly, lock as lock
from ipalib.util import apirepr as apirepr

unicode = str

class Output(ReadOnly):
    type: Incomplete
    validate: Incomplete
    doc: Incomplete
    flags: Incomplete
    name: Incomplete
    def __init__(
        self,
        name,
        type: Incomplete | None = ...,
        doc: Incomplete | None = ...,
        flags=...,
    ) -> None: ...

class Entry(Output):
    type: Incomplete
    doc: Incomplete

emsg: str

class ListOfEntries(Output):
    type: Incomplete
    doc: Incomplete
    def validate(self, cmd, entries, version) -> None: ...

class PrimaryKey(Output):
    def validate(self, cmd, value, version) -> None: ...

class ListOfPrimaryKeys(Output):
    def validate(self, cmd, values, version) -> None: ...

result: Incomplete
summary: Incomplete
value: Incomplete
standard: Incomplete
standard_entry: Incomplete
standard_list_of_entries: Incomplete
standard_delete: Incomplete
standard_multi_delete: Incomplete
standard_boolean: Incomplete
standard_value: Incomplete
simple_value: Incomplete
simple_entry: Incomplete

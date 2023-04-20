from _typeshed import Incomplete
from ipalib import Command

register: Incomplete

class json_metadata(Command):
    __doc__: Incomplete
    NO_CLI: bool
    takes_args: Incomplete
    takes_options: Incomplete
    has_output: Incomplete
    def execute(
        self,
        objname: Incomplete | None = ...,
        methodname: Incomplete | None = ...,
        **options,
    ): ...

class i18n_messages(Command):
    __doc__: Incomplete
    NO_CLI: bool
    messages: Incomplete
    has_output: Incomplete
    def execute(self, **options): ...

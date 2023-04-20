from _typeshed import Incomplete
from collections.abc import Generator
from ipalib import (
    backend as backend,
    output as output,
    parameters as parameters,
)
from ipalib.frontend import Method as Method

class Create(Method):
    has_output: Incomplete
    def get_args(self) -> Generator[Incomplete, None, None]: ...
    def get_options(self) -> Generator[Incomplete, None, None]: ...

class PKQuery(Method):
    def get_args(self) -> Generator[Incomplete, None, None]: ...

class Retrieve(PKQuery):
    has_output: Incomplete

class Update(PKQuery):
    has_output: Incomplete
    def get_options(self) -> Generator[Incomplete, None, None]: ...

class Delete(PKQuery):
    has_output: Incomplete

class Search(Method):
    has_output: Incomplete
    def get_args(self) -> Generator[Incomplete, None, None]: ...
    def get_options(self) -> Generator[Incomplete, None, None]: ...

class CrudBackend(backend.Connectible):
    def create(self, **kw) -> None: ...
    def retrieve(self, primary_key, attributes) -> None: ...
    def update(self, primary_key, **kw) -> None: ...
    def delete(self, primary_key) -> None: ...
    def search(self, **kw) -> None: ...

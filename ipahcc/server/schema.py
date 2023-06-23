__all__ = (
    "validate_schema",
    "ValidationError",
)

import logging
import pathlib
import typing
import uuid
from datetime import datetime

from ipalib.util import validate_hostname
from jsonschema import (
    Draft4Validator,
    RefResolver,
    ValidationError,
    draft4_format_checker,
)
from jsonschema.exceptions import best_match
from jsonschema.validators import validator_for

logger = logging.getLogger(__name__)


SCHEMA_DIR = pathlib.Path(__file__).absolute().parent / "schema"

# newest draft available on RHEL 8
DRAFT_04_URI = "http://json-schema.org/draft-04/schema"
VALIDATOR_CLS = Draft4Validator

RESOLVER = RefResolver(
    base_uri=f"{SCHEMA_DIR.as_uri()}/",
    referrer={},
)

SCHEMATA = {
    "defs": "defs.json",
    "HostRegisterRequest": "host_register_request.json",
    "HostRegisterResponse": "host_register_response.json",
    "HostConfRequest": "host_conf_request.json",
    "HostConfResponse": "host_conf_response.json",
    "IPADomainRequest": "ipadomain_request.json",
    "IPADomainResponse": "ipadomain_response.json",
    "Errors": "errors.json",
}


def _build_validators(
    resolver=RESOLVER,
) -> typing.Dict[str, VALIDATOR_CLS]:
    """Build and verify JSON schema validators"""
    validators = {}
    for name, filename in SCHEMATA.items():
        _, schema = resolver.resolve(filename)
        cls = validator_for(schema)
        if name != "defs":
            validators[name] = cls(schema, resolver=resolver)
    return validators


VALIDATORS = _build_validators()


def validate_schema(instance: dict, schema_id: str):
    validator = VALIDATORS[schema_id]
    try:
        error = best_match(validator.iter_errors(instance))
        if error is not None:
            raise error
    except ValidationError:
        logger.exception("Schema %r validation error", schema_id)
        raise


# Additional format checkers (not defined in Draft-04)
@draft4_format_checker.checks("uuid", ValueError)
def format_uuid(instance: object) -> bool:
    if not isinstance(instance, str):
        return False
    if len(instance) != 36:
        return False
    uuid.UUID(instance)
    return True


@draft4_format_checker.checks("date-time", ValueError)
def format_date_time(instance: object) -> bool:
    if not isinstance(instance, str):
        return False
    dt = datetime.fromisoformat(instance)
    # must have a timezone (e.g. "Z" or "+02:00" suffix)
    return dt.tzinfo is not None


@draft4_format_checker.checks("idn-hostname", ValueError)
def format_idn_hostname(instance: object) -> bool:
    if not isinstance(instance, str):
        return False
    if instance.endswith("."):
        return False
    validate_hostname(instance)
    return True

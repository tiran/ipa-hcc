__all__ = (
    "rfc3339_datetime",
    "validate_schema",
    "ValidationError",
)

import copy
import logging
import typing
from datetime import datetime, timezone

import jsonschema
from jsonschema import ValidationError

from ipahcc import hccplatform

logger = logging.getLogger(__name__)


def rfc3339_datetime(dt: datetime) -> str:
    """Convert datetime to RFC 3339 compatible string"""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat("T", timespec="seconds")


# The custom schema types are using format specifiers from
# https://spec.openapis.org/registry/format/ and pattern, because
# python-jsonschema packages on RHEL 8 and 9 don't have a format validator.

DEFS = {
    "CaCertBundle": {
        "title": "A bundle of CA certificates",
        "description": "A string of concatenated, PEM-encoded X.509 certificates",
        "type": "string",
    },
    "Certificate": {
        "type": "object",
        "required": ["pem"],
        "additionalProperties": False,
        "properties": {
            "pem": {
                "title": "PEM encoded X.509 certificate",
                "example": (
                    r"-----BEGIN CERTIFICATE-----\n"
                    r"MII...\n"
                    r"-----END CERTIFICATE-----\n"
                ),
                "type": "string",
            },
            "nickname": {
                "title": "Internal nick name in LDAP",
                "example": "DOMAIN.EXAMPLE CA",
                "type": "string",
            },
            "issuer": {
                "title": "issuer name",
                "example": "O=DOMAIN.EXAMPLE, CN=Certificate Authority",
                "type": "string",
            },
            "subject": {
                "title": "subject name",
                "example": "O=DOMAIN.EXAMPLE, CN=Certificate Authority",
                "type": "string",
            },
            "serial_number": {
                "title": "base 10 encoded serial number",
                "example": "1",
                "type": "string",
                "pattern": r"^[1-9][0-9]*$",
            },
            "not_before": {
                "title": "Not valid before timestamp (UTC)",
                "example": "2023-03-21T05:38:09+00:00",
                "type": "string",
                "format": "date-time",
            },
            "not_after": {
                "title": "Not valid after timestamp (UTC)",
                "example": "2043-03-21T05:38:09+00:00",
                "type": "string",
                "format": "date-time",
            },
        },
    },
    "DomainId": {
        "title": "domain id",
        "description": "A domain id",
        "example": "772e9618-d0f8-4bf8-bfed-d2831f63c619",
        "type": "string",
        "format": "uuid",
        "minLength": 36,
        "maxLength": 36,
        "pattern": r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    },
    "DomainName": {
        "title": "Fully qualified domain name",
        "description": "A name of a domain (all lower-case)",
        "example": "domain.example",
        "type": "string",
        "minLength": 3,
        "maxLength": 253,
        "format": "idn-hostname",
        "pattern": r"^[a-z0-9\.\-]+$",
    },
    "DomainType": {
        "title": "Domain Type",
        "description": f"Type of domain (currently only {hccplatform.HCC_DOMAIN_TYPE})",
        "example": "rhel-idm",
        "type": "string",
        "enum": [hccplatform.HCC_DOMAIN_TYPE],
    },
    "Error": {
        "title": "Error information",
        "type": "object",
        "required": ["id", "status", "title", "details"],
        "additionalProperties": False,
        "properties": {
            "id": {
                "title": "Error identifier",
                "description": "A unique, random error identifier",
                "example": "27c19744-29f2-42a0-8669-8fa050f8ffdf",
                "type": "string",
            },
            "status": {
                "title": "HTTP status code",
                "description": "The HTTP status code for the error.",
                "example": "404",
                "type": "integer",
                "minimum": 100,
                "maximum": 599,
            },
            "title": {
                "title": "HTTP status text",
                "description": "The human-readable HTTP status text for the error.",
                "example": "Not Found",
                "type": "string",
            },
            "details": {
                "title": "Details",
                "description": "A detailed explanation of the error, e.g. traceback.",
                "example": "Resource not found",
                "type": "string",
            },
        },
    },
    "Fqdn": {
        "title": "FQDN",
        "description": "A host's Fully Qualified Domain Name (all lower-case).",
        "example": "host.domain.example",
        "type": "string",
        "minLength": 3,
        "maxLength": 253,
        "format": "idn-hostname",
        "pattern": r"^[a-z0-9\.\-]+$",
    },
    "HostId": {
        "title": "host id",
        "description": "A Host-Based Inventory ID of a host.",
        "example": "f0468001-7632-4d3f-afd2-770c93825adf",
        "type": "string",
        "format": "uuid",
        "minLength": 36,
        "maxLength": 36,
        "pattern": r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    },
    "LocationName": {
        "title": "Location identifier (IPA location, AD site)",
        "description": "A location identifier (lower-case DNS label)",
        "example": "alpha",
        "type": "string",
        "minLength": 1,
        "maxLength": 63,
        "pattern": r"^[a-z][a-z0-9\-]*$",
    },
    "OrgId": {
        "title": "Organization id",
        "description": "The Org ID of the tenant that owns the host.",
        "example": "000102",
        "type": "string",
    },
    "SubscriptionManagerId": {
        "title": "Subscription manager id",
        "description": "A Red Hat Subcription Manager ID of a RHEL host.",
        "example": "e658e3eb-148c-46a6-b48a-099f9593191a",
        "type": "string",
        "format": "uuid",
        "minLength": 36,
        "maxLength": 36,
        "pattern": r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    },
    "RealmName": {
        "title": "Kerberos realm name",
        "description": "A Kerberos realm name (usually all upper-case domain name)",
        "example": "DOMAIN.EXAMPLE",
        "type": "string",
        "minLength": 3,
        "maxLength": 253,
        "pattern": r"^[A-Z0-9\.\-]+$",
    },
}


def _limit_defs(*names):
    """Limit '$defs' to make exception message more readable"""
    return {name: DEFS[name] for name in names}


# POST /hcc/{inventory_id}/{hostname}
# "subscription_manager_id" is in mTLS client cert
HCC_HOST_REGISTER_REQUEST = {
    "$id": "HCCHostRegisterRequest",
    "title": "Host registration request",
    "description": "Request from a host to an IPA server",
    "type": "object",
    "required": ["domain_type", "domain_name", "domain_id"],
    "additionalProperties": False,
    "properties": {
        "domain_type": {"$ref": "#/$defs/DomainType"},
        "domain_name": {"$ref": "#/$defs/DomainName"},
        "domain_id": {"$ref": "#/$defs/DomainId"},
    },
    "$defs": _limit_defs("DomainName", "DomainType", "DomainId"),
}

HCC_HOST_REGISTER_RESPONSE = {
    "$id": "HCCHostRegisterResponse",
    "title": "Host registration response",
    "description": "Response of an IPA server to to host",
    "type": "object",
    "required": [
        # XXX: more fields?
        "status",
        "kdc_cabundle",
    ],
    "additionalProperties": False,
    "properties": {
        "status": {"type": "string"},
        "kdc_cabundle": {"$ref": "#/$defs/CaCertBundle"},
    },
    "$defs": _limit_defs("CaCertBundle"),
}

# POST /api/idm/v1/host-conf/{inventory_id}/{hostname}
# "subscription_manager_id" is in mTLS client cert
HOST_CONF_REQUEST = {
    "$id": "HostConfRequest",
    "title": "Host configuration request",
    "description": "Request from a client to HCC API to request configuration data",
    "type": "object",
    # "required": [],
    "additionalProperties": False,
    "properties": {
        # additional selectors / filters
        "domain_type": {"$ref": "#/$defs/DomainType"},
        "domain_name": {"$ref": "#/$defs/DomainName"},
        "domain_id": {"$ref": "#/$defs/DomainId"},
        "location": {"$ref": "#/$defs/LocationName"},
    },
    "$defs": _limit_defs(
        "DomainName", "DomainType", "DomainId", "LocationName"
    ),
}

HOST_CONF_RESPONSE = {
    "$id": "HostConfResponse",
    "title": "Host configuration response",
    "description": "Response from HCC to client",
    "type": "object",
    "required": [
        "auto_enrollment_enabled",
        "domain_type",
        "domain_name",
        "domain_id",
        "inventory_id",
        hccplatform.HCC_DOMAIN_TYPE,
    ],
    "additionalProperties": False,
    "properties": {
        "auto_enrollment_enabled": {"type": "boolean"},
        "domain_type": {"$ref": "#/$defs/DomainType"},
        "domain_name": {"$ref": "#/$defs/DomainName"},
        "domain_id": {"$ref": "#/$defs/DomainId"},
        "inventory_id": {"$ref": "#/$defs/HostId"},
        hccplatform.HCC_DOMAIN_TYPE: {
            "title": "RHEL IdM-specific data",
            "type": "object",
            "required": ["cabundle", "enrollment_servers", "realm_name"],
            "additionalProperties": False,
            "properties": {
                "cabundle": {"$ref": "#/$defs/CaCertBundle"},
                "enrollment_servers": {
                    "title": (
                        "An array of RHEL IdM servers with activate "
                        "HCC enrollment agents"
                    ),
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["fqdn"],
                        "additionalProperties": False,
                        "properties": {
                            "fqdn": {"$ref": "#/$defs/Fqdn"},
                            "location": {"$ref": "#/$defs/LocationName"},
                        },
                    },
                },
                "realm_name": {"$ref": "#/$defs/RealmName"},
            },
        },
    },
    "$defs": _limit_defs(
        "CaCertBundle",
        "DomainId",
        "DomainName",
        "DomainType",
        "Fqdn",
        "HostId",
        "LocationName",
        "RealmName",
    ),
}

# PUT /api/idm/v1/domains/{domain_id}/register
# PUT /api/idm/v1/domains/{domain_id}/update
# GET /api/idm/v1/domains/{domain_id} (not implemented in mockapi)
IPA_DOMAIN_REQUEST = {
    "$id": "IPADomainRequest",
    "title": "Domain registration/update request and response",
    "description": (
        "Request from an RHEL IdM server to HCC API to "
        "register or update a domain."
    ),
    "type": "object",
    "required": [
        "domain_type",
        "domain_name",
        hccplatform.HCC_DOMAIN_TYPE,
    ],
    "additionalProperties": False,
    "properties": {
        "title": {"type": "string"},
        "description": {"type": "string"},
        "auto_enrollment_enabled": {"type": "boolean", "default": True},
        "domain_type": {"$ref": "#/$defs/DomainType"},
        "domain_name": {"$ref": "#/$defs/DomainName"},
        hccplatform.HCC_DOMAIN_TYPE: {
            "type": "object",
            "required": [
                "ca_certs",
                "realm_name",
                "realm_domains",
                "servers",
            ],
            "additionalProperties": False,
            "properties": {
                "ca_certs": {
                    "title": "Array of trusted CA certificates",
                    "type": "array",
                    "items": {"$ref": "#/$defs/Certificate"},
                },
                "realm_name": {"$ref": "#/$defs/RealmName"},
                "realm_domains": {
                    "title": "Realm domains",
                    "descriptions": "DNS names that are attached to the Kerberos realm",
                    "type": "array",
                    "items": {"$ref": "#/$defs/DomainName"},
                },
                "locations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["name"],
                        "additionalProperties": False,
                        "properties": {
                            "name": {"$ref": "#/$defs/LocationName"},
                            "description": {"type": "string"},
                        },
                    },
                },
                "servers": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": [
                            "fqdn",
                            "ca_server",
                            "hcc_enrollment_server",
                            "hcc_update_server",
                            "pkinit_server",
                        ],
                        "additionalProperties": False,
                        "properties": {
                            "fqdn": {"$ref": "#/$defs/Fqdn"},
                            # The RHSM id is not available unless a server
                            # has the ipa-hcc-server package installed or the
                            # value was added manually.
                            "subscription_manager_id": {
                                "$ref": "#/$defs/SubscriptionManagerId"
                            },
                            "location": {"$ref": "#/$defs/LocationName"},
                            "ca_server": {"type": "boolean"},
                            "hcc_enrollment_server": {"type": "boolean"},
                            "hcc_update_server": {"type": "boolean"},
                            "pkinit_server": {"type": "boolean"},
                        },
                    },
                },
            },
        },
    },
    "$defs": _limit_defs(
        "Certificate",
        "DomainId",
        "DomainName",
        "DomainType",
        "Fqdn",
        "HostId",
        "LocationName",
        "RealmName",
        "SubscriptionManagerId",
    ),
}

IPA_DOMAIN_RESPONSE = copy.deepcopy(IPA_DOMAIN_REQUEST)
IPA_DOMAIN_RESPONSE.update(
    {
        "$id": "IPADomainResponse",
        "title": "Domain registration or update response",
        "description": "Response from HCC API to RHEL IdM server",
    }
)

# mypy: disable-error-code="attr-defined"
IPA_DOMAIN_RESPONSE["required"].extend(["domain_id"])
IPA_DOMAIN_RESPONSE["properties"].update(
    {
        "domain_id": {"$ref": "#/$defs/DomainId"},
    }
)

ERROR_RESPONSE = {
    "$id": "Errors",
    "title": "Generic error response",
    "description": "Error response",
    "type": "array",
    "minItems": 1,
    "items": {"$ref": "#/$defs/Error"},
    "$defs": _limit_defs("Error"),
}

SCHEMATA = {
    s["$id"]: s
    for s in [
        HCC_HOST_REGISTER_REQUEST,
        HCC_HOST_REGISTER_RESPONSE,
        HOST_CONF_REQUEST,
        HOST_CONF_RESPONSE,
        IPA_DOMAIN_REQUEST,
        IPA_DOMAIN_RESPONSE,
        ERROR_RESPONSE,
    ]
}


def validate_schema(
    instance: typing.Union[dict, typing.List[dict]], schema_id: str
):
    schema = SCHEMATA[schema_id]
    try:
        return jsonschema.validate(instance, schema)
    except ValidationError:
        logger.exception("Schema %r validation error", schema_id)
        raise


def _dump():
    # pylint: disable=import-outside-toplevel, import-error
    import sys

    import yaml  # type: ignore

    yaml.dump(
        {"components": {"schemas": DEFS}},
        sys.stdout,
        indent=4,
        sort_keys=False,
    )


if __name__ == "__main__":
    _dump()

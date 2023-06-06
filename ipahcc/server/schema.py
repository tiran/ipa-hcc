__all__ = (
    "validate_schema",
    "ValidationError",
)
import logging

import jsonschema
from jsonschema import ValidationError

from ipahcc import hccplatform

logger = logging.getLogger(__name__)


DEFS = {
    "domain_type": {
        "title": "Domain Type",
        "description": f"Type of domain (currently only {hccplatform.HCC_DOMAIN_TYPE})",
        "type": "string",
        "enum": [hccplatform.HCC_DOMAIN_TYPE],
    },
    "hostname": {
        "title": "Fully qualified host name",
        "description": "Name of a host as FQDN (all lower-case)",
        "type": "string",
        "minLength": 3,
        "maxLength": 253,
        "pattern": r"^[a-z0-9\.\-]+$",
    },
    "location": {
        "title": "Location identifier (IPA location, AD site)",
        "description": "A location identifier (lower-case DNS label)",
        "type": "string",
        "minLength": 1,
        "maxLength": 63,
        "pattern": r"^[a-z][a-z0-9\-]*$",
    },
    "domain_name": {
        "title": "Fully qualified domain name",
        "description": "Name of a domain (all lower-case)",
        "type": "string",
        "minLength": 3,
        "maxLength": 253,
        "pattern": r"^[a-z0-9\.\-]+$",
    },
    "realm_name": {
        "title": "Kerberos realm name",
        "description": "A Kerberos realm name (usually all upper-case domain name)",
        "type": "string",
        "minLength": 3,
        "maxLength": 253,
        "pattern": r"^[A-Z0-9\.\-]+$",
    },
    "uuid": {
        "title": "Universal unique identifier (UUID)",
        "description": (
            "UUID of a resource "
            "(e.g. domain, inventory, subscription manager)"
        ),
        "type": "string",
        "minLength": 36,
        "maxLength": 36,
    },
}

# POST /hcc/{inventory_id}/{hostname}
# "subscription_manager_id" is in mTLS client cert
HCC_REQUEST = {
    "$id": "/schemas/hcc-host-register/request",
    "title": "Host registration request",
    "description": "Request from a host to an IPA server",
    "type": "object",
    "required": ["domain_type", "domain_name", "domain_id"],
    "additionalProperties": False,
    "properties": {
        "domain_type": {"$ref": "#/$defs/domain_type"},
        "domain_name": {"$ref": "#/$defs/domain_name"},
        "domain_id": {"$ref": "#/$defs/uuid"},
    },
    "$defs": DEFS,
}

HCC_RESPONSE = {
    "$id": "/schemas/hcc-host-register/response",
    "title": "Host registration response",
    "description": "Response of an IPA server to to host",
    "type": "object",
    "required": [
        # XXX
        "status",
        "kdc_cabundle",
    ],
    "additionalProperties": False,
    "properties": {
        "status": {"type": "string"},
        "kdc_cabundle": {"type": "string"},
    },
}

# POST /api/idm/v1/host-conf/{inventory_id}/{hostname}
# "subscription_manager_id" is in mTLS client cert
HOST_CONF_REQUEST = {
    "$id": "/schemas/host-conf/request",
    "title": "Host configuration request",
    "description": "Request from a client to HCC API to request configuration data",
    "type": "object",
    # "required": [],
    "additionalProperties": False,
    "properties": {
        # additional selectors / filters
        "domain_type": {"$ref": "#/$defs/domain_type"},
        "domain_name": {"$ref": "#/$defs/domain_name"},
        "domain_id": {"$ref": "#/$defs/uuid"},
        "location": {"$ref": "#/$defs/location"},
    },
    "$defs": DEFS,
}

HOST_CONF_RESPONSE = {
    "$id": "/schemas/host-conf/response",
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
        "domain_type": {"$ref": "#/$defs/domain_type"},
        "domain_name": {"$ref": "#/$defs/domain_name"},
        "domain_id": {"$ref": "#/$defs/uuid"},
        "inventory_id": {"$ref": "#/$defs/uuid"},
        hccplatform.HCC_DOMAIN_TYPE: {
            "title": "RHEL IdM-specific data",
            "type": "object",
            "required": ["cabundle", "enrollment_servers", "realm_name"],
            "additionalProperties": False,
            "properties": {
                "cabundle": {
                    "title": "Bundle of CA certificates",
                    "description": "A PEM bundle of IPA's trusted CA certificates",
                    "type": "string",
                },
                "enrollment_servers": {
                    "title": (
                        "An array of RHEL IdM servers with activate "
                        "HCC enrollment agents"
                    ),
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["fqdn", "location"],
                        "additionalProperties": False,
                        "properties": {
                            "fqdn": {"$ref": "#/$defs/hostname"},
                            "location": {
                                "oneOf": [
                                    {"$ref": "#/$defs/location"},
                                    {"type": "null"},
                                ],
                            },
                        },
                    },
                },
                "realm_name": {"$ref": "#/$defs/realm_name"},
            },
        },
    },
    "$defs": DEFS,
}

# POST /api/idm/v1/check-host/{inventory_id}/{fqdn}
CHECK_HOST_REQUEST = {
    "$id": "/schemas/check-host/request",
    "title": "Host verification request",
    "description": (
        "Request from a RHEL IdM server to HCC API to verify a "
        "host enrollment request"
    ),
    "type": "object",
    # subscription_manager_id and fqdn are passed via PATH variables
    "required": [
        "domain_type",
        "domain_name",
        "domain_id",
        "subscription_manager_id",
    ],
    "additionalProperties": False,
    "properties": {
        "domain_type": {"$ref": "#/$defs/domain_type"},
        "domain_name": {"$ref": "#/$defs/domain_name"},
        "domain_id": {"$ref": "#/$defs/uuid"},
        "subscription_manager_id": {"$ref": "#/$defs/uuid"},
    },
    "$defs": DEFS,
}

CHECK_HOST_RESPONSE = {
    "$id": "/schemas/check-host/response",
    "title": "Host verification response",
    "description": "Response from HCC API to RHEL IdM server",
    "type": "object",
    "required": [
        # XXX
        "inventory_id"
    ],
    "additionalProperties": False,
    "properties": {
        "inventory_id": {"$ref": "#/$defs/uuid"},
    },
    "$defs": DEFS,
}

# PUT /api/idm/v1/domains/{domain_id}/register
# PUT /api/idm/v1/domains/{domain_id}/update
DOMAIN_REQUEST = {
    "$id": "/schemas/domain-register-update/request",
    "title": "Domain registration or update request",
    "description": (
        "Request from an RHEL IdM server to HCC API to "
        "register or update a domain"
    ),
    "type": "object",
    "required": [
        "domain_type",
        "domain_name",
        hccplatform.HCC_DOMAIN_TYPE,
    ],
    "additionalProperties": False,
    "properties": {
        "domain_type": {"$ref": "#/$defs/domain_type"},
        "domain_name": {"$ref": "#/$defs/domain_name"},
        hccplatform.HCC_DOMAIN_TYPE: {
            "type": "object",
            "required": ["cacerts", "realm_name", "realm_domains", "servers"],
            "additionalProperties": False,
            "properties": {
                "cacerts": {
                    "title": "Array of trusted CA certificates",
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["nickname", "pem"],
                        "additionalProperties": False,
                        "properties": {
                            "nickname": {
                                "title": "Internal nick name in LDAP",
                                "type": "string",
                            },
                            "pem": {
                                "title": "PEM encoded X.509 certificate",
                                "type": "string",
                            },
                            # optional, not used at the moment
                            "issuer": {
                                "title": "issuer name",
                                "type": "string",
                            },
                            "subject": {
                                "title": "subject name",
                                "type": "string",
                            },
                            "serial_number": {
                                "title": "base 10 encoded serial number",
                                "type": "string",
                            },
                            "not_before": {
                                "title": "Not valid before timestamp (UTC)",
                                "type": "string",
                            },
                            "not_after": {
                                "title": "Not valid after timestamp (UTC)",
                                "type": "string",
                            },
                        },
                    },
                },
                "realm_name": {"$ref": "#/$defs/realm_name"},
                "realm_domains": {
                    "title": "Realm domains",
                    "descriptions": "DNS names that are attached to the Kerberos realm",
                    "type": "array",
                    "items": {"$ref": "#/$defs/domain_name"},
                },
                # locations is a superset of servers[*]["location"]
                "locations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["name", "description"],
                        "additionalProperties": False,
                        "properties": {
                            "name": {"$ref": "#/$defs/location"},
                            "description": {
                                "oneOf": [
                                    {"type": "string"},
                                    {"type": "null"},
                                ]
                            },
                        },
                    },
                },
                "servers": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["fqdn"],
                        "additionalProperties": False,
                        "properties": {
                            "fqdn": {"$ref": "#/$defs/hostname"},
                            "subscription_manager_id": {
                                "oneOf": [
                                    {"$ref": "#/$defs/uuid"},
                                    {"type": "null"},
                                ],
                            },
                            "location": {
                                "oneOf": [
                                    {"$ref": "#/$defs/location"},
                                    {"type": "null"},
                                ],
                            },
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
    "$defs": DEFS,
}

DOMAIN_RESPONSE = {
    "$id": "/schemas/domain-register-update/response",
    "title": "Domain registration or update response",
    "description": "Response from HCC API to RHEL IdM server",
    "type": "object",
    "required": [
        # XXX
        "status",
    ],
    "additionalProperties": False,
    "properties": {
        "status": {"type": "string"},
    },
}

ERROR_RESPONSE = {
    "$id": "/schemas/error/response",
    "title": "Generic error response",
    "description": "Error response",
    "type": "array",
    "minItems": 1,
    "items": {
        "type": "object",
        "required": ["id", "status", "title", "details"],
        "additionalProperties": False,
        "properties": {
            "id": {"title": "Unique error id", "type": "str"},
            "status": {"title": "HTTP status code", "type": "integer"},
            "title": {"title": "HTTP status reason", "type": "string"},
            "details": {"title": "Reason text", "type": "string"},
        },
    },
}

SCHEMATA = {
    s["$id"]: s
    for s in [
        HCC_REQUEST,
        HCC_RESPONSE,
        HOST_CONF_REQUEST,
        HOST_CONF_RESPONSE,
        CHECK_HOST_REQUEST,
        CHECK_HOST_RESPONSE,
        DOMAIN_REQUEST,
        DOMAIN_RESPONSE,
        ERROR_RESPONSE,
    ]
}


def validate_schema(instance: dict, schema_id: str):
    schema = SCHEMATA[schema_id]
    try:
        return jsonschema.validate(instance, schema)
    except ValidationError:
        logger.exception("Schema %r validation error", schema_id)
        raise

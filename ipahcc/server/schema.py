__all__ = (
    "validate_schema",
    "ValidationError",
)
import logging

from ipahcc import hccplatform

if hccplatform.PY2:
    try:
        import jsonschema
        from jsonschema import ValidationError
    except ImportError:
        jsonschema = None
        ValidationError = Exception

else:
    import jsonschema
    from jsonschema import ValidationError

logger = logging.getLogger(__name__)


DEFS = {
    "domain_type": {
        "type": "string",
        "enum": [hccplatform.HCC_DOMAIN_TYPE],
    },
    "hostname": {
        "type": "string",
        "minLength": 3,
        "maxLength": 253,
        "pattern": r"^[a-z0-9\.\-]+$",
    },
    "location": {
        "type": "string",
        "minLength": 1,
        "maxLength": 63,
        "pattern": r"^[a-z][a-z0-9\-]*$",
    },
    "domain_name": {"$ref": "#/$defs/hostname"},
    "realm_name": {
        "type": "string",
        "minLength": 3,
        "maxLength": 253,
        "pattern": r"^[A-Z0-9\.\-]+$",
    },
    "uuid": {"type": "string", "minLength": 36, "maxLength": 36},
}

HCC_REQUEST = {
    "$id": "/schemas/hcc-host-register/request",
    "type": "object",
    "required": ["domain_type", "domain_name", "domain_id", "inventory_id"],
    "additionalProperties": False,
    "properties": {
        "domain_type": {"$ref": "#/$defs/domain_type"},
        "domain_name": {"$ref": "#/$defs/domain_name"},
        "domain_id": {"$ref": "#/$defs/uuid"},
        "inventory_id": {"$ref": "#/$defs/uuid"},
    },
    "$defs": DEFS,
}

HCC_RESPONSE = {
    "$id": "/schemas/hcc-host-register/response",
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

HOST_CONF_REQUEST = {
    "$id": "/schemas/host-conf/request",
    "type": "object",
    "required": ["inventory_id"],
    "additionalProperties": False,
    "properties": {
        "inventory_id": {"$ref": "#/$defs/uuid"},
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
            "type": "object",
            "required": ["cabundle", "enrollment_servers", "realm_name"],
            "additionalProperties": False,
            "properties": {
                "cabundle": {"type": "string"},
                "enrollment_servers": {
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

CHECK_HOST_REQUEST = {
    "$id": "/schemas/check-host/request",
    "type": "object",
    # subscription_manager_id and fqdn are passed via PATH variables
    "required": ["domain_type", "domain_name", "domain_id", "inventory_id"],
    "additionalProperties": False,
    "properties": {
        "domain_type": {"$ref": "#/$defs/domain_type"},
        "domain_name": {"$ref": "#/$defs/domain_name"},
        "domain_id": {"$ref": "#/$defs/uuid"},
        "inventory_id": {"$ref": "#/$defs/uuid"},
    },
    "$defs": DEFS,
}

CHECK_HOST_RESPONSE = {
    "$id": "/schemas/check-host/response",
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


DOMAIN_REQUEST = {
    "$id": "/schemas/domain/request",
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
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["nickname", "pem"],
                        "additionalProperties": False,
                        "properties": {
                            "nickname": {"type": "string"},
                            "pem": {"type": "string"},
                            # optional, not used at the moment
                            "issuer": {"type": "string"},
                            "subject": {"type": "string"},
                            "serial_number": {"type": "string"},
                            "not_before": {"type": "string"},
                            "not_after": {"type": "string"},
                        },
                    },
                },
                "realm_name": {"$ref": "#/$defs/realm_name"},
                "realm_domains": {
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
    "$id": "/schemas/domain/response",
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
    "type": "object",
    "required": ["status", "title", "details"],
    "additionalProperties": False,
    "properties": {
        "status": {"type": "integer"},
        "title": {"type": "string"},
        "details": {"type": "string"},
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


def validate_schema(instance, schema_id):
    schema = SCHEMATA[schema_id]
    if jsonschema is not None:
        try:
            jsonschema.validate(instance, schema)
        except ValidationError:
            logger.exception("Schema %r validation error", schema_id)
            raise

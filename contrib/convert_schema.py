#!/usr/bin/python3
import json
import os
import pathlib
import sys

import yaml

BASEDIR = pathlib.Path(__file__).absolute().parent.parent
IDBDIR = BASEDIR.parent / "idm-domains-backend"
OPENAPI_YAML = IDBDIR / "api" / "public.openapi.yaml"

sys.path.append(str(BASEDIR))

from ipahcc.server.schema import (  # noqa: E402
    DRAFT_04_URI,
    SCHEMA_DIR,
    SCHEMATA,
)

# These schemas are not (yet) in OpenAPI
HOST_REGISTER_REQUEST = {
    "$schema": DRAFT_04_URI,
    "title": "Host registration request",
    "description": "Request from a host to an IPA server",
    "type": "object",
    "required": ["domain_type", "domain_name", "domain_id"],
    "additionalProperties": False,
    "properties": {
        "domain_type": {"$ref": "defs.json#/$defs/DomainType"},
        "domain_name": {"$ref": "defs.json#/$defs/DomainName"},
        "domain_id": {"$ref": "defs.json#/$defs/DomainId"},
    },
}

HOST_REGISTER_RESPONSE = {
    "$schema": DRAFT_04_URI,
    "title": "Host registration response",
    "description": "Response of an IPA server to to host",
    "type": "object",
    "required": [
        "status",
        "kdc_cabundle",
    ],
    "additionalProperties": False,
    "properties": {
        "status": {"type": "string"},
        "kdc_cabundle": {"$ref": "defs.json#/$defs/CaCertBundle"},
    },
}

IPA_DOMAIN_REQUEST = {
    "$schema": DRAFT_04_URI,
    "title": "Domain registration/update request",
    "description": (
        "Request from an RHEL IdM server to HCC API to "
        "register or update a domain."
    ),
    "type": "object",
    "required": [
        "domain_type",
        "domain_name",
        "rhel-idm",
    ],
    "additionalProperties": False,
    "properties": {
        "title": {"type": "string"},
        "description": {"type": "string"},
        "auto_enrollment_enabled": {"type": "boolean", "default": True},
        "domain_type": {"$ref": "defs.json#/$defs/DomainType"},
        "domain_name": {"$ref": "defs.json#/$defs/DomainName"},
        "rhel-idm": {
            "$ref": "defs.json#/$defs/RhelIdmDomain",
        },
    },
}


def read_openapi(filename: os.PathLike = OPENAPI_YAML) -> dict:
    with open(filename, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def fixup_ref(obj, refmap: dict, prefix: str = ""):
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            if k == "$ref":
                obj["$ref"] = prefix + refmap[v]
            elif k == "example":
                obj.pop("example")
            elif isinstance(v, (dict, list)):
                fixup_ref(v, refmap, prefix)
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                fixup_ref(item, refmap, prefix)
    else:
        raise TypeError(type(obj), repr(obj))


def extract_openapi(oapi: dict) -> dict:
    defs = {}
    results = {}
    refmap = {}
    for orig_name, schema in oapi["components"]["schemas"].items():
        xrhipahcc = schema.pop("x-rh-ipa-hcc", None)
        if xrhipahcc is None:
            continue
        typ = xrhipahcc["type"]
        new_name = xrhipahcc.get("name", orig_name)
        if typ == "defs":
            defs[new_name] = schema
            orig_path = f"#/components/schemas/{orig_name}"
            refmap[orig_path] = f"#/$defs/{new_name}"
        elif typ in {"request", "response"}:
            new_schema = {"$schema": DRAFT_04_URI}
            new_schema.update(schema)
            results[new_name] = new_schema
        else:
            raise ValueError(typ)

    for obj in results.values():
        fixup_ref(obj, refmap, "defs.json")

    for obj in defs.values():
        fixup_ref(obj, refmap, "")
    results["defs"] = {
        "$schema": DRAFT_04_URI,
        "$defs": defs,
    }
    return results


def main():
    oapi = read_openapi()
    results = extract_openapi(oapi)
    results.update(
        {
            "HostRegisterRequest": HOST_REGISTER_REQUEST,
            "HostRegisterResponse": HOST_REGISTER_RESPONSE,
            "IPADomainRequest": IPA_DOMAIN_REQUEST,
        }
    )
    for name, schema in results.items():
        filename = SCHEMATA[name]
        with open(SCHEMA_DIR / filename, "w", encoding="utf-8") as f:
            json.dump(schema, f, indent=2)
            f.write("\n")


if __name__ == "__main__":
    main()

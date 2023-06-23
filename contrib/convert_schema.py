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
    for name, schema in results.items():
        filename = SCHEMATA[name]
        with open(SCHEMA_DIR / filename, "w", encoding="utf-8") as f:
            json.dump(schema, f, indent=2)
            f.write("\n")


if __name__ == "__main__":
    main()

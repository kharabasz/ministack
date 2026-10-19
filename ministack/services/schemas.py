# Copyright (c) 2026 MiniStack Contributors. SPDX-License-Identifier: MIT
# Copies or substantial portions, including AI-assisted ports or rewrites, must retain this notice (see LICENSE).
"""
Amazon EventBridge Schemas Emulator (registries and schemas).
REST/JSON protocol — /v1/registries/... and /tags/{arn}, signed as schemas.

Supports:
  Registries:  CreateRegistry, DescribeRegistry, UpdateRegistry, DeleteRegistry,
               ListRegistries
  Schemas:     CreateSchema, DescribeSchema (latest or a given version),
               UpdateSchema (a new version when the content changes),
               DeleteSchema, ListSchemas, ListSchemaVersions
  Tags:        TagResource, UntagResource, ListTagsForResource

Not emulated: schema discovery, code bindings, resource policies, search.
"""

import copy
import json
import re
from datetime import datetime, timezone
from urllib.parse import unquote

from ministack.core.responses import (
    AccountRegionScopedDict,
    get_account_id,
    get_region,
)

_registries = AccountRegionScopedDict()  # registry name -> registry record
_schemas = AccountRegionScopedDict()     # "registry/schema" -> schema record with versions
_tags = AccountRegionScopedDict()        # ARN -> {key: value}

_SCHEMA_TYPES = ("OpenApi3", "JSONSchemaDraft4")
_NAME_RE = re.compile(r"^[\.\-_A-Za-z@0-9]+$")


def reset():
    _registries.clear()
    _schemas.clear()
    _tags.clear()


def get_state():
    return {
        "registries": copy.deepcopy(_registries),
        "schemas": copy.deepcopy(_schemas),
        "tags": copy.deepcopy(_tags),
    }


def load_persisted_state(data):
    if not data:
        return
    _registries.update(data.get("registries", {}))
    _schemas.update(data.get("schemas", {}))
    _tags.update(data.get("tags", {}))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _json(status, body):
    return status, {"Content-Type": "application/json"}, json.dumps(body).encode()


def _error(status, code, message):
    return (status, {"Content-Type": "application/json", "x-amzn-errortype": code},
            json.dumps({"Code": code, "Message": message}).encode())


def _not_found(message):
    return _error(404, "NotFoundException", message)


def _registry_arn(name):
    return f"arn:aws:schemas:{get_region()}:{get_account_id()}:registry/{name}"


def _schema_arn(registry, name):
    return f"arn:aws:schemas:{get_region()}:{get_account_id()}:schema/{registry}/{name}"


def _set_tags(arn, tags):
    if tags:
        merged = _tags.get(arn, {})
        merged.update(tags)
        _tags[arn] = merged


def _validate_content(schema_type, content):
    if schema_type not in _SCHEMA_TYPES:
        return _error(400, "BadRequestException", f"Type must be one of {', '.join(_SCHEMA_TYPES)}")
    if not content:
        return _error(400, "BadRequestException", "Content is required")
    try:
        json.loads(content)
    except (TypeError, ValueError):
        return _error(400, "BadRequestException", "Content must be a JSON document")
    return None


# ---------------------------------------------------------------------------
# Registries
# ---------------------------------------------------------------------------


def _registry_view(reg):
    return {
        "RegistryName": reg["RegistryName"],
        "RegistryArn": reg["RegistryArn"],
        "Description": reg.get("Description", ""),
        "tags": _tags.get(reg["RegistryArn"], {}),
    }


def _create_registry(name, body):
    if not _NAME_RE.match(name) or len(name) > 64:
        return _error(400, "BadRequestException", f"Invalid registry name: {name}")
    if name in _registries:
        return _error(409, "ConflictException", f"Registry with name {name} already exists.")
    reg = {"RegistryName": name, "RegistryArn": _registry_arn(name), "Description": body.get("Description", "")}
    _registries[name] = reg
    _set_tags(reg["RegistryArn"], body.get("tags"))
    return _json(201, _registry_view(reg))


def _describe_registry(name):
    reg = _registries.get(name)
    if not reg:
        return _not_found(f"Registry with name {name} does not exist.")
    return _json(200, _registry_view(reg))


def _update_registry(name, body):
    reg = _registries.get(name)
    if not reg:
        return _not_found(f"Registry with name {name} does not exist.")
    if "Description" in body:
        reg["Description"] = body["Description"]
    return _json(200, _registry_view(reg))


def _delete_registry(name):
    reg = _registries.get(name)
    if not reg:
        return _not_found(f"Registry with name {name} does not exist.")
    # AWS deletes the registry's schemas with it.
    for key in [k for k in _schemas.keys() if k.startswith(f"{name}/")]:
        _tags.pop(_schemas[key]["SchemaArn"], None)
        _schemas.pop(key, None)
    _registries.pop(name, None)
    _tags.pop(reg["RegistryArn"], None)
    return 204, {}, b""


def _list_registries(query):
    prefix = query.get("registryNamePrefix", "")
    items = [
        {"RegistryName": r["RegistryName"], "RegistryArn": r["RegistryArn"], "tags": _tags.get(r["RegistryArn"], {})}
        for r in _registries.values() if r["RegistryName"].startswith(prefix)
    ]
    return _json(200, {"Registries": items})


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


def _schema_view(schema, version=None, include_content=True):
    ver = schema["Versions"][-1] if version is None else version
    out = {
        "SchemaName": schema["SchemaName"],
        "SchemaArn": schema["SchemaArn"],
        "SchemaVersion": ver["SchemaVersion"],
        "Type": ver["Type"],
        "Description": schema.get("Description", ""),
        "LastModified": schema["LastModified"],
        "VersionCreatedDate": ver["VersionCreatedDate"],
        "tags": _tags.get(schema["SchemaArn"], {}),
    }
    if include_content:
        out["Content"] = ver["Content"]
    return out


def _create_schema(registry, name, body):
    if registry not in _registries:
        return _not_found(f"Registry with name {registry} does not exist.")
    if not _NAME_RE.match(name) or len(name) > 385:
        return _error(400, "BadRequestException", f"Invalid schema name: {name}")
    key = f"{registry}/{name}"
    if key in _schemas:
        return _error(409, "ConflictException", f"Schema with name {name} already exists.")
    err = _validate_content(body.get("Type"), body.get("Content"))
    if err:
        return err
    now = _now()
    schema = {
        "SchemaName": name,
        "RegistryName": registry,
        "SchemaArn": _schema_arn(registry, name),
        "Description": body.get("Description", ""),
        "LastModified": now,
        "Versions": [{"SchemaVersion": "1", "Type": body["Type"], "Content": body["Content"],
                      "VersionCreatedDate": now}],
    }
    _schemas[key] = schema
    _set_tags(schema["SchemaArn"], body.get("tags"))
    return _json(201, _schema_view(schema, include_content=False))


def _find_schema(registry, name):
    if registry not in _registries:
        return None, _not_found(f"Registry with name {registry} does not exist.")
    schema = _schemas.get(f"{registry}/{name}")
    if not schema:
        return None, _not_found(f"Schema with name {name} does not exist.")
    return schema, None


def _describe_schema(registry, name, query):
    schema, err = _find_schema(registry, name)
    if err:
        return err
    wanted = query.get("schemaVersion")
    if wanted:
        version = next((v for v in schema["Versions"] if v["SchemaVersion"] == wanted), None)
        if version is None:
            return _not_found(f"Schema version {wanted} of {name} does not exist.")
        return _json(200, _schema_view(schema, version))
    return _json(200, _schema_view(schema))


def _update_schema(registry, name, body):
    schema, err = _find_schema(registry, name)
    if err:
        return err
    latest = schema["Versions"][-1]
    schema_type = body.get("Type", latest["Type"])
    content = body.get("Content", latest["Content"])
    err = _validate_content(schema_type, content)
    if err:
        return err
    now = _now()
    if "Description" in body:
        schema["Description"] = body["Description"]
    # A new version only when the content or type changes.
    if content != latest["Content"] or schema_type != latest["Type"]:
        schema["Versions"].append({"SchemaVersion": str(len(schema["Versions"]) + 1), "Type": schema_type,
                                   "Content": content, "VersionCreatedDate": now})
    schema["LastModified"] = now
    return _json(200, _schema_view(schema, include_content=False))


def _delete_schema(registry, name):
    schema, err = _find_schema(registry, name)
    if err:
        return err
    _schemas.pop(f"{registry}/{name}", None)
    _tags.pop(schema["SchemaArn"], None)
    return 204, {}, b""


def _list_schemas(registry, query):
    if registry not in _registries:
        return _not_found(f"Registry with name {registry} does not exist.")
    prefix = query.get("schemaNamePrefix", "")
    items = [
        {"SchemaName": s["SchemaName"], "SchemaArn": s["SchemaArn"], "LastModified": s["LastModified"],
         "VersionCount": len(s["Versions"]), "tags": _tags.get(s["SchemaArn"], {})}
        for s in _schemas.values()
        if s["RegistryName"] == registry and s["SchemaName"].startswith(prefix)
    ]
    return _json(200, {"Schemas": items})


def _list_schema_versions(registry, name):
    schema, err = _find_schema(registry, name)
    if err:
        return err
    items = [{"SchemaName": schema["SchemaName"], "SchemaArn": schema["SchemaArn"],
              "SchemaVersion": v["SchemaVersion"], "Type": v["Type"]} for v in schema["Versions"]]
    return _json(200, {"SchemaVersions": items})


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------


def _resource_exists(arn):
    resource = arn.split(":", 5)[-1] if arn.startswith("arn:") else ""
    kind, _, rest = resource.partition("/")
    if kind == "registry":
        reg = _registries.get(rest)
        return bool(reg and reg["RegistryArn"] == arn)
    if kind == "schema":
        schema = _schemas.get(rest)
        return bool(schema and schema["SchemaArn"] == arn)
    return False


def _tag_resource(arn, body):
    if not _resource_exists(arn):
        return _not_found(f"Resource {arn} does not exist.")
    _set_tags(arn, body.get("tags") or {})
    return 204, {}, b""


def _untag_resource(arn, keys):
    if not _resource_exists(arn):
        return _not_found(f"Resource {arn} does not exist.")
    existing = _tags.get(arn, {})
    for key in keys:
        existing.pop(key, None)
    if existing:
        _tags[arn] = existing
    else:
        _tags.pop(arn, None)
    return 204, {}, b""


def _list_tags(arn):
    if not _resource_exists(arn):
        return _not_found(f"Resource {arn} does not exist.")
    return _json(200, {"tags": _tags.get(arn, {})})


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

_REGISTRY_PATH = re.compile(r"^/v1/registries/name/([^/]+)$")
_SCHEMAS_PATH = re.compile(r"^/v1/registries/name/([^/]+)/schemas$")
_SCHEMA_PATH = re.compile(r"^/v1/registries/name/([^/]+)/schemas/name/([^/]+)$")
_VERSIONS_PATH = re.compile(r"^/v1/registries/name/([^/]+)/schemas/name/([^/]+)/versions$")


async def handle_request(method, path, headers, body_bytes, query_params):
    try:
        body = json.loads(body_bytes) if body_bytes else {}
    except json.JSONDecodeError:
        return _error(400, "BadRequestException", "Request body is not valid JSON")
    query = {k: (v[0] if isinstance(v, list) and v else v) for k, v in query_params.items()}

    if path == "/v1/registries" and method == "GET":
        return _list_registries(query)
    m = _REGISTRY_PATH.match(path)
    if m:
        name = unquote(m.group(1))
        if method == "POST":
            return _create_registry(name, body)
        if method == "GET":
            return _describe_registry(name)
        if method == "PUT":
            return _update_registry(name, body)
        if method == "DELETE":
            return _delete_registry(name)
    m = _SCHEMAS_PATH.match(path)
    if m and method == "GET":
        return _list_schemas(unquote(m.group(1)), query)
    m = _SCHEMA_PATH.match(path)
    if m:
        registry, name = unquote(m.group(1)), unquote(m.group(2))
        if method == "POST":
            return _create_schema(registry, name, body)
        if method == "GET":
            return _describe_schema(registry, name, query)
        if method == "PUT":
            return _update_schema(registry, name, body)
        if method == "DELETE":
            return _delete_schema(registry, name)
    m = _VERSIONS_PATH.match(path)
    if m and method == "GET":
        return _list_schema_versions(unquote(m.group(1)), unquote(m.group(2)))

    if path.startswith("/tags/"):
        arn = unquote(path[len("/tags/"):])
        if method == "GET":
            return _list_tags(arn)
        if method == "POST":
            return _tag_resource(arn, body)
        if method == "DELETE":
            keys = query_params.get("tagKeys", [])
            if isinstance(keys, str):
                keys = [keys]
            return _untag_resource(arn, keys)

    return _error(400, "BadRequestException", f"No route for {method} {path}")

"""EventBridge Schemas: registries, versioned schemas and tags."""

import asyncio
import json
import uuid

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError

from ministack.core import persistence
from ministack.core.responses import set_request_account_id, set_request_region
from ministack.services import schemas as schemas_svc

_SCHEMA = json.dumps({"openapi": "3.0.0", "info": {"title": "Event", "version": "1.0.0"}, "paths": {},
                      "components": {"schemas": {"Event": {"type": "object"}}}})
_DRAFT4 = json.dumps({"$schema": "http://json-schema.org/draft-04/schema#", "type": "object"})


def _code(exc):
    return exc.value.response["Error"]["Code"]


def _status(exc):
    return exc.value.response["ResponseMetadata"]["HTTPStatusCode"]


def _expect(exc, code, status):
    assert (_code(exc), _status(exc)) == (code, status)


def _name(prefix="reg"):
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


@pytest.fixture
def registry(schemas):
    name = _name()
    schemas.create_registry(RegistryName=name)
    yield name
    try:
        schemas.delete_registry(RegistryName=name)
    except ClientError:
        pass


def _create_schema(schemas, registry, name="orders.created", content=_SCHEMA, schema_type="OpenApi3", **kw):
    return schemas.create_schema(RegistryName=registry, SchemaName=name, Type=schema_type, Content=content, **kw)


# ---------------------------------------------------------------------------
# Registries
# ---------------------------------------------------------------------------


def test_schemas_registry_create_describe_update(schemas):
    name = _name()
    created = schemas.create_registry(RegistryName=name, Description="orders", Tags={"team": "orders"})
    assert created["ResponseMetadata"]["HTTPStatusCode"] == 201
    assert created["RegistryArn"] == f"arn:aws:schemas:us-east-1:000000000000:registry/{name}"
    got = schemas.describe_registry(RegistryName=name)
    assert (got["RegistryName"], got["Description"], got["Tags"]) == (name, "orders", {"team": "orders"})
    schemas.update_registry(RegistryName=name, Description="changed")
    assert schemas.describe_registry(RegistryName=name)["Description"] == "changed"
    assert schemas.delete_registry(RegistryName=name)["ResponseMetadata"]["HTTPStatusCode"] == 204


def test_schemas_registry_duplicate_is_conflict(schemas, registry):
    with pytest.raises(ClientError) as exc:
        schemas.create_registry(RegistryName=registry)
    _expect(exc, "ConflictException", 409)


@pytest.mark.parametrize("call", ["describe_registry", "update_registry", "delete_registry", "list_schemas"])
def test_schemas_missing_registry_is_not_found(schemas, call):
    with pytest.raises(ClientError) as exc:
        getattr(schemas, call)(RegistryName=_name("missing"))
    _expect(exc, "NotFoundException", 404)


def test_schemas_registry_description_limit(schemas, registry):
    with pytest.raises(ClientError) as exc:
        schemas.create_registry(RegistryName=_name(), Description="x" * 257)
    _expect(exc, "BadRequestException", 400)
    with pytest.raises(ClientError) as exc:
        schemas.update_registry(RegistryName=registry, Description="x" * 257)
    _expect(exc, "BadRequestException", 400)
    schemas.update_registry(RegistryName=registry, Description="x" * 256)


def test_schemas_list_registries_prefix_scope_and_pages(schemas):
    prefix = _name("page")
    names = [f"{prefix}-{i}" for i in range(3)]
    for name in reversed(names):
        schemas.create_registry(RegistryName=name)
    try:
        listed = schemas.list_registries(RegistryNamePrefix=prefix)
        assert [r["RegistryName"] for r in listed["Registries"]] == names
        assert "NextToken" not in listed
        first = schemas.list_registries(RegistryNamePrefix=prefix, Limit=2)
        assert [r["RegistryName"] for r in first["Registries"]] == names[:2]
        second = schemas.list_registries(RegistryNamePrefix=prefix, Limit=2, NextToken=first["NextToken"])
        assert [r["RegistryName"] for r in second["Registries"]] == names[2:]
        assert "NextToken" not in second
        pages = schemas.get_paginator("list_registries").paginate(
            RegistryNamePrefix=prefix, PaginationConfig={"PageSize": 1})
        assert [r["RegistryName"] for page in pages for r in page["Registries"]] == names
        local = schemas.list_registries(RegistryNamePrefix=prefix, Scope="LOCAL")
        assert [r["RegistryName"] for r in local["Registries"]] == names
        assert schemas.list_registries(RegistryNamePrefix=prefix, Scope="AWS")["Registries"] == []
        with pytest.raises(ClientError) as exc:
            schemas.list_registries(Scope="GLOBAL")
        _expect(exc, "BadRequestException", 400)
        with pytest.raises(ClientError) as exc:
            schemas.list_registries(NextToken="not-a-token")
        _expect(exc, "BadRequestException", 400)
    finally:
        for name in names:
            schemas.delete_registry(RegistryName=name)


def test_schemas_registries_are_region_scoped(schemas, registry):
    west = boto3.client(
        "schemas", endpoint_url=schemas.meta.endpoint_url, region_name="us-west-2",
        aws_access_key_id="test", aws_secret_access_key="test", config=Config(retries={"max_attempts": 0}))
    with pytest.raises(ClientError) as exc:
        west.describe_registry(RegistryName=registry)
    _expect(exc, "NotFoundException", 404)
    assert registry not in [r["RegistryName"] for r in west.list_registries()["Registries"]]
    west.create_registry(RegistryName=registry)
    try:
        arn = west.describe_registry(RegistryName=registry)["RegistryArn"]
        assert arn.startswith("arn:aws:schemas:us-west-2:")
    finally:
        west.delete_registry(RegistryName=registry)
    schemas.describe_registry(RegistryName=registry)


def test_schemas_delete_registry_deletes_its_schemas(schemas):
    registry = _name()
    schemas.create_registry(RegistryName=registry)
    arn = _create_schema(schemas, registry, Tags={"k": "v"})["SchemaArn"]
    schemas.delete_registry(RegistryName=registry)
    schemas.create_registry(RegistryName=registry)
    try:
        with pytest.raises(ClientError) as exc:
            schemas.describe_schema(RegistryName=registry, SchemaName="orders.created")
        _expect(exc, "NotFoundException", 404)
        with pytest.raises(ClientError) as exc:
            schemas.list_tags_for_resource(ResourceArn=arn)
        _expect(exc, "NotFoundException", 404)
        assert schemas.list_schemas(RegistryName=registry)["Schemas"] == []
    finally:
        schemas.delete_registry(RegistryName=registry)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


def test_schemas_create_and_describe_schema(schemas, registry):
    created = _create_schema(schemas, registry, Description="orders", Tags={"Name": "orders"})
    assert created["ResponseMetadata"]["HTTPStatusCode"] == 201
    assert created["SchemaArn"] == f"arn:aws:schemas:us-east-1:000000000000:schema/{registry}/orders.created"
    assert (created["SchemaVersion"], created["Type"]) == ("1", "OpenApi3")
    assert "Content" not in created
    got = schemas.describe_schema(RegistryName=registry, SchemaName="orders.created")
    assert json.loads(got["Content"]) == json.loads(_SCHEMA)
    assert (got["Description"], got["Tags"], got["SchemaVersion"]) == ("orders", {"Name": "orders"}, "1")


def test_schemas_create_json_schema_draft4(schemas, registry):
    created = _create_schema(schemas, registry, name="draft4", content=_DRAFT4, schema_type="JSONSchemaDraft4")
    assert created["Type"] == "JSONSchemaDraft4"
    assert schemas.describe_schema(RegistryName=registry, SchemaName="draft4")["Content"] == _DRAFT4


def test_schemas_create_schema_in_missing_registry(schemas):
    with pytest.raises(ClientError) as exc:
        _create_schema(schemas, _name("missing"))
    _expect(exc, "NotFoundException", 404)


def test_schemas_duplicate_schema_is_conflict(schemas, registry):
    _create_schema(schemas, registry)
    with pytest.raises(ClientError) as exc:
        _create_schema(schemas, registry)
    _expect(exc, "ConflictException", 409)


@pytest.mark.parametrize("kwargs", [
    {"Type": "Avro", "Content": _SCHEMA},
    {"Type": "OpenApi3", "Content": "{not json"},
    {"Type": "OpenApi3", "Content": "x" * 100001},
    {"Type": "OpenApi3", "Content": _SCHEMA, "Description": "x" * 257},
], ids=["bad-type", "invalid-json", "content-too-long", "description-too-long"])
def test_schemas_create_schema_rejects_bad_input(schemas, registry, kwargs):
    with pytest.raises(ClientError) as exc:
        schemas.create_schema(RegistryName=registry, SchemaName="bad", **kwargs)
    _expect(exc, "BadRequestException", 400)
    with pytest.raises(ClientError) as exc:
        schemas.describe_schema(RegistryName=registry, SchemaName="bad")
    _expect(exc, "NotFoundException", 404)


def test_schemas_update_description_only_keeps_version(schemas, registry):
    _create_schema(schemas, registry)
    updated = schemas.update_schema(RegistryName=registry, SchemaName="orders.created", Description="same body")
    assert updated["SchemaVersion"] == "1"
    got = schemas.describe_schema(RegistryName=registry, SchemaName="orders.created")
    assert (got["Description"], got["SchemaVersion"]) == ("same body", "1")


def test_schemas_update_content_adds_version(schemas, registry):
    _create_schema(schemas, registry)
    changed = json.dumps({**json.loads(_SCHEMA), "info": {"title": "Event", "version": "2.0.0"}})
    updated = schemas.update_schema(RegistryName=registry, SchemaName="orders.created", Content=changed)
    assert updated["SchemaVersion"] == "2"
    latest = schemas.describe_schema(RegistryName=registry, SchemaName="orders.created")
    assert (latest["SchemaVersion"], latest["Content"]) == ("2", changed)
    first = schemas.describe_schema(RegistryName=registry, SchemaName="orders.created", SchemaVersion="1")
    assert json.loads(first["Content"]) == json.loads(_SCHEMA)
    same = schemas.update_schema(RegistryName=registry, SchemaName="orders.created", Content=changed)
    assert same["SchemaVersion"] == "2"


def test_schemas_update_type_only_adds_version(schemas, registry):
    _create_schema(schemas, registry, content=_DRAFT4)
    updated = schemas.update_schema(RegistryName=registry, SchemaName="orders.created", Type="JSONSchemaDraft4")
    assert (updated["SchemaVersion"], updated["Type"]) == ("2", "JSONSchemaDraft4")
    versions = schemas.list_schema_versions(RegistryName=registry, SchemaName="orders.created")["SchemaVersions"]
    assert [(v["SchemaVersion"], v["Type"]) for v in versions] == [("1", "OpenApi3"), ("2", "JSONSchemaDraft4")]


@pytest.mark.parametrize("kwargs", [
    {"Content": "{not json"}, {"Content": "x" * 100001}, {"Type": "Avro"}, {"Description": "x" * 257},
], ids=["invalid-json", "content-too-long", "bad-type", "description-too-long"])
def test_schemas_update_schema_rejects_bad_input(schemas, registry, kwargs):
    _create_schema(schemas, registry)
    with pytest.raises(ClientError) as exc:
        schemas.update_schema(RegistryName=registry, SchemaName="orders.created", **kwargs)
    _expect(exc, "BadRequestException", 400)
    got = schemas.describe_schema(RegistryName=registry, SchemaName="orders.created")
    assert (got["SchemaVersion"], got["Description"]) == ("1", "")


@pytest.mark.parametrize("call", ["describe_schema", "update_schema", "delete_schema", "list_schema_versions"])
def test_schemas_missing_schema_is_not_found(schemas, registry, call):
    with pytest.raises(ClientError) as exc:
        getattr(schemas, call)(RegistryName=registry, SchemaName="missing")
    _expect(exc, "NotFoundException", 404)


def test_schemas_describe_unknown_version_is_not_found(schemas, registry):
    _create_schema(schemas, registry)
    with pytest.raises(ClientError) as exc:
        schemas.describe_schema(RegistryName=registry, SchemaName="orders.created", SchemaVersion="9")
    _expect(exc, "NotFoundException", 404)


def test_schemas_delete_schema(schemas, registry):
    arn = _create_schema(schemas, registry)["SchemaArn"]
    assert schemas.delete_schema(
        RegistryName=registry, SchemaName="orders.created")["ResponseMetadata"]["HTTPStatusCode"] == 204
    with pytest.raises(ClientError) as exc:
        schemas.describe_schema(RegistryName=registry, SchemaName="orders.created")
    _expect(exc, "NotFoundException", 404)
    with pytest.raises(ClientError) as exc:
        schemas.list_tags_for_resource(ResourceArn=arn)
    _expect(exc, "NotFoundException", 404)


def test_schemas_list_schemas_prefix_and_pages(schemas, registry):
    for name in ("b.two", "a.one", "c.three", "other"):
        _create_schema(schemas, registry, name=name)
    listed = schemas.list_schemas(RegistryName=registry)["Schemas"]
    assert [s["SchemaName"] for s in listed] == ["a.one", "b.two", "c.three", "other"]
    assert listed[0]["VersionCount"] == 1
    filtered = schemas.list_schemas(RegistryName=registry, SchemaNamePrefix="b.")["Schemas"]
    assert [s["SchemaName"] for s in filtered] == ["b.two"]
    page = schemas.list_schemas(RegistryName=registry, Limit=3)
    assert [s["SchemaName"] for s in page["Schemas"]] == ["a.one", "b.two", "c.three"]
    rest = schemas.list_schemas(RegistryName=registry, Limit=3, NextToken=page["NextToken"])
    assert [s["SchemaName"] for s in rest["Schemas"]] == ["other"]
    assert "NextToken" not in rest


def test_schemas_list_schema_versions_pages(schemas, registry):
    _create_schema(schemas, registry)
    for version in ("2", "3"):
        content = json.dumps({**json.loads(_SCHEMA), "info": {"title": "Event", "version": version}})
        schemas.update_schema(RegistryName=registry, SchemaName="orders.created", Content=content)
    pages = schemas.get_paginator("list_schema_versions").paginate(
        RegistryName=registry, SchemaName="orders.created", PaginationConfig={"PageSize": 2})
    assert [len(p["SchemaVersions"]) for p in pages] == [2, 1]


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------


def test_schemas_tags_on_schema_and_registry(schemas, registry):
    schema_arn = _create_schema(schemas, registry, Tags={"Name": "orders"})["SchemaArn"]
    registry_arn = schemas.describe_registry(RegistryName=registry)["RegistryArn"]
    assert schemas.tag_resource(
        ResourceArn=schema_arn, Tags={"env": "dev"})["ResponseMetadata"]["HTTPStatusCode"] == 204
    schemas.untag_resource(ResourceArn=schema_arn, TagKeys=["Name"])
    assert schemas.list_tags_for_resource(ResourceArn=schema_arn)["Tags"] == {"env": "dev"}
    schemas.tag_resource(ResourceArn=registry_arn, Tags={"owner": "orders"})
    assert schemas.list_tags_for_resource(ResourceArn=registry_arn)["Tags"] == {"owner": "orders"}
    assert schemas.describe_registry(RegistryName=registry)["Tags"] == {"owner": "orders"}
    schemas.untag_resource(ResourceArn=registry_arn, TagKeys=["owner"])
    assert schemas.list_tags_for_resource(ResourceArn=registry_arn)["Tags"] == {}


@pytest.mark.parametrize("arn", [
    "arn:aws:schemas:us-east-1:000000000000:registry/does-not-exist",
    "arn:aws:schemas:us-east-1:000000000000:schema/does-not-exist/x",
    "arn:aws:schemas:us-east-1:000000000000:discoverer/x",
    "not-an-arn",
], ids=["missing-registry", "missing-schema", "other-type", "malformed"])
def test_schemas_tags_on_unknown_resource_are_not_found(schemas, arn):
    for call, kwargs in (("list_tags_for_resource", {}), ("tag_resource", {"Tags": {"a": "b"}}),
                         ("untag_resource", {"TagKeys": ["a"]})):
        with pytest.raises(ClientError) as exc:
            getattr(schemas, call)(ResourceArn=arn, **kwargs)
        _expect(exc, "NotFoundException", 404)


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------


@pytest.mark.auth_contract
@pytest.mark.parametrize("permission", ["none", "list-only", "allow", "other-registry"])
def test_schemas_create_registry_permission_contract(auth_enabled, iam_user, schemas, permission):
    name = _name("auth")
    statements = {
        "none": [],
        "list-only": [{"Effect": "Allow", "Action": "schemas:ListRegistries", "Resource": "*"}],
        "allow": [{"Effect": "Allow", "Action": "schemas:CreateRegistry",
                   "Resource": f"arn:aws:schemas:us-east-1:*:registry/{name}"}],
        "other-registry": [{"Effect": "Allow", "Action": "schemas:CreateRegistry",
                            "Resource": "arn:aws:schemas:us-east-1:*:registry/other"}],
    }[permission]
    policy = {"Version": "2012-10-17", "Statement": statements} if statements else None
    client = iam_user(policy=policy).client("schemas")
    try:
        if auth_enabled and permission != "allow":
            with pytest.raises(ClientError) as exc:
                client.create_registry(RegistryName=name)
            assert _code(exc) in ("AccessDenied", "AccessDeniedException")
            assert _status(exc) == 403
            with pytest.raises(ClientError) as exc:
                schemas.describe_registry(RegistryName=name)
            _expect(exc, "NotFoundException", 404)
        else:
            assert client.create_registry(RegistryName=name)["RegistryArn"].endswith(f":registry/{name}")
    finally:
        try:
            schemas.delete_registry(RegistryName=name)
        except ClientError:
            pass


@pytest.mark.auth_contract
@pytest.mark.parametrize("permission", ["none", "allow"])
def test_schemas_schema_permission_contract(auth_enabled, iam_user, schemas, registry, permission):
    arn = _create_schema(schemas, registry)["SchemaArn"]
    statements = [{"Effect": "Allow", "Action": ["schemas:DescribeSchema", "schemas:ListTagsForResource"],
                   "Resource": arn}] if permission == "allow" else []
    policy = {"Version": "2012-10-17", "Statement": statements} if statements else None
    client = iam_user(policy=policy).client("schemas")
    if auth_enabled and permission == "none":
        for call, kwargs in (("describe_schema", {"RegistryName": registry, "SchemaName": "orders.created"}),
                             ("list_tags_for_resource", {"ResourceArn": arn}),
                             ("delete_schema", {"RegistryName": registry, "SchemaName": "orders.created"})):
            with pytest.raises(ClientError) as exc:
                getattr(client, call)(**kwargs)
            assert _code(exc) in ("AccessDenied", "AccessDeniedException")
            assert _status(exc) == 403
        schemas.describe_schema(RegistryName=registry, SchemaName="orders.created")
    else:
        assert client.describe_schema(RegistryName=registry, SchemaName="orders.created")["SchemaArn"] == arn
        assert client.list_tags_for_resource(ResourceArn=arn)["Tags"] == {}
        if auth_enabled:
            with pytest.raises(ClientError) as exc:
                client.delete_schema(RegistryName=registry, SchemaName="orders.created")
            assert _status(exc) == 403


# ---------------------------------------------------------------------------
# In-process: account isolation and persistence
# ---------------------------------------------------------------------------


def _call(method, path, body=None, query=None):
    raw = json.dumps(body).encode() if body is not None else b""
    status, _, out = asyncio.run(schemas_svc.handle_request(method, path, {}, raw, query or {}))
    return status, (json.loads(out) if out else {})


@pytest.fixture
def local_state():
    saved = schemas_svc.get_state()
    schemas_svc.reset()
    set_request_region("us-east-1")
    set_request_account_id("111111111111")
    yield
    set_request_account_id("000000000000")
    schemas_svc.reset()
    schemas_svc.load_persisted_state(saved)


def test_schemas_registries_are_account_scoped(local_state):
    assert _call("POST", "/v1/registries/name/shared")[0] == 201
    set_request_account_id("222222222222")
    assert _call("GET", "/v1/registries/name/shared")[0] == 404
    assert _call("GET", "/v1/registries")[1]["Registries"] == []
    assert _call("POST", "/v1/registries/name/shared")[0] == 201
    set_request_account_id("111111111111")
    status, body = _call("GET", "/v1/registries/name/shared")
    assert (status, body["RegistryArn"]) == (200, "arn:aws:schemas:us-east-1:111111111111:registry/shared")


def test_schemas_state_round_trips_through_persistence(local_state):
    _call("POST", "/v1/registries/name/kept", {"Description": "d", "tags": {"a": "1"}})
    _call("POST", "/v1/registries/name/kept/schemas/name/s", {"Type": "OpenApi3", "Content": _SCHEMA})
    _call("PUT", "/v1/registries/name/kept/schemas/name/s", {"Content": _DRAFT4, "Type": "JSONSchemaDraft4"})
    set_request_account_id("222222222222")
    _call("POST", "/v1/registries/name/other")
    # Through the same JSON encoding the state file uses, so every tenant is kept.
    state = json.loads(json.dumps(schemas_svc.get_state(), default=persistence._json_default),
                       object_hook=persistence._json_object_hook)
    schemas_svc.reset()
    assert _call("GET", "/v1/registries/name/other")[0] == 404
    schemas_svc.load_persisted_state(state)
    assert _call("GET", "/v1/registries/name/other")[0] == 200
    set_request_account_id("111111111111")
    status, reg = _call("GET", "/v1/registries/name/kept")
    assert (status, reg["Description"], reg["tags"]) == (200, "d", {"a": "1"})
    status, versions = _call("GET", "/v1/registries/name/kept/schemas/name/s/versions")
    assert [v["SchemaVersion"] for v in versions["SchemaVersions"]] == ["1", "2"]
    status, first = _call("GET", "/v1/registries/name/kept/schemas/name/s", query={"schemaVersion": "1"})
    assert first["Content"] == _SCHEMA

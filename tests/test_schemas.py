"""EventBridge Schemas: the registry and schema calls the Terraform aws_schemas_* resources make."""

import json
import uuid

import pytest
from botocore.exceptions import ClientError

_SCHEMA = json.dumps({"openapi": "3.0.0", "info": {"title": "Event", "version": "1.0.0"}, "paths": {},
                      "components": {"schemas": {"Event": {"type": "object"}}}})


def _code(exc):
    return exc.value.response["Error"]["Code"]


def test_schemas_registry_lifecycle(schemas):
    name = f"reg-{uuid.uuid4().hex[:8]}"
    created = schemas.create_registry(RegistryName=name, Description="platform", Tags={"team": "platform"})
    assert created["RegistryArn"].endswith(f":registry/{name}")
    got = schemas.describe_registry(RegistryName=name)
    assert got["Description"] == "platform"
    assert got["Tags"] == {"team": "platform"}
    schemas.update_registry(RegistryName=name, Description="changed")
    assert schemas.describe_registry(RegistryName=name)["Description"] == "changed"
    assert name in [r["RegistryName"] for r in schemas.list_registries()["Registries"]]
    with pytest.raises(ClientError) as exc:
        schemas.create_registry(RegistryName=name)
    assert _code(exc) == "ConflictException"
    schemas.delete_registry(RegistryName=name)
    with pytest.raises(ClientError) as exc:
        schemas.describe_registry(RegistryName=name)
    assert _code(exc) == "NotFoundException"


def test_schemas_schema_versions_and_tags(schemas):
    registry = f"reg-{uuid.uuid4().hex[:8]}"
    schemas.create_registry(RegistryName=registry)
    created = schemas.create_schema(RegistryName=registry, SchemaName="delayed.event", Type="OpenApi3",
                                    Content=_SCHEMA, Tags={"Name": "delayed"})
    assert created["SchemaVersion"] == "1"
    arn = created["SchemaArn"]
    got = schemas.describe_schema(RegistryName=registry, SchemaName="delayed.event")
    assert json.loads(got["Content"]) == json.loads(_SCHEMA)
    assert got["Type"] == "OpenApi3"
    assert got["Tags"] == {"Name": "delayed"}

    unchanged = schemas.update_schema(RegistryName=registry, SchemaName="delayed.event", Description="same body")
    assert unchanged["SchemaVersion"] == "1"
    changed = json.dumps({**json.loads(_SCHEMA), "info": {"title": "Event", "version": "2.0.0"}})
    updated = schemas.update_schema(RegistryName=registry, SchemaName="delayed.event", Type="OpenApi3", Content=changed)
    assert updated["SchemaVersion"] == "2"
    assert [v["SchemaVersion"] for v in schemas.list_schema_versions(
        RegistryName=registry, SchemaName="delayed.event")["SchemaVersions"]] == ["1", "2"]
    first = schemas.describe_schema(RegistryName=registry, SchemaName="delayed.event", SchemaVersion="1")
    assert json.loads(first["Content"]) == json.loads(_SCHEMA)

    schemas.tag_resource(ResourceArn=arn, Tags={"env": "dev"})
    schemas.untag_resource(ResourceArn=arn, TagKeys=["Name"])
    assert schemas.list_tags_for_resource(ResourceArn=arn)["Tags"] == {"env": "dev"}
    assert [s["SchemaName"] for s in schemas.list_schemas(RegistryName=registry)["Schemas"]] == ["delayed.event"]

    with pytest.raises(ClientError) as exc:
        schemas.create_schema(RegistryName=registry, SchemaName="bad", Type="Avro", Content=_SCHEMA)
    assert _code(exc) == "BadRequestException"
    schemas.delete_schema(RegistryName=registry, SchemaName="delayed.event")
    with pytest.raises(ClientError) as exc:
        schemas.describe_schema(RegistryName=registry, SchemaName="delayed.event")
    assert _code(exc) == "NotFoundException"
    schemas.delete_registry(RegistryName=registry)

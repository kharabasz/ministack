"""Application Auto Scaling: the ECS control plane used by Terraform aws_appautoscaling_* and the
AWS::ApplicationAutoScaling::* CloudFormation types."""

import json
import re
import time
import uuid

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from conftest import ENDPOINT, make_client

from ministack.core import persistence
from ministack.core.responses import request_scope
from ministack.core.router import detect_service
from ministack.services import application_autoscaling as aas

_DIM = "ecs:service:DesiredCount"
_CPU = {"TargetValue": 70.0, "ScaleInCooldown": 60, "ScaleOutCooldown": 60,
        "PredefinedMetricSpecification": {"PredefinedMetricType": "ECSServiceAverageCPUUtilization"}}
_MEMORY = {"TargetValue": 80.0,
           "PredefinedMetricSpecification": {"PredefinedMetricType": "ECSServiceAverageMemoryUtilization"}}
_STEP = {"AdjustmentType": "ChangeInCapacity", "Cooldown": 60, "MetricAggregationType": "Average",
         "StepAdjustments": [{"MetricIntervalLowerBound": 0.0, "ScalingAdjustment": 1}]}


def _resource():
    return f"service/cluster-{uuid.uuid4().hex[:8]}/svc"


def _code(exc):
    return exc.value.response["Error"]["Code"]


def _register(client, rid, **kwargs):
    kwargs.setdefault("MinCapacity", 1)
    kwargs.setdefault("MaxCapacity", 6)
    return client.register_scalable_target(
        ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM, **kwargs)["ScalableTargetARN"]


def _target(client, rid):
    targets = client.describe_scalable_targets(ServiceNamespace="ecs", ResourceIds=[rid])["ScalableTargets"]
    assert len(targets) <= 1
    return targets[0] if targets else None


def _other_client(**kwargs):
    kwargs.setdefault("region_name", "us-east-1")
    kwargs.setdefault("aws_access_key_id", "test")
    return boto3.client("application-autoscaling", endpoint_url=ENDPOINT, aws_secret_access_key="test",
                        config=Config(retries={"max_attempts": 0}), **kwargs)


# ---------------------------------------------------------------------------
# Scalable targets
# ---------------------------------------------------------------------------


def test_register_and_describe_scalable_target(appautoscaling):
    rid = _resource()
    arn = _register(appautoscaling, rid)
    target = _target(appautoscaling, rid)
    assert (target["MinCapacity"], target["MaxCapacity"]) == (1, 6)
    assert target["ScalableTargetARN"] == arn
    assert re.fullmatch(r"arn:aws:application-autoscaling:us-east-1:\d{12}:scalable-target/[0-9a-f]{36}", arn)
    assert target["RoleARN"].endswith(
        ":role/aws-service-role/ecs.application-autoscaling.amazonaws.com/"
        "AWSServiceRoleForApplicationAutoScaling_ECSService")
    assert target["SuspendedState"] == {"DynamicScalingInSuspended": False, "DynamicScalingOutSuspended": False,
                                        "ScheduledScalingSuspended": False}
    assert not any(k.startswith("_") for k in target)


def test_describe_scalable_targets_without_resource_ids(appautoscaling):
    rids = [_resource(), _resource()]
    for rid in rids:
        _register(appautoscaling, rid)
    listed = []
    paginator = appautoscaling.get_paginator("describe_scalable_targets")
    for page in paginator.paginate(ServiceNamespace="ecs"):
        listed += [t["ResourceId"] for t in page["ScalableTargets"]]
    assert set(rids) <= set(listed)


def test_register_again_updates_existing_target(appautoscaling):
    rid = _resource()
    arn = _register(appautoscaling, rid)
    role = "arn:aws:iam::000000000000:role/custom-scaling"
    again = appautoscaling.register_scalable_target(
        ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM, MaxCapacity=10, RoleARN=role,
        SuspendedState={"ScheduledScalingSuspended": True})["ScalableTargetARN"]
    assert again == arn
    target = _target(appautoscaling, rid)
    assert (target["MinCapacity"], target["MaxCapacity"]) == (1, 10)
    assert target["RoleARN"] == role
    assert target["SuspendedState"]["ScheduledScalingSuspended"] is True
    assert target["SuspendedState"]["DynamicScalingInSuspended"] is False


def test_rejected_update_leaves_target_unchanged(appautoscaling):
    rid = _resource()
    _register(appautoscaling, rid)
    with pytest.raises(ClientError) as exc:
        appautoscaling.register_scalable_target(
            ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM, MinCapacity=10,
            SuspendedState={"DynamicScalingInSuspended": True})
    assert _code(exc) == "ValidationException"
    target = _target(appautoscaling, rid)
    assert (target["MinCapacity"], target["MaxCapacity"]) == (1, 6)
    assert target["SuspendedState"]["DynamicScalingInSuspended"] is False


def test_new_target_requires_min_and_max(appautoscaling):
    rid = _resource()
    with pytest.raises(ClientError) as exc:
        appautoscaling.register_scalable_target(
            ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM, MaxCapacity=3)
    assert _code(exc) == "ValidationException"
    assert _target(appautoscaling, rid) is None


def test_new_target_min_greater_than_max(appautoscaling):
    rid = _resource()
    with pytest.raises(ClientError) as exc:
        _register(appautoscaling, rid, MinCapacity=5, MaxCapacity=2)
    assert _code(exc) == "ValidationException"
    assert _target(appautoscaling, rid) is None


@pytest.mark.parametrize("namespace,rid,dimension", [
    ("dynamodb", "table/my-table", "dynamodb:table:ReadCapacityUnits"),
    ("ecs", "service/cluster/svc", "dynamodb:table:ReadCapacityUnits"),
    ("ecs", "table/my-table", _DIM),
    ("not-a-namespace", "service/cluster/svc", _DIM),
])
def test_register_rejects_unsupported_identity(appautoscaling, namespace, rid, dimension):
    with pytest.raises(ClientError) as exc:
        appautoscaling.register_scalable_target(
            ServiceNamespace=namespace, ResourceId=rid, ScalableDimension=dimension, MinCapacity=1, MaxCapacity=2)
    assert _code(exc) == "ValidationException"


def test_describe_rejects_unknown_namespace(appautoscaling):
    for op in (appautoscaling.describe_scalable_targets, appautoscaling.describe_scaling_policies,
               appautoscaling.describe_scheduled_actions):
        with pytest.raises(ClientError) as exc:
            op(ServiceNamespace="not-a-namespace")
        assert _code(exc) == "ValidationException"


def test_describe_filters_by_dimension(appautoscaling):
    rid = _resource()
    _register(appautoscaling, rid)
    assert appautoscaling.describe_scalable_targets(
        ServiceNamespace="ecs", ResourceIds=[rid], ScalableDimension="ecs:other:Dimension")["ScalableTargets"] == []
    assert len(appautoscaling.describe_scalable_targets(
        ServiceNamespace="ecs", ResourceIds=[rid], ScalableDimension=_DIM)["ScalableTargets"]) == 1


def test_describe_paginates(appautoscaling):
    rids = sorted(_resource() for _ in range(3))
    for rid in rids:
        _register(appautoscaling, rid)
    first = appautoscaling.describe_scalable_targets(ServiceNamespace="ecs", ResourceIds=rids, MaxResults=2)
    assert len(first["ScalableTargets"]) == 2
    second = appautoscaling.describe_scalable_targets(
        ServiceNamespace="ecs", ResourceIds=rids, MaxResults=2, NextToken=first["NextToken"])
    assert len(second["ScalableTargets"]) == 1
    assert "NextToken" not in second
    seen = {t["ResourceId"] for t in first["ScalableTargets"] + second["ScalableTargets"]}
    assert seen == set(rids)
    with pytest.raises(ClientError) as exc:
        appautoscaling.describe_scalable_targets(ServiceNamespace="ecs", NextToken="not-a-token")
    assert _code(exc) == "InvalidNextTokenException"
    with pytest.raises(ClientError) as exc:
        appautoscaling.describe_scalable_targets(ServiceNamespace="ecs", MaxResults=51)
    assert _code(exc) == "ValidationException"


def test_deregister_unknown_target(appautoscaling):
    with pytest.raises(ClientError) as exc:
        appautoscaling.deregister_scalable_target(ServiceNamespace="ecs", ResourceId=_resource(),
                                                  ScalableDimension=_DIM)
    assert _code(exc) == "ObjectNotFoundException"


def test_deregister_removes_policies_scheduled_actions_and_tags(appautoscaling):
    rid = _resource()
    arn = _register(appautoscaling, rid, Tags={"team": "a"})
    appautoscaling.put_scaling_policy(
        PolicyName="cpu", ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM,
        PolicyType="TargetTrackingScaling", TargetTrackingScalingPolicyConfiguration=_CPU)
    appautoscaling.put_scheduled_action(
        ServiceNamespace="ecs", ScheduledActionName="night", ResourceId=rid, ScalableDimension=_DIM,
        Schedule="cron(0 22 * * ? *)")
    appautoscaling.deregister_scalable_target(ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM)

    assert _target(appautoscaling, rid) is None
    assert appautoscaling.describe_scaling_policies(ServiceNamespace="ecs", ResourceId=rid)["ScalingPolicies"] == []
    assert appautoscaling.describe_scheduled_actions(
        ServiceNamespace="ecs", ResourceId=rid)["ScheduledActions"] == []
    with pytest.raises(ClientError) as exc:
        appautoscaling.list_tags_for_resource(ResourceARN=arn)
    assert _code(exc) == "ResourceNotFoundException"


# ---------------------------------------------------------------------------
# Scaling policies
# ---------------------------------------------------------------------------


def test_put_policy_requires_registered_target(appautoscaling):
    with pytest.raises(ClientError) as exc:
        appautoscaling.put_scaling_policy(
            PolicyName="cpu", ServiceNamespace="ecs", ResourceId=_resource(), ScalableDimension=_DIM,
            PolicyType="TargetTrackingScaling", TargetTrackingScalingPolicyConfiguration=_CPU)
    assert _code(exc) == "ObjectNotFoundException"


def test_target_tracking_policy(appautoscaling):
    rid = _resource()
    _register(appautoscaling, rid)
    put = appautoscaling.put_scaling_policy(
        PolicyName="cpu", ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM,
        PolicyType="TargetTrackingScaling", TargetTrackingScalingPolicyConfiguration=_CPU)
    assert re.fullmatch(
        rf"arn:aws:autoscaling:us-east-1:\d{{12}}:scalingPolicy:[0-9a-f-]{{36}}:resource/ecs/{rid}:policyName/cpu",
        put["PolicyARN"])
    # No CloudWatch alarms are created, so none are reported.
    assert put.get("Alarms", []) == []
    policy = appautoscaling.describe_scaling_policies(ServiceNamespace="ecs", ResourceId=rid)["ScalingPolicies"][0]
    assert policy["PolicyARN"] == put["PolicyARN"]
    assert policy["PolicyType"] == "TargetTrackingScaling"
    assert policy["TargetTrackingScalingPolicyConfiguration"] == _CPU
    assert "StepScalingPolicyConfiguration" not in policy


def test_two_policies_on_one_target_have_distinct_arns(appautoscaling):
    rid = _resource()
    _register(appautoscaling, rid)
    arns = [appautoscaling.put_scaling_policy(
        PolicyName=name, ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM,
        PolicyType="TargetTrackingScaling", TargetTrackingScalingPolicyConfiguration=config)["PolicyARN"]
        for name, config in (("cpu", _CPU), ("memory", _MEMORY))]
    assert arns[0] != arns[1]
    assert arns[0].endswith(":policyName/cpu") and arns[1].endswith(":policyName/memory")


def test_put_policy_again_updates_in_place(appautoscaling):
    rid = _resource()
    _register(appautoscaling, rid)
    first = appautoscaling.put_scaling_policy(
        PolicyName="cpu", ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM,
        PolicyType="TargetTrackingScaling", TargetTrackingScalingPolicyConfiguration=_CPU)["PolicyARN"]
    created = appautoscaling.describe_scaling_policies(
        ServiceNamespace="ecs", ResourceId=rid)["ScalingPolicies"][0]["CreationTime"]
    updated_config = dict(_CPU, TargetValue=50.0)
    second = appautoscaling.put_scaling_policy(
        PolicyName="cpu", ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM,
        PolicyType="TargetTrackingScaling", TargetTrackingScalingPolicyConfiguration=updated_config)["PolicyARN"]
    assert second == first
    policies = appautoscaling.describe_scaling_policies(ServiceNamespace="ecs", ResourceId=rid)["ScalingPolicies"]
    assert len(policies) == 1
    assert policies[0]["CreationTime"] == created
    assert policies[0]["TargetTrackingScalingPolicyConfiguration"]["TargetValue"] == 50.0


def test_step_scaling_policy_and_name_filter(appautoscaling):
    rid = _resource()
    _register(appautoscaling, rid)
    appautoscaling.put_scaling_policy(
        PolicyName="scale-out", ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM,
        PolicyType="StepScaling", StepScalingPolicyConfiguration=_STEP)
    appautoscaling.put_scaling_policy(
        PolicyName="cpu", ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM,
        PolicyType="TargetTrackingScaling", TargetTrackingScalingPolicyConfiguration=_CPU)
    found = appautoscaling.describe_scaling_policies(
        ServiceNamespace="ecs", ResourceId=rid, PolicyNames=["scale-out"])["ScalingPolicies"]
    assert [p["PolicyName"] for p in found] == ["scale-out"]
    assert found[0]["PolicyType"] == "StepScaling"
    assert found[0]["StepScalingPolicyConfiguration"] == _STEP


@pytest.mark.parametrize("kwargs", [
    {"PolicyType": "TargetTrackingScaling"},
    {"PolicyType": "StepScaling"},
    {"PolicyType": "NotAType", "StepScalingPolicyConfiguration": _STEP},
    {"PolicyType": "PredictiveScaling",
     "PredictiveScalingPolicyConfiguration": {"MetricSpecifications": [{"TargetValue": 40.0}]}},
])
def test_put_policy_validation(appautoscaling, kwargs):
    rid = _resource()
    _register(appautoscaling, rid)
    with pytest.raises(ClientError) as exc:
        appautoscaling.put_scaling_policy(
            PolicyName="p", ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM, **kwargs)
    assert _code(exc) == "ValidationException"
    assert appautoscaling.describe_scaling_policies(ServiceNamespace="ecs", ResourceId=rid)["ScalingPolicies"] == []


def test_delete_scaling_policy(appautoscaling):
    rid = _resource()
    _register(appautoscaling, rid)
    appautoscaling.put_scaling_policy(
        PolicyName="cpu", ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM,
        PolicyType="TargetTrackingScaling", TargetTrackingScalingPolicyConfiguration=_CPU)
    appautoscaling.delete_scaling_policy(PolicyName="cpu", ServiceNamespace="ecs", ResourceId=rid,
                                         ScalableDimension=_DIM)
    assert appautoscaling.describe_scaling_policies(ServiceNamespace="ecs", ResourceId=rid)["ScalingPolicies"] == []
    with pytest.raises(ClientError) as exc:
        appautoscaling.delete_scaling_policy(PolicyName="cpu", ServiceNamespace="ecs", ResourceId=rid,
                                             ScalableDimension=_DIM)
    assert _code(exc) == "ObjectNotFoundException"


# ---------------------------------------------------------------------------
# Scheduled actions
# ---------------------------------------------------------------------------


def test_scheduled_action_lifecycle(appautoscaling):
    rid = _resource()
    _register(appautoscaling, rid)
    appautoscaling.put_scheduled_action(
        ServiceNamespace="ecs", ScheduledActionName="night", ResourceId=rid, ScalableDimension=_DIM,
        Schedule="cron(0 22 * * ? *)", Timezone="Europe/Warsaw",
        ScalableTargetAction={"MinCapacity": 0, "MaxCapacity": 1})
    action = appautoscaling.describe_scheduled_actions(
        ServiceNamespace="ecs", ResourceId=rid)["ScheduledActions"][0]
    assert action["Schedule"] == "cron(0 22 * * ? *)"
    assert action["Timezone"] == "Europe/Warsaw"
    assert action["ScalableTargetAction"] == {"MinCapacity": 0, "MaxCapacity": 1}
    assert re.fullmatch(
        rf"arn:aws:autoscaling:us-east-1:\d{{12}}:scheduledAction:[0-9a-f-]{{36}}:resource/ecs/{rid}"
        r":scheduledActionName/night", action["ScheduledActionARN"])

    # Putting it again updates the given fields and keeps the ARN.
    appautoscaling.put_scheduled_action(
        ServiceNamespace="ecs", ScheduledActionName="night", ResourceId=rid, ScalableDimension=_DIM,
        ScalableTargetAction={"MinCapacity": 1, "MaxCapacity": 2})
    updated = appautoscaling.describe_scheduled_actions(
        ServiceNamespace="ecs", ResourceId=rid, ScheduledActionNames=["night"])["ScheduledActions"]
    assert len(updated) == 1
    assert updated[0]["ScheduledActionARN"] == action["ScheduledActionARN"]
    assert updated[0]["Schedule"] == "cron(0 22 * * ? *)"
    assert updated[0]["ScalableTargetAction"] == {"MinCapacity": 1, "MaxCapacity": 2}

    appautoscaling.delete_scheduled_action(
        ServiceNamespace="ecs", ScheduledActionName="night", ResourceId=rid, ScalableDimension=_DIM)
    assert appautoscaling.describe_scheduled_actions(
        ServiceNamespace="ecs", ResourceId=rid)["ScheduledActions"] == []
    with pytest.raises(ClientError) as exc:
        appautoscaling.delete_scheduled_action(
            ServiceNamespace="ecs", ScheduledActionName="night", ResourceId=rid, ScalableDimension=_DIM)
    assert _code(exc) == "ObjectNotFoundException"


def test_scheduled_action_validation(appautoscaling):
    rid = _resource()
    with pytest.raises(ClientError) as exc:
        appautoscaling.put_scheduled_action(
            ServiceNamespace="ecs", ScheduledActionName="night", ResourceId=rid, ScalableDimension=_DIM,
            Schedule="rate(1 hour)")
    assert _code(exc) == "ObjectNotFoundException"
    _register(appautoscaling, rid)
    for kwargs in ({}, {"Schedule": "rate(1 hour)", "ScalableTargetAction": {"MinCapacity": 3, "MaxCapacity": 1}}):
        with pytest.raises(ClientError) as exc:
            appautoscaling.put_scheduled_action(
                ServiceNamespace="ecs", ScheduledActionName="night", ResourceId=rid, ScalableDimension=_DIM,
                **kwargs)
        assert _code(exc) == "ValidationException"
    assert appautoscaling.describe_scheduled_actions(
        ServiceNamespace="ecs", ResourceId=rid)["ScheduledActions"] == []


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------


def test_tags_on_scalable_target(appautoscaling):
    rid = _resource()
    arn = _register(appautoscaling, rid, Tags={"team": "a"})
    assert appautoscaling.list_tags_for_resource(ResourceARN=arn)["Tags"] == {"team": "a"}
    # Tags on RegisterScalableTarget apply when the target is created.
    _register(appautoscaling, rid, Tags={"ignored": "x"})
    assert appautoscaling.list_tags_for_resource(ResourceARN=arn)["Tags"] == {"team": "a"}
    appautoscaling.tag_resource(ResourceARN=arn, Tags={"env": "dev", "team": "b"})
    assert appautoscaling.list_tags_for_resource(ResourceARN=arn)["Tags"] == {"team": "b", "env": "dev"}
    appautoscaling.untag_resource(ResourceARN=arn, TagKeys=["team"])
    assert appautoscaling.list_tags_for_resource(ResourceARN=arn)["Tags"] == {"env": "dev"}


def test_tag_operations_on_unknown_arn(appautoscaling):
    arn = "arn:aws:application-autoscaling:us-east-1:000000000000:scalable-target/" + "0" * 36
    for call in (lambda: appautoscaling.list_tags_for_resource(ResourceARN=arn),
                 lambda: appautoscaling.tag_resource(ResourceARN=arn, Tags={"a": "b"}),
                 lambda: appautoscaling.untag_resource(ResourceARN=arn, TagKeys=["a"])):
        with pytest.raises(ClientError) as exc:
            call()
        assert _code(exc) == "ResourceNotFoundException"
        assert exc.value.response["Error"]["Message"]


# ---------------------------------------------------------------------------
# Wire format, isolation, persistence and routing
# ---------------------------------------------------------------------------


def test_errors_use_modeled_message_member():
    with request_scope("000000000000", "us-east-1"):
        status, headers, body = aas.call("DescribeScalableTargets", {})
    assert status == 400
    assert headers["Content-Type"] == "application/x-amz-json-1.1"
    payload = json.loads(body)
    assert payload["__type"] == "ValidationException"
    assert "Message" in payload and "message" not in payload
    with request_scope("000000000000", "us-east-1"):
        status, _, body = aas.call("ListTagsForResource", {"ResourceARN": "arn:aws:x"})
    assert json.loads(body)["ResourceName"] == "arn:aws:x"


def test_non_integer_capacity_is_a_validation_error():
    rid = _resource()
    with request_scope("000000000000", "us-east-1"):
        status, _, body = aas.call("RegisterScalableTarget", {
            "ServiceNamespace": "ecs", "ResourceId": rid, "ScalableDimension": _DIM,
            "MinCapacity": "one", "MaxCapacity": 2})
        assert aas._targets.get(f"ecs|{rid}|{_DIM}") is None
    assert status == 400
    assert json.loads(body)["__type"] == "ValidationException"


def test_unknown_operation(appautoscaling):
    import urllib.error
    import urllib.request
    req = urllib.request.Request(
        ENDPOINT, data=b"{}", method="POST",
        headers={"Content-Type": "application/x-amz-json-1.1",
                 "X-Amz-Target": "AnyScaleFrontendService.NoSuchOperation",
                 "Authorization": "AWS4-HMAC-SHA256 Credential=test/20260101/us-east-1/"
                                  "application-autoscaling/aws4_request, SignedHeaders=host, Signature=x"})
    try:
        urllib.request.urlopen(req, timeout=5)
        raise AssertionError("expected an error")
    except urllib.error.HTTPError as err:
        if err.code == 400:
            assert json.loads(err.read())["__type"] == "UnknownOperationException"
        else:
            # Under AUTH=true the forged signature is refused before dispatch.
            assert err.code == 403


def test_targets_are_region_scoped(appautoscaling):
    rid = _resource()
    _register(appautoscaling, rid)
    west = _other_client(region_name="us-west-2")
    assert west.describe_scalable_targets(ServiceNamespace="ecs", ResourceIds=[rid])["ScalableTargets"] == []
    with pytest.raises(ClientError) as exc:
        west.put_scaling_policy(PolicyName="cpu", ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM,
                                PolicyType="TargetTrackingScaling", TargetTrackingScalingPolicyConfiguration=_CPU)
    assert _code(exc) == "ObjectNotFoundException"


def test_targets_are_account_scoped(appautoscaling, auth_enabled):
    if auth_enabled:
        pytest.skip("account selection by access key id needs AUTH=false")
    rid = _resource()
    _register(appautoscaling, rid)
    other = _other_client(aws_access_key_id="111111111111")
    assert other.describe_scalable_targets(ServiceNamespace="ecs", ResourceIds=[rid])["ScalableTargets"] == []
    arn = _register(other, rid)
    assert ":111111111111:" in arn
    assert ":111111111111:" in _target(other, rid)["RoleARN"]
    other.deregister_scalable_target(ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM)
    assert _target(appautoscaling, rid) is not None


def test_state_round_trip_keeps_every_tenant(tmp_path, monkeypatch):
    monkeypatch.setattr(persistence, "STATE_DIR", str(tmp_path))
    monkeypatch.setattr(persistence, "PERSIST_STATE", True)
    saved = aas.get_state()
    aas.reset()
    try:
        tenants = (("000000000000", "us-east-1"), ("111111111111", "eu-west-1"))
        for account, region in tenants:
            with request_scope(account, region):
                rid = f"service/c-{account}/svc"
                aas.call("RegisterScalableTarget", {"ServiceNamespace": "ecs", "ResourceId": rid,
                                                    "ScalableDimension": _DIM, "MinCapacity": 1,
                                                    "MaxCapacity": 2, "Tags": {"t": account}})
                aas.call("PutScalingPolicy", {"PolicyName": "cpu", "ServiceNamespace": "ecs", "ResourceId": rid,
                                              "ScalableDimension": _DIM, "PolicyType": "TargetTrackingScaling",
                                              "TargetTrackingScalingPolicyConfiguration": _CPU})
                aas.call("PutScheduledAction", {"ScheduledActionName": "n", "ServiceNamespace": "ecs",
                                                "ResourceId": rid, "ScalableDimension": _DIM,
                                                "Schedule": "rate(1 hour)"})
        persistence.save_state("application_autoscaling", aas.get_state())
        aas.reset()
        loaded = persistence.load_state("application_autoscaling")
        assert loaded is not None
        aas.load_persisted_state(loaded)
        for account, region in tenants:
            with request_scope(account, region):
                rid = f"service/c-{account}/svc"
                body = json.loads(aas.call("DescribeScalableTargets", {"ServiceNamespace": "ecs"})[2])
                assert [t["ResourceId"] for t in body["ScalableTargets"]] == [rid]
                arn = body["ScalableTargets"][0]["ScalableTargetARN"]
                assert json.loads(aas.call("ListTagsForResource", {"ResourceARN": arn})[2])["Tags"] == {"t": account}
                policies = json.loads(aas.call("DescribeScalingPolicies", {"ServiceNamespace": "ecs"})[2])
                assert [p["PolicyName"] for p in policies["ScalingPolicies"]] == ["cpu"]
                actions = json.loads(aas.call("DescribeScheduledActions", {"ServiceNamespace": "ecs"})[2])
                assert [a["ScheduledActionName"] for a in actions["ScheduledActions"]] == ["n"]
    finally:
        aas.reset()
        aas.load_persisted_state(saved)


def test_router_detects_application_autoscaling():
    auth = ("AWS4-HMAC-SHA256 Credential=test/20260101/us-east-1/application-autoscaling/aws4_request, "
            "SignedHeaders=host, Signature=x")
    by_target = {"x-amz-target": "AnyScaleFrontendService.DescribeScalableTargets",
                 "content-type": "application/x-amz-json-1.1", "host": "localhost:4566"}
    assert detect_service("POST", "/", by_target, {}) == "application-autoscaling"
    by_scope = {"authorization": auth, "host": "localhost:4566"}
    assert detect_service("POST", "/", by_scope, {}) == "application-autoscaling"
    by_host = {"host": "application-autoscaling.us-east-1.amazonaws.com"}
    assert detect_service("POST", "/", by_host, {}) == "application-autoscaling"


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------


_DENIED = ("AccessDeniedException", "AccessDenied")


@pytest.mark.auth_contract
def test_calls_without_permission(auth_enabled, iam_user):
    client = iam_user().client("application-autoscaling")
    rid = _resource()
    if auth_enabled:
        with pytest.raises(ClientError) as exc:
            _register(client, rid)
        assert _code(exc) in _DENIED
        with pytest.raises(ClientError) as exc:
            client.describe_scalable_targets(ServiceNamespace="ecs")
        assert _code(exc) in _DENIED
    else:
        _register(client, rid)
        assert _target(client, rid)["ResourceId"] == rid
        client.deregister_scalable_target(ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM)


@pytest.mark.auth_contract
def test_calls_with_allow_and_explicit_deny(auth_enabled, iam_user):
    policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": [
            "application-autoscaling:RegisterScalableTarget", "application-autoscaling:DescribeScalableTargets",
            "application-autoscaling:PutScalingPolicy", "application-autoscaling:DeregisterScalableTarget"],
         "Resource": "*"},
        {"Effect": "Deny", "Action": "application-autoscaling:DeregisterScalableTarget", "Resource": "*"},
    ]}
    client = iam_user(policy=policy).client("application-autoscaling")
    rid = _resource()
    _register(client, rid)
    assert _target(client, rid)["ResourceId"] == rid
    client.put_scaling_policy(PolicyName="cpu", ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM,
                              PolicyType="TargetTrackingScaling", TargetTrackingScalingPolicyConfiguration=_CPU)
    if auth_enabled:
        with pytest.raises(ClientError) as exc:
            client.deregister_scalable_target(ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM)
        assert _code(exc) in _DENIED
        # Not in the Allow statement.
        with pytest.raises(ClientError) as exc:
            client.describe_scaling_policies(ServiceNamespace="ecs")
        assert _code(exc) in _DENIED
        assert _target(client, rid) is not None
        make_client("application-autoscaling").deregister_scalable_target(
            ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM)
    else:
        assert client.describe_scaling_policies(ServiceNamespace="ecs", ResourceId=rid)["ScalingPolicies"]
        client.deregister_scalable_target(ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM)
        assert _target(client, rid) is None


# ---------------------------------------------------------------------------
# CloudFormation
# ---------------------------------------------------------------------------


def _wait_stack(cfn, name, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return {"StackStatus": "DELETE_COMPLETE"}
            raise
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        time.sleep(0.3)
    raise TimeoutError(name)


def _cfn_template(rid, max_capacity=3, target_value=50, tags=None, scheduled=None, policy_type=None):
    target_props = {"ServiceNamespace": "ecs", "ScalableDimension": _DIM, "ResourceId": rid,
                    "MinCapacity": 1, "MaxCapacity": max_capacity}
    if tags is not None:
        target_props["Tags"] = tags
    if scheduled is not None:
        target_props["ScheduledActions"] = scheduled
    return {
        "Resources": {
            "Target": {"Type": "AWS::ApplicationAutoScaling::ScalableTarget", "Properties": target_props},
            "Policy": {
                "Type": "AWS::ApplicationAutoScaling::ScalingPolicy",
                "Properties": {
                    "PolicyName": "repro-cpu",
                    "PolicyType": policy_type or "TargetTrackingScaling",
                    "ScalingTargetId": {"Ref": "Target"},
                    "TargetTrackingScalingPolicyConfiguration": {
                        "TargetValue": target_value,
                        "PredefinedMetricSpecification": {
                            "PredefinedMetricType": "ECSServiceAverageCPUUtilization"},
                    },
                },
            },
        },
        "Outputs": {
            "TargetRef": {"Value": {"Ref": "Target"}},
            "PolicyRef": {"Value": {"Ref": "Policy"}},
            "PolicyArn": {"Value": {"Fn::GetAtt": ["Policy", "Arn"]}},
        },
    }


def test_cfn_validate_template(cfn):
    cfn.validate_template(TemplateBody=json.dumps(_cfn_template("service/repro-cluster/repro-service")))


def test_cfn_scalable_target_and_policy_lifecycle(cfn, appautoscaling):
    rid = _resource()
    name = f"aas-{uuid.uuid4().hex[:8]}"
    scheduled = [{"ScheduledActionName": "night", "Schedule": "cron(0 22 * * ? *)",
                  "ScalableTargetAction": {"MinCapacity": 0, "MaxCapacity": 1}}]
    cfn.create_stack(StackName=name, TemplateBody=json.dumps(
        _cfn_template(rid, tags=[{"Key": "team", "Value": "a"}], scheduled=scheduled)))
    stack = _wait_stack(cfn, name)
    assert stack["StackStatus"] == "CREATE_COMPLETE", stack.get("StackStatusReason")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack["Outputs"]}
    assert outputs["TargetRef"] == f"{rid}|{_DIM}|ecs"

    target = _target(appautoscaling, rid)
    assert (target["MinCapacity"], target["MaxCapacity"]) == (1, 3)
    assert appautoscaling.list_tags_for_resource(ResourceARN=target["ScalableTargetARN"])["Tags"] == {"team": "a"}
    policy = appautoscaling.describe_scaling_policies(ServiceNamespace="ecs", ResourceId=rid)["ScalingPolicies"][0]
    assert outputs["PolicyRef"] == outputs["PolicyArn"] == policy["PolicyARN"]
    assert policy["TargetTrackingScalingPolicyConfiguration"]["TargetValue"] == 50
    actions = appautoscaling.describe_scheduled_actions(ServiceNamespace="ecs", ResourceId=rid)["ScheduledActions"]
    assert [a["ScheduledActionName"] for a in actions] == ["night"]

    cfn.update_stack(StackName=name, TemplateBody=json.dumps(
        _cfn_template(rid, max_capacity=8, target_value=60, tags=[{"Key": "env", "Value": "dev"}], scheduled=[])))
    stack = _wait_stack(cfn, name)
    assert stack["StackStatus"] == "UPDATE_COMPLETE", stack.get("StackStatusReason")
    target = _target(appautoscaling, rid)
    assert target["MaxCapacity"] == 8
    assert appautoscaling.list_tags_for_resource(ResourceARN=target["ScalableTargetARN"])["Tags"] == {"env": "dev"}
    policies = appautoscaling.describe_scaling_policies(ServiceNamespace="ecs", ResourceId=rid)["ScalingPolicies"]
    assert [p["PolicyARN"] for p in policies] == [policy["PolicyARN"]]
    assert policies[0]["TargetTrackingScalingPolicyConfiguration"]["TargetValue"] == 60
    assert appautoscaling.describe_scheduled_actions(
        ServiceNamespace="ecs", ResourceId=rid)["ScheduledActions"] == []

    cfn.delete_stack(StackName=name)
    assert _wait_stack(cfn, name)["StackStatus"] == "DELETE_COMPLETE"
    assert _target(appautoscaling, rid) is None
    assert appautoscaling.describe_scaling_policies(ServiceNamespace="ecs", ResourceId=rid)["ScalingPolicies"] == []


def test_cfn_resource_id_change_replaces_target(cfn, appautoscaling):
    old_rid, new_rid = _resource(), _resource()
    name = f"aas-{uuid.uuid4().hex[:8]}"
    cfn.create_stack(StackName=name, TemplateBody=json.dumps(_cfn_template(old_rid)))
    assert _wait_stack(cfn, name)["StackStatus"] == "CREATE_COMPLETE"
    cfn.update_stack(StackName=name, TemplateBody=json.dumps(_cfn_template(new_rid)))
    stack = _wait_stack(cfn, name)
    assert stack["StackStatus"] == "UPDATE_COMPLETE", stack.get("StackStatusReason")
    assert _target(appautoscaling, old_rid) is None
    assert _target(appautoscaling, new_rid) is not None
    assert [p["PolicyName"] for p in appautoscaling.describe_scaling_policies(
        ServiceNamespace="ecs", ResourceId=new_rid)["ScalingPolicies"]] == ["repro-cpu"]
    cfn.delete_stack(StackName=name)
    assert _wait_stack(cfn, name)["StackStatus"] == "DELETE_COMPLETE"
    assert _target(appautoscaling, new_rid) is None


def test_cfn_policy_with_target_id_and_resource_id_fails(cfn, appautoscaling):
    rid = _resource()
    name = f"aas-{uuid.uuid4().hex[:8]}"
    template = _cfn_template(rid)
    template["Resources"]["Policy"]["Properties"].update(
        {"ResourceId": rid, "ScalableDimension": _DIM, "ServiceNamespace": "ecs"})
    cfn.create_stack(StackName=name, TemplateBody=json.dumps(template))
    stack = _wait_stack(cfn, name)
    assert stack["StackStatus"] in ("ROLLBACK_COMPLETE", "CREATE_FAILED")
    assert _target(appautoscaling, rid) is None
    cfn.delete_stack(StackName=name)
    _wait_stack(cfn, name)

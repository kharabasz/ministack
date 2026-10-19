"""Application Auto Scaling: the calls the Terraform aws_appautoscaling_* resources make for ECS services."""

import uuid

import pytest
from botocore.exceptions import ClientError

_DIM = "ecs:service:DesiredCount"


def _resource():
    return f"service/cluster-{uuid.uuid4().hex[:6]}/svc"


def test_appautoscaling_scalable_target_lifecycle(appautoscaling):
    rid = _resource()
    arn = appautoscaling.register_scalable_target(
        ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=6,
        Tags={"team": "platform"})["ScalableTargetARN"]
    target = appautoscaling.describe_scalable_targets(ServiceNamespace="ecs", ResourceIds=[rid])["ScalableTargets"][0]
    assert (target["MinCapacity"], target["MaxCapacity"]) == (1, 6)
    assert target["ScalableTargetARN"] == arn
    assert target["SuspendedState"]["ScheduledScalingSuspended"] is False
    assert appautoscaling.list_tags_for_resource(ResourceARN=arn)["Tags"] == {"team": "platform"}

    # Registering again updates the existing target.
    appautoscaling.register_scalable_target(ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM, MaxCapacity=10)
    assert appautoscaling.describe_scalable_targets(
        ServiceNamespace="ecs", ResourceIds=[rid])["ScalableTargets"][0]["MaxCapacity"] == 10

    appautoscaling.deregister_scalable_target(ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM)
    assert appautoscaling.describe_scalable_targets(ServiceNamespace="ecs", ResourceIds=[rid])["ScalableTargets"] == []
    with pytest.raises(ClientError) as exc:
        appautoscaling.deregister_scalable_target(ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM)
    assert exc.value.response["Error"]["Code"] == "ObjectNotFoundException"


def test_appautoscaling_policies_and_scheduled_actions(appautoscaling):
    rid = _resource()
    with pytest.raises(ClientError) as exc:
        appautoscaling.put_scaling_policy(
            PolicyName="cpu", ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM,
            PolicyType="TargetTrackingScaling",
            TargetTrackingScalingPolicyConfiguration={"TargetValue": 70.0})
    assert exc.value.response["Error"]["Code"] == "ObjectNotFoundException"

    appautoscaling.register_scalable_target(ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM,
                                            MinCapacity=1, MaxCapacity=4)
    config = {"TargetValue": 70.0, "ScaleInCooldown": 60, "ScaleOutCooldown": 60,
              "PredefinedMetricSpecification": {"PredefinedMetricType": "ECSServiceAverageCPUUtilization"}}
    put = appautoscaling.put_scaling_policy(
        PolicyName="cpu", ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM,
        PolicyType="TargetTrackingScaling", TargetTrackingScalingPolicyConfiguration=config)
    assert put["PolicyARN"].endswith(":policyName/cpu")
    assert len(put["Alarms"]) == 2
    policy = appautoscaling.describe_scaling_policies(ServiceNamespace="ecs", ResourceId=rid)["ScalingPolicies"][0]
    assert policy["TargetTrackingScalingPolicyConfiguration"] == config
    assert policy["PolicyType"] == "TargetTrackingScaling"

    appautoscaling.put_scheduled_action(
        ServiceNamespace="ecs", ScheduledActionName="night", ResourceId=rid, ScalableDimension=_DIM,
        Schedule="cron(0 22 * * ? *)", ScalableTargetAction={"MinCapacity": 0, "MaxCapacity": 1})
    action = appautoscaling.describe_scheduled_actions(ServiceNamespace="ecs", ResourceId=rid)["ScheduledActions"][0]
    assert action["Schedule"] == "cron(0 22 * * ? *)"
    assert action["ScalableTargetAction"] == {"MinCapacity": 0, "MaxCapacity": 1}

    appautoscaling.delete_scaling_policy(PolicyName="cpu", ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM)
    assert appautoscaling.describe_scaling_policies(ServiceNamespace="ecs", ResourceId=rid)["ScalingPolicies"] == []
    # Deregistering the target removes its scheduled actions too.
    appautoscaling.deregister_scalable_target(ServiceNamespace="ecs", ResourceId=rid, ScalableDimension=_DIM)
    assert appautoscaling.describe_scheduled_actions(ServiceNamespace="ecs", ResourceId=rid)["ScheduledActions"] == []

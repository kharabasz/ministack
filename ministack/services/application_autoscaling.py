# Copyright (c) 2026 MiniStack Contributors. SPDX-License-Identifier: MIT
# Copies or substantial portions, including AI-assisted ports or rewrites, must retain this notice (see LICENSE).
"""
Application Auto Scaling Emulator (control plane).
JSON 1.1 protocol via X-Amz-Target AnyScaleFrontendService.<Action>, signed as
application-autoscaling.

Supports:
  Scalable targets:  RegisterScalableTarget, DescribeScalableTargets, DeregisterScalableTarget
  Scaling policies:  PutScalingPolicy, DescribeScalingPolicies, DeleteScalingPolicy
  Scheduled actions: PutScheduledAction, DescribeScheduledActions, DeleteScheduledAction
  Tags:              TagResource, UntagResource, ListTagsForResource

Targets, policies and scheduled actions are stored as given; nothing evaluates
metrics or changes capacity.
"""

import copy
import json
import time

from ministack.core.responses import (
    AccountRegionScopedDict,
    error_response_json,
    get_account_id,
    get_region,
    json_response,
    new_uuid,
)

_targets = AccountRegionScopedDict()     # "namespace|resource|dimension" -> scalable target
_policies = AccountRegionScopedDict()    # "namespace|resource|dimension|name" -> scaling policy
_scheduled = AccountRegionScopedDict()   # "namespace|resource|dimension|name" -> scheduled action
_tags = AccountRegionScopedDict()        # scalable target ARN -> {key: value}

_NAMESPACES = ("ecs", "elasticmapreduce", "ec2", "appstream", "dynamodb", "rds", "sagemaker",
               "custom-resource", "comprehend", "lambda", "cassandra", "kafka", "elasticache",
               "neptune", "workspaces")
_POLICY_TYPES = ("StepScaling", "TargetTrackingScaling", "PredictiveScaling")


def reset():
    _targets.clear()
    _policies.clear()
    _scheduled.clear()
    _tags.clear()


def get_state():
    return {
        "targets": copy.deepcopy(_targets),
        "policies": copy.deepcopy(_policies),
        "scheduled": copy.deepcopy(_scheduled),
        "tags": copy.deepcopy(_tags),
    }


def load_persisted_state(data):
    if not data:
        return
    _targets.update(data.get("targets", {}))
    _policies.update(data.get("policies", {}))
    _scheduled.update(data.get("scheduled", {}))
    _tags.update(data.get("tags", {}))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validation(message):
    return error_response_json("ValidationException", message, 400)


def _not_found(message):
    return error_response_json("ObjectNotFoundException", message, 400)


def _target_key(data):
    return f"{data.get('ServiceNamespace')}|{data.get('ResourceId')}|{data.get('ScalableDimension')}"


def _require(data, *names):
    for name in names:
        if not data.get(name):
            return _validation(f"1 validation error detected: Value null at '{name[0].lower() + name[1:]}' "
                               "failed to satisfy constraint: Member must not be null")
    if data.get("ServiceNamespace") and data["ServiceNamespace"] not in _NAMESPACES:
        return _validation(f"Unsupported service namespace: {data['ServiceNamespace']}")
    return None


def _id():
    return new_uuid()


def _arn(kind, ident):
    return f"arn:aws:application-autoscaling:{get_region()}:{get_account_id()}:{kind}/{ident}"


def _matches(item, data, list_key, name_key):
    if item["ServiceNamespace"] != data.get("ServiceNamespace"):
        return False
    if data.get("ResourceId") and item["ResourceId"] != data["ResourceId"]:
        return False
    if data.get("ScalableDimension") and item["ScalableDimension"] != data["ScalableDimension"]:
        return False
    names = data.get(list_key) or []
    return not names or item[name_key] in names


# ---------------------------------------------------------------------------
# Scalable targets
# ---------------------------------------------------------------------------


def _register_scalable_target(data):
    err = _require(data, "ServiceNamespace", "ResourceId", "ScalableDimension")
    if err:
        return err
    key = _target_key(data)
    existing = _targets.get(key)
    if existing is None:
        if data.get("MinCapacity") is None or data.get("MaxCapacity") is None:
            return _validation("MinCapacity and MaxCapacity are required when registering a new scalable target")
        target = {
            "ServiceNamespace": data["ServiceNamespace"],
            "ResourceId": data["ResourceId"],
            "ScalableDimension": data["ScalableDimension"],
            "RoleARN": data.get("RoleARN") or (
                f"arn:aws:iam::{get_account_id()}:role/aws-service-role/"
                f"{data['ServiceNamespace']}.application-autoscaling.amazonaws.com/"
                "AWSServiceRoleForApplicationAutoScaling_ECSService"),
            "CreationTime": time.time(),
            "SuspendedState": {"DynamicScalingInSuspended": False, "DynamicScalingOutSuspended": False,
                               "ScheduledScalingSuspended": False},
            "ScalableTargetARN": _arn("scalable-target", _id().replace("-", "")[:28]),
        }
    else:
        target = existing
    for field in ("MinCapacity", "MaxCapacity"):
        if data.get(field) is not None:
            target[field] = int(data[field])
    if target["MinCapacity"] > target["MaxCapacity"]:
        return _validation("MinCapacity cannot be greater than MaxCapacity")
    if data.get("SuspendedState"):
        target["SuspendedState"].update(data["SuspendedState"])
    _targets[key] = target
    if data.get("Tags"):
        merged = _tags.get(target["ScalableTargetARN"], {})
        merged.update(data["Tags"])
        _tags[target["ScalableTargetARN"]] = merged
    return json_response({"ScalableTargetARN": target["ScalableTargetARN"]})


def _describe_scalable_targets(data):
    if not data.get("ServiceNamespace"):
        return _validation("ServiceNamespace is required")
    ids = data.get("ResourceIds") or []
    items = [t for t in _targets.values()
             if t["ServiceNamespace"] == data["ServiceNamespace"]
             and (not ids or t["ResourceId"] in ids)
             and (not data.get("ScalableDimension") or t["ScalableDimension"] == data["ScalableDimension"])]
    return json_response({"ScalableTargets": items})


def _deregister_scalable_target(data):
    err = _require(data, "ServiceNamespace", "ResourceId", "ScalableDimension")
    if err:
        return err
    key = _target_key(data)
    target = _targets.get(key)
    if not target:
        return _not_found(f"No scalable target registered for service namespace: {data['ServiceNamespace']}, "
                          f"resource ID: {data['ResourceId']}, scalable dimension: {data['ScalableDimension']}")
    # AWS deletes the target's scaling policies and scheduled actions with it.
    for store in (_policies, _scheduled):
        for k in [k for k in store.keys() if k.startswith(key + "|")]:
            store.pop(k, None)
    _targets.pop(key, None)
    _tags.pop(target["ScalableTargetARN"], None)
    return json_response({})


def _target_or_error(data):
    target = _targets.get(_target_key(data))
    if not target:
        return None, _not_found(
            f"No scalable target registered for service namespace: {data.get('ServiceNamespace')}, "
            f"resource ID: {data.get('ResourceId')}, scalable dimension: {data.get('ScalableDimension')}")
    return target, None


# ---------------------------------------------------------------------------
# Scaling policies
# ---------------------------------------------------------------------------


def _put_scaling_policy(data):
    err = _require(data, "PolicyName", "ServiceNamespace", "ResourceId", "ScalableDimension")
    if err:
        return err
    _, err = _target_or_error(data)
    if err:
        return err
    policy_type = data.get("PolicyType", "StepScaling")
    if policy_type not in _POLICY_TYPES:
        return _validation(f"Invalid PolicyType: {policy_type}")
    config_key = {"StepScaling": "StepScalingPolicyConfiguration",
                  "TargetTrackingScaling": "TargetTrackingScalingPolicyConfiguration",
                  "PredictiveScaling": "PredictiveScalingPolicyConfiguration"}[policy_type]
    if not data.get(config_key):
        return _validation(f"{config_key} is required for a {policy_type} policy")
    key = f"{_target_key(data)}|{data['PolicyName']}"
    existing = _policies.get(key)
    resource = data["ResourceId"]
    policy_arn = existing["PolicyARN"] if existing else (
        f"arn:aws:autoscaling:{get_region()}:{get_account_id()}:scalingPolicy:{_id()}:"
        f"resource/{data['ServiceNamespace']}/{resource}:policyName/{data['PolicyName']}")
    alarms = []
    if policy_type == "TargetTrackingScaling":
        # AWS creates a high and a low alarm for each target tracking policy.
        base = f"TargetTracking-{resource}"
        alarms = [{"AlarmName": f"{base}-AlarmHigh-{_id()}",
                   "AlarmARN": f"arn:aws:cloudwatch:{get_region()}:{get_account_id()}:alarm:{base}-AlarmHigh"},
                  {"AlarmName": f"{base}-AlarmLow-{_id()}",
                   "AlarmARN": f"arn:aws:cloudwatch:{get_region()}:{get_account_id()}:alarm:{base}-AlarmLow"}]
        if existing:
            alarms = existing.get("Alarms", alarms)
    policy = {
        "PolicyARN": policy_arn,
        "PolicyName": data["PolicyName"],
        "ServiceNamespace": data["ServiceNamespace"],
        "ResourceId": resource,
        "ScalableDimension": data["ScalableDimension"],
        "PolicyType": policy_type,
        config_key: data[config_key],
        "Alarms": alarms,
        "CreationTime": existing["CreationTime"] if existing else time.time(),
    }
    _policies[key] = policy
    return json_response({"PolicyARN": policy_arn, "Alarms": alarms})


def _describe_scaling_policies(data):
    if not data.get("ServiceNamespace"):
        return _validation("ServiceNamespace is required")
    items = [p for p in _policies.values() if _matches(p, data, "PolicyNames", "PolicyName")]
    return json_response({"ScalingPolicies": items})


def _delete_scaling_policy(data):
    err = _require(data, "PolicyName", "ServiceNamespace", "ResourceId", "ScalableDimension")
    if err:
        return err
    key = f"{_target_key(data)}|{data['PolicyName']}"
    if key not in _policies:
        return _not_found(f"No scaling policy found for service namespace: {data['ServiceNamespace']}, "
                          f"resource ID: {data['ResourceId']}, scalable dimension: {data['ScalableDimension']}, "
                          f"policy name: {data['PolicyName']}")
    _policies.pop(key, None)
    return json_response({})


# ---------------------------------------------------------------------------
# Scheduled actions
# ---------------------------------------------------------------------------


def _put_scheduled_action(data):
    err = _require(data, "ScheduledActionName", "ServiceNamespace", "ResourceId", "ScalableDimension")
    if err:
        return err
    _, err = _target_or_error(data)
    if err:
        return err
    key = f"{_target_key(data)}|{data['ScheduledActionName']}"
    existing = _scheduled.get(key)
    if not existing and not data.get("Schedule"):
        return _validation("Schedule is required when creating a scheduled action")
    action = existing or {
        "ScheduledActionName": data["ScheduledActionName"],
        "ScheduledActionARN": _arn("scheduled-action", _id()),
        "ServiceNamespace": data["ServiceNamespace"],
        "ResourceId": data["ResourceId"],
        "ScalableDimension": data["ScalableDimension"],
        "CreationTime": time.time(),
    }
    for field in ("Schedule", "Timezone", "StartTime", "EndTime", "ScalableTargetAction"):
        if field in data:
            action[field] = data[field]
    _scheduled[key] = action
    return json_response({})


def _describe_scheduled_actions(data):
    if not data.get("ServiceNamespace"):
        return _validation("ServiceNamespace is required")
    items = [a for a in _scheduled.values() if _matches(a, data, "ScheduledActionNames", "ScheduledActionName")]
    return json_response({"ScheduledActions": items})


def _delete_scheduled_action(data):
    err = _require(data, "ScheduledActionName", "ServiceNamespace", "ResourceId", "ScalableDimension")
    if err:
        return err
    key = f"{_target_key(data)}|{data['ScheduledActionName']}"
    if key not in _scheduled:
        return _not_found(f"No scheduled action found for name: {data['ScheduledActionName']}")
    _scheduled.pop(key, None)
    return json_response({})


# ---------------------------------------------------------------------------
# Tags (scalable targets are the taggable resource)
# ---------------------------------------------------------------------------


def _target_arn_exists(arn):
    return any(t["ScalableTargetARN"] == arn for t in _targets.values())


def _tag_resource(data):
    arn = data.get("ResourceARN", "")
    if not _target_arn_exists(arn):
        return error_response_json("ResourceNotFoundException", f"Resource {arn} not found", 400)
    merged = _tags.get(arn, {})
    merged.update(data.get("Tags") or {})
    _tags[arn] = merged
    return json_response({})


def _untag_resource(data):
    arn = data.get("ResourceARN", "")
    if not _target_arn_exists(arn):
        return error_response_json("ResourceNotFoundException", f"Resource {arn} not found", 400)
    existing = _tags.get(arn, {})
    for key in data.get("TagKeys") or []:
        existing.pop(key, None)
    if existing:
        _tags[arn] = existing
    else:
        _tags.pop(arn, None)
    return json_response({})


def _list_tags_for_resource(data):
    arn = data.get("ResourceARN", "")
    if not _target_arn_exists(arn):
        return error_response_json("ResourceNotFoundException", f"Resource {arn} not found", 400)
    return json_response({"Tags": _tags.get(arn, {})})


_HANDLERS = {
    "RegisterScalableTarget": _register_scalable_target,
    "DescribeScalableTargets": _describe_scalable_targets,
    "DeregisterScalableTarget": _deregister_scalable_target,
    "PutScalingPolicy": _put_scaling_policy,
    "DescribeScalingPolicies": _describe_scaling_policies,
    "DeleteScalingPolicy": _delete_scaling_policy,
    "PutScheduledAction": _put_scheduled_action,
    "DescribeScheduledActions": _describe_scheduled_actions,
    "DeleteScheduledAction": _delete_scheduled_action,
    "TagResource": _tag_resource,
    "UntagResource": _untag_resource,
    "ListTagsForResource": _list_tags_for_resource,
}


async def handle_request(method, path, headers, body, query_params):
    target = headers.get("x-amz-target", "")
    action = target.split(".")[-1] if "." in target else ""
    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        return error_response_json("SerializationException", "Invalid JSON", 400)
    handler = _HANDLERS.get(action)
    if not handler:
        return error_response_json("InvalidAction", f"Unknown action: {action}", 400)
    return handler(data)

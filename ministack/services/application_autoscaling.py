# Copyright (c) 2026 MiniStack Contributors. SPDX-License-Identifier: MIT
# Copies or substantial portions, including AI-assisted ports or rewrites, must retain this notice (see LICENSE).
"""
Application Auto Scaling Emulator (control plane, ECS services only).
JSON 1.1 protocol via X-Amz-Target AnyScaleFrontendService.<Action>, signed as
application-autoscaling.

Supports:
  Scalable targets:  RegisterScalableTarget, DescribeScalableTargets, DeregisterScalableTarget
  Scaling policies:  PutScalingPolicy, DescribeScalingPolicies, DeleteScalingPolicy
                     (StepScaling and TargetTrackingScaling)
  Scheduled actions: PutScheduledAction, DescribeScheduledActions, DeleteScheduledAction
  Tags:              TagResource, UntagResource, ListTagsForResource

Only the ``ecs`` namespace (``ecs:service:DesiredCount`` on
``service/<cluster>/<service>``) is accepted for writes. Targets, policies and
scheduled actions are stored as given: nothing evaluates metrics, no CloudWatch
alarms are created for target-tracking policies, and the ECS service's desired
count is never changed. The ECS service named by ResourceId is not required to
exist in MiniStack.
"""

import copy
import json
import logging
import re
import time

from ministack.core.responses import (
    AccountRegionScopedDict,
    error_response_json,
    get_account_id,
    get_region,
    json_response,
    new_uuid,
)

logger = logging.getLogger("application-autoscaling")

_JSON_1_1 = "application/x-amz-json-1.1"

_targets = AccountRegionScopedDict()     # "namespace|resource|dimension" -> scalable target
_policies = AccountRegionScopedDict()    # "namespace|resource|dimension|name" -> scaling policy
_scheduled = AccountRegionScopedDict()   # "namespace|resource|dimension|name" -> scheduled action
_tags = AccountRegionScopedDict()        # scalable target ARN -> {key: value}

# The ServiceNamespace enum from the botocore model; any other value fails the
# model's enum constraint.
_MODEL_NAMESPACES = ("ecs", "elasticmapreduce", "ec2", "appstream", "dynamodb", "rds", "sagemaker",
                     "custom-resource", "comprehend", "lambda", "cassandra", "kafka", "elasticache",
                     "neptune", "workspaces")
# MiniStack choice: only ECS services can be registered.
_SUPPORTED_NAMESPACES = ("ecs",)
_ECS_DIMENSION = "ecs:service:DesiredCount"
_ECS_RESOURCE_RE = re.compile(r"^service/[^/]+/[^/]+$")
# AWS docs (Application Auto Scaling User Guide, service-linked roles): the
# role Application Auto Scaling uses for ECS services when no RoleARN is given.
_ECS_SERVICE_LINKED_ROLE = ("role/aws-service-role/ecs.application-autoscaling.amazonaws.com/"
                            "AWSServiceRoleForApplicationAutoScaling_ECSService")
_POLICY_CONFIG = {
    "StepScaling": "StepScalingPolicyConfiguration",
    "TargetTrackingScaling": "TargetTrackingScalingPolicyConfiguration",
}
_MODEL_POLICY_TYPES = ("StepScaling", "TargetTrackingScaling", "PredictiveScaling")
_SCHEDULED_FIELDS = ("Schedule", "Timezone", "StartTime", "EndTime", "ScalableTargetAction")
_MAX_RESULTS = 50


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


class _Invalid(Exception):
    """A request that fails validation; carries the error response."""

    def __init__(self, response):
        super().__init__()
        self.response = response


def _error(code, message, extra=None):
    # botocore: every modeled exception of this service declares "Message".
    return error_response_json(code, message, 400, extra, message_key="Message", content_type=_JSON_1_1)


def _ok(payload):
    return json_response(payload, content_type=_JSON_1_1)


def _validation(message):
    return _error("ValidationException", message)


def _not_found(message):
    return _error("ObjectNotFoundException", message)


def _null_error(name):
    member = name[0].lower() + name[1:]
    return _validation(f"1 validation error detected: Value null at '{member}' "
                       "failed to satisfy constraint: Member must not be null")


def _check_namespace(data):
    namespace = data.get("ServiceNamespace")
    if not namespace:
        raise _Invalid(_null_error("ServiceNamespace"))
    if namespace not in _MODEL_NAMESPACES:
        raise _Invalid(_validation(
            f"1 validation error detected: Value '{namespace}' at 'serviceNamespace' failed to satisfy "
            f"constraint: Member must satisfy enum value set: [{', '.join(_MODEL_NAMESPACES)}]"))
    return namespace


def _check_target_identity(data, *extra_required):
    """Validate the namespace / resource / dimension triple of a write call."""
    namespace = _check_namespace(data)
    for name in ("ResourceId", "ScalableDimension") + extra_required:
        if not data.get(name):
            raise _Invalid(_null_error(name))
    if namespace not in _SUPPORTED_NAMESPACES:
        raise _Invalid(_validation(
            f"MiniStack supports only the ecs service namespace for Application Auto Scaling, not {namespace}"))
    if data["ScalableDimension"] != _ECS_DIMENSION or not _ECS_RESOURCE_RE.match(data["ResourceId"]):
        raise _Invalid(_validation("Unsupported service namespace, resource type or scalable dimension"))


def _capacity(data, name):
    value = data.get(name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise _Invalid(_validation(f"{name} must be an integer"))
    if value < 0:
        raise _Invalid(_validation(f"{name} must be greater than or equal to 0"))
    return value


def _target_key(data):
    return f"{data['ServiceNamespace']}|{data['ResourceId']}|{data['ScalableDimension']}"


def _public(record):
    return {k: v for k, v in record.items() if not k.startswith("_")}


def _paginate(items, data, key):
    """Offset-token pagination shared by the three Describe operations."""
    max_results = data.get("MaxResults")
    if max_results is None:
        max_results = _MAX_RESULTS
    elif isinstance(max_results, bool) or not isinstance(max_results, int) or not 1 <= max_results <= _MAX_RESULTS:
        raise _Invalid(_validation(f"MaxResults must be between 1 and {_MAX_RESULTS}"))
    token = data.get("NextToken")
    start = 0
    if token is not None:
        if not isinstance(token, str) or not token.isdigit() or int(token) > len(items):
            raise _Invalid(_error("InvalidNextTokenException", "Invalid token"))
        start = int(token)
    page = items[start:start + max_results]
    result = {key: [_public(i) for i in page]}
    if start + max_results < len(items):
        result["NextToken"] = str(start + max_results)
    return _ok(result)


def _matches(item, data, list_key, name_key):
    if item["ServiceNamespace"] != data["ServiceNamespace"]:
        return False
    if data.get("ResourceId") and item["ResourceId"] != data["ResourceId"]:
        return False
    if data.get("ScalableDimension") and item["ScalableDimension"] != data["ScalableDimension"]:
        return False
    names = data.get(list_key) or []
    return not names or item[name_key] in names


def _target_missing(data):
    return _not_found(
        f"No scalable target registered for service namespace: {data['ServiceNamespace']}, "
        f"resource ID: {data['ResourceId']}, scalable dimension: {data['ScalableDimension']}")


def _child_arn(target, kind, name_kind, name):
    # AWS docs (API reference and CLI examples): policy and scheduled-action
    # ARNs share one id per scalable target and end in the resource and name.
    return (f"arn:aws:autoscaling:{get_region()}:{get_account_id()}:{kind}:{target['_ChildId']}:"
            f"resource/{target['ServiceNamespace']}/{target['ResourceId']}:{name_kind}/{name}")


# ---------------------------------------------------------------------------
# Scalable targets
# ---------------------------------------------------------------------------


def _register_scalable_target(data):
    _check_target_identity(data)
    min_capacity = _capacity(data, "MinCapacity")
    max_capacity = _capacity(data, "MaxCapacity")
    key = _target_key(data)
    existing = _targets.get(key)
    if existing is None:
        if min_capacity is None or max_capacity is None:
            return _validation("MinCapacity and MaxCapacity are required to register a new scalable target")
        target = {
            "ServiceNamespace": data["ServiceNamespace"],
            "ResourceId": data["ResourceId"],
            "ScalableDimension": data["ScalableDimension"],
            "RoleARN": f"arn:aws:iam::{get_account_id()}:{_ECS_SERVICE_LINKED_ROLE}",
            "CreationTime": time.time(),
            "SuspendedState": {"DynamicScalingInSuspended": False, "DynamicScalingOutSuspended": False,
                               "ScheduledScalingSuspended": False},
            # AWS docs example: scalable-target/ followed by 36 hex characters.
            "ScalableTargetARN": (f"arn:aws:application-autoscaling:{get_region()}:{get_account_id()}:"
                                  f"scalable-target/{(new_uuid() + new_uuid()).replace('-', '')[:36]}"),
            "_ChildId": new_uuid(),
        }
    else:
        # Work on a copy so a rejected update leaves the stored target intact.
        target = copy.deepcopy(existing)
    if min_capacity is not None:
        target["MinCapacity"] = min_capacity
    if max_capacity is not None:
        target["MaxCapacity"] = max_capacity
    if target["MinCapacity"] > target["MaxCapacity"]:
        return _validation("Minimum capacity cannot be greater than maximum capacity")
    if data.get("RoleARN"):
        target["RoleARN"] = data["RoleARN"]
    suspended = data.get("SuspendedState")
    if suspended:
        if not isinstance(suspended, dict) or not all(isinstance(v, bool) for v in suspended.values()):
            return _validation("SuspendedState members must be booleans")
        target["SuspendedState"].update(suspended)
    _targets[key] = target
    # Model docs: Tags apply when the target is created; TagResource tags an
    # existing one.
    if existing is None and data.get("Tags"):
        _tags[target["ScalableTargetARN"]] = dict(data["Tags"])
    logger.debug("Registered scalable target %s", key)
    return _ok({"ScalableTargetARN": target["ScalableTargetARN"]})


def _describe_scalable_targets(data):
    namespace = _check_namespace(data)
    ids = data.get("ResourceIds") or []
    items = [t for t in _targets.values()
             if t["ServiceNamespace"] == namespace
             and (not ids or t["ResourceId"] in ids)
             and (not data.get("ScalableDimension") or t["ScalableDimension"] == data["ScalableDimension"])]
    return _paginate(items, data, "ScalableTargets")


def _deregister_scalable_target(data):
    _check_target_identity(data)
    key = _target_key(data)
    target = _targets.get(key)
    if not target:
        return _target_missing(data)
    # AWS API reference: deregistering a scalable target deletes the scaling
    # policies and scheduled actions associated with it.
    for store in (_policies, _scheduled):
        for k in [k for k in store.keys() if k.startswith(key + "|")]:
            store.pop(k, None)
    _targets.pop(key, None)
    _tags.pop(target["ScalableTargetARN"], None)
    return _ok({})


# ---------------------------------------------------------------------------
# Scaling policies
# ---------------------------------------------------------------------------


def _put_scaling_policy(data):
    _check_target_identity(data, "PolicyName")
    target = _targets.get(_target_key(data))
    if not target:
        return _target_missing(data)
    key = f"{_target_key(data)}|{data['PolicyName']}"
    existing = _policies.get(key)
    # Model docs: PolicyType is required when creating a policy; an update
    # that omits it keeps the policy's type.
    policy_type = data.get("PolicyType") or (existing or {}).get("PolicyType")
    if not policy_type:
        return _validation("PolicyType is required when creating a scaling policy")
    if policy_type not in _MODEL_POLICY_TYPES:
        return _validation(
            f"1 validation error detected: Value '{policy_type}' at 'policyType' failed to satisfy constraint: "
            f"Member must satisfy enum value set: [{', '.join(_MODEL_POLICY_TYPES)}]")
    if policy_type not in _POLICY_CONFIG:
        return _validation(f"MiniStack does not support {policy_type} policies")
    config_key = _POLICY_CONFIG[policy_type]
    config = data.get(config_key)
    if not isinstance(config, dict) or not config:
        return _validation(f"{config_key} is required for a {policy_type} policy")
    if policy_type == "TargetTrackingScaling" and not isinstance(config.get("TargetValue"), (int, float)):
        return _null_error("TargetValue")
    policy = {
        "PolicyARN": existing["PolicyARN"] if existing else _child_arn(
            target, "scalingPolicy", "policyName", data["PolicyName"]),
        "PolicyName": data["PolicyName"],
        "ServiceNamespace": data["ServiceNamespace"],
        "ResourceId": data["ResourceId"],
        "ScalableDimension": data["ScalableDimension"],
        "PolicyType": policy_type,
        config_key: config,
        "CreationTime": existing["CreationTime"] if existing else time.time(),
    }
    _policies[key] = policy
    return _ok({"PolicyARN": policy["PolicyARN"]})


def _describe_scaling_policies(data):
    _check_namespace(data)
    items = [p for p in _policies.values() if _matches(p, data, "PolicyNames", "PolicyName")]
    return _paginate(items, data, "ScalingPolicies")


def _delete_scaling_policy(data):
    _check_target_identity(data, "PolicyName")
    key = f"{_target_key(data)}|{data['PolicyName']}"
    if key not in _policies:
        return _not_found(f"No scaling policy found for service namespace: {data['ServiceNamespace']}, "
                          f"resource ID: {data['ResourceId']}, scalable dimension: {data['ScalableDimension']}, "
                          f"policy name: {data['PolicyName']}")
    _policies.pop(key, None)
    return _ok({})


# ---------------------------------------------------------------------------
# Scheduled actions
# ---------------------------------------------------------------------------


def _put_scheduled_action(data):
    _check_target_identity(data, "ScheduledActionName")
    target = _targets.get(_target_key(data))
    if not target:
        return _target_missing(data)
    key = f"{_target_key(data)}|{data['ScheduledActionName']}"
    existing = _scheduled.get(key)
    if not existing and not data.get("Schedule"):
        return _validation("Schedule is required when creating a scheduled action")
    action_target = data.get("ScalableTargetAction") or {}
    if not isinstance(action_target, dict):
        return _validation("ScalableTargetAction must be an object")
    for name in ("MinCapacity", "MaxCapacity"):
        _capacity(action_target, name)
    if (action_target.get("MinCapacity") is not None and action_target.get("MaxCapacity") is not None
            and action_target["MinCapacity"] > action_target["MaxCapacity"]):
        return _validation("Minimum capacity cannot be greater than maximum capacity")
    action = copy.deepcopy(existing) if existing else {
        "ScheduledActionName": data["ScheduledActionName"],
        "ScheduledActionARN": _child_arn(target, "scheduledAction", "scheduledActionName",
                                         data["ScheduledActionName"]),
        "ServiceNamespace": data["ServiceNamespace"],
        "ResourceId": data["ResourceId"],
        "ScalableDimension": data["ScalableDimension"],
        "CreationTime": time.time(),
    }
    for field in _SCHEDULED_FIELDS:
        if field in data:
            action[field] = data[field]
    _scheduled[key] = action
    return _ok({})


def _describe_scheduled_actions(data):
    _check_namespace(data)
    items = [a for a in _scheduled.values() if _matches(a, data, "ScheduledActionNames", "ScheduledActionName")]
    return _paginate(items, data, "ScheduledActions")


def _delete_scheduled_action(data):
    _check_target_identity(data, "ScheduledActionName")
    key = f"{_target_key(data)}|{data['ScheduledActionName']}"
    if key not in _scheduled:
        return _not_found(f"No scheduled action found for name: {data['ScheduledActionName']}")
    _scheduled.pop(key, None)
    return _ok({})


# ---------------------------------------------------------------------------
# Tags (scalable targets are the taggable resource)
# ---------------------------------------------------------------------------


def _tagged_target_arn(data):
    arn = data.get("ResourceARN")
    if not arn:
        raise _Invalid(_null_error("ResourceARN"))
    if not any(t["ScalableTargetARN"] == arn for t in _targets.values()):
        raise _Invalid(_error("ResourceNotFoundException", f"Resource {arn} not found",
                              extra={"ResourceName": arn}))
    return arn


def _tag_resource(data):
    arn = _tagged_target_arn(data)
    if not data.get("Tags"):
        return _null_error("Tags")
    merged = dict(_tags.get(arn, {}))
    merged.update(data["Tags"])
    _tags[arn] = merged
    return _ok({})


def _untag_resource(data):
    arn = _tagged_target_arn(data)
    if data.get("TagKeys") is None:
        return _null_error("TagKeys")
    remaining = {k: v for k, v in _tags.get(arn, {}).items() if k not in data["TagKeys"]}
    if remaining:
        _tags[arn] = remaining
    else:
        _tags.pop(arn, None)
    return _ok({})


def _list_tags_for_resource(data):
    arn = _tagged_target_arn(data)
    return _ok({"Tags": dict(_tags.get(arn, {}))})


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


def call(action, data):
    """Run one operation in-process (used by the CloudFormation provisioners)."""
    try:
        return _HANDLERS[action](data)
    except _Invalid as exc:
        return exc.response


async def handle_request(method, path, headers, body, query_params):
    target = headers.get("x-amz-target", "")
    action = target.split(".")[-1] if "." in target else ""
    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        return _error("SerializationException", "Invalid JSON")
    if not isinstance(data, dict):
        return _error("SerializationException", "Request body must be a JSON object")
    if action not in _HANDLERS:
        return _error("UnknownOperationException", f"Unknown operation: {action}")
    return call(action, data)

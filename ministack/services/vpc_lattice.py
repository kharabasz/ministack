# Copyright (c) 2026 MiniStack Contributors. SPDX-License-Identifier: MIT
# Copies or substantial portions, including AI-assisted ports or rewrites, must retain this notice (see LICENSE).
"""
Amazon VPC Lattice Service Emulator (control plane).
REST/JSON protocol — /servicenetworks, /servicenetworkvpcassociations,
/authpolicy, /accesslogsubscriptions and /tags paths, signed as vpc-lattice.

Supports:
  Service networks:  CreateServiceNetwork, GetServiceNetwork, UpdateServiceNetwork,
                     DeleteServiceNetwork, ListServiceNetworks
  VPC associations:  CreateServiceNetworkVpcAssociation, GetServiceNetworkVpcAssociation,
                     UpdateServiceNetworkVpcAssociation, DeleteServiceNetworkVpcAssociation,
                     ListServiceNetworkVpcAssociations
  Auth policies:     PutAuthPolicy, GetAuthPolicy, DeleteAuthPolicy (service networks)
  Access logs:       CreateAccessLogSubscription, GetAccessLogSubscription,
                     UpdateAccessLogSubscription, DeleteAccessLogSubscription,
                     ListAccessLogSubscriptions (service networks)
  Tags:              TagResource, UntagResource, ListTagsForResource

Not emulated: services, target groups, listeners, rules, resource
configurations, and any request routing. VPC associations are ACTIVE on
create and gone after delete.
"""

import copy
import json
import logging
import random
import re
from datetime import datetime, timezone
from urllib.parse import unquote

from ministack.core.responses import (
    AccountRegionScopedDict,
    get_account_id,
    get_region,
)

logger = logging.getLogger("vpc-lattice")

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

_service_networks = AccountRegionScopedDict()   # sn_id -> service network record
_vpc_associations = AccountRegionScopedDict()   # snva_id -> VPC association record
_auth_policies = AccountRegionScopedDict()      # resource ARN -> auth policy record
_access_log_subscriptions = AccountRegionScopedDict()  # als_id -> subscription record
_tags = AccountRegionScopedDict()               # resource ARN -> {key: value}


def reset():
    _service_networks.clear()
    _vpc_associations.clear()
    _auth_policies.clear()
    _access_log_subscriptions.clear()
    _tags.clear()


def get_state():
    return {
        "service_networks": copy.deepcopy(_service_networks),
        "vpc_associations": copy.deepcopy(_vpc_associations),
        "auth_policies": copy.deepcopy(_auth_policies),
        "access_log_subscriptions": copy.deepcopy(_access_log_subscriptions),
        "tags": copy.deepcopy(_tags),
    }


def load_persisted_state(data):
    if not data:
        return
    _service_networks.update(data.get("service_networks", {}))
    _vpc_associations.update(data.get("vpc_associations", {}))
    _auth_policies.update(data.get("auth_policies", {}))
    _access_log_subscriptions.update(data.get("access_log_subscriptions", {}))
    _tags.update(data.get("tags", {}))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_AUTH_TYPES = ("NONE", "AWS_IAM")
_LOG_TYPES = ("SERVICE", "RESOURCE")
_NAME_RE = re.compile(r"^(?!servicenetwork-)(?!-)(?![a-z0-9-]*--)[a-z0-9-]{3,63}(?<!-)$")


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _new_id(prefix):
    return f"{prefix}-" + "".join(random.choices("0123456789abcdef", k=17))


def _arn(resource_type, resource_id):
    return f"arn:aws:vpc-lattice:{get_region()}:{get_account_id()}:{resource_type}/{resource_id}"


def _json(status, body):
    return status, {"Content-Type": "application/json"}, json.dumps(body).encode()


def _error(status, code, message, **fields):
    body = {"message": message, **fields}
    return status, {"Content-Type": "application/json", "x-amzn-errortype": code}, json.dumps(body).encode()


def _not_found(resource_type, resource_id):
    return _error(404, "ResourceNotFoundException",
                  f"{resource_type} not found: {resource_id}",
                  resourceId=resource_id, resourceType=resource_type)


def _conflict(resource_type, resource_id, message):
    return _error(409, "ConflictException", message,
                  resourceId=resource_id, resourceType=resource_type)


def _validation(message, field=None):
    extra = {"reason": "fieldValidationFailed" if field else "other"}
    if field:
        extra["fieldList"] = [{"name": field, "message": message}]
    return _error(400, "ValidationException", message, **extra)


def _id_from_identifier(identifier):
    """Identifiers are an ID or an ARN; ARNs end in /<id>."""
    return identifier.rsplit("/", 1)[-1] if identifier.startswith("arn:") else identifier


def _find_service_network(identifier):
    sn_id = _id_from_identifier(identifier)
    sn = _service_networks.get(sn_id)
    if sn:
        return sn
    # GetServiceNetwork also accepts the network's name.
    for candidate in _service_networks.values():
        if candidate["name"] == identifier:
            return candidate
    return None


def _set_tags(arn, tags):
    if tags:
        existing = _tags.get(arn, {})
        existing.update(tags)
        _tags[arn] = existing


def _drop_resource(arn):
    _tags.pop(arn, None)
    _auth_policies.pop(arn, None)


# ---------------------------------------------------------------------------
# Service networks
# ---------------------------------------------------------------------------


def _sn_vpc_count(sn_id):
    return sum(1 for a in _vpc_associations.values() if a["serviceNetworkId"] == sn_id)


def _create_service_network(body):
    name = body.get("name")
    if not name:
        return _validation("name is required", "name")
    if not _NAME_RE.match(name):
        return _validation(
            "name must be 3-63 lowercase letters, numbers or hyphens, must not start or end "
            "with a hyphen, contain consecutive hyphens or start with servicenetwork-", "name")
    auth_type = body.get("authType", "NONE")
    if auth_type not in _AUTH_TYPES:
        return _validation(f"Invalid authType: {auth_type}", "authType")
    for existing in _service_networks.values():
        if existing["name"] == name:
            return _conflict("SERVICE_NETWORK", existing["id"],
                             f"Service network with name {name} already exists")
    sn_id = _new_id("sn")
    now = _now()
    record = {
        "id": sn_id,
        "name": name,
        "arn": _arn("servicenetwork", sn_id),
        "authType": auth_type,
        "sharingConfig": {"enabled": bool((body.get("sharingConfig") or {}).get("enabled", False))},
        "createdAt": now,
        "lastUpdatedAt": now,
    }
    _service_networks[sn_id] = record
    _set_tags(record["arn"], body.get("tags"))
    return _json(201, {k: record[k] for k in ("id", "name", "arn", "authType", "sharingConfig")})


def _sn_view(sn):
    return {
        **sn,
        "numberOfAssociatedVPCs": _sn_vpc_count(sn["id"]),
        "numberOfAssociatedServices": 0,
    }


def _get_service_network(identifier):
    sn = _find_service_network(identifier)
    if not sn:
        return _not_found("SERVICE_NETWORK", identifier)
    return _json(200, _sn_view(sn))


def _update_service_network(identifier, body):
    sn = _find_service_network(identifier)
    if not sn:
        return _not_found("SERVICE_NETWORK", identifier)
    auth_type = body.get("authType")
    if auth_type not in _AUTH_TYPES:
        return _validation(f"Invalid authType: {auth_type}", "authType")
    sn["authType"] = auth_type
    sn["lastUpdatedAt"] = _now()
    return _json(200, {k: sn[k] for k in ("id", "name", "arn", "authType")})


def _delete_service_network(identifier):
    sn = _find_service_network(identifier)
    if not sn:
        return _not_found("SERVICE_NETWORK", identifier)
    if _sn_vpc_count(sn["id"]):
        return _conflict("SERVICE_NETWORK", sn["id"],
                         "Service network has VPC associations; delete them first")
    for sub_id, sub in list(_access_log_subscriptions.items()):
        if sub["resourceId"] == sn["id"]:
            _tags.pop(sub["arn"], None)
            _access_log_subscriptions.pop(sub_id, None)
    _service_networks.pop(sn["id"], None)
    _drop_resource(sn["arn"])
    return 204, {}, b""


def _list_service_networks(query):
    items = [
        {k: v for k, v in _sn_view(sn).items() if k not in ("authType", "sharingConfig")}
        | {"numberOfAssociatedResourceConfigurations": 0}
        for sn in _service_networks.values()
    ]
    return _json(200, {"items": items})


# ---------------------------------------------------------------------------
# VPC associations
# ---------------------------------------------------------------------------


def _association_view(assoc):
    sn = _service_networks.get(assoc["serviceNetworkId"]) or {}
    return {
        **assoc,
        "serviceNetworkName": sn.get("name", ""),
        "serviceNetworkArn": sn.get("arn", ""),
    }


def _create_vpc_association(body):
    sn_identifier = body.get("serviceNetworkIdentifier")
    vpc_id = body.get("vpcIdentifier")
    if not sn_identifier:
        return _validation("serviceNetworkIdentifier is required", "serviceNetworkIdentifier")
    if not vpc_id:
        return _validation("vpcIdentifier is required", "vpcIdentifier")
    sn = _find_service_network(sn_identifier)
    if not sn:
        return _not_found("SERVICE_NETWORK", sn_identifier)
    for existing in _vpc_associations.values():
        if existing["serviceNetworkId"] == sn["id"] and existing["vpcId"] == vpc_id:
            return _conflict("SERVICE_NETWORK_VPC_ASSOCIATION", existing["id"],
                             f"VPC {vpc_id} is already associated with service network {sn['id']}")
    assoc_id = _new_id("snva")
    now = _now()
    record = {
        "id": assoc_id,
        "arn": _arn("servicenetworkvpcassociation", assoc_id),
        "status": "ACTIVE",
        "createdBy": get_account_id(),
        "createdAt": now,
        "lastUpdatedAt": now,
        "serviceNetworkId": sn["id"],
        "vpcId": vpc_id,
        "securityGroupIds": list(body.get("securityGroupIds") or []),
        "privateDnsEnabled": bool(body.get("privateDnsEnabled", False)),
    }
    if body.get("dnsOptions"):
        record["dnsOptions"] = body["dnsOptions"]
    _vpc_associations[assoc_id] = record
    _set_tags(record["arn"], body.get("tags"))
    out_keys = ("id", "status", "arn", "createdBy", "securityGroupIds", "privateDnsEnabled", "dnsOptions")
    return _json(200, {k: record[k] for k in out_keys if k in record})


def _find_association(identifier):
    return _vpc_associations.get(_id_from_identifier(identifier))


def _get_vpc_association(identifier):
    assoc = _find_association(identifier)
    if not assoc:
        return _not_found("SERVICE_NETWORK_VPC_ASSOCIATION", identifier)
    return _json(200, _association_view(assoc))


def _update_vpc_association(identifier, body):
    assoc = _find_association(identifier)
    if not assoc:
        return _not_found("SERVICE_NETWORK_VPC_ASSOCIATION", identifier)
    if "securityGroupIds" in body:
        assoc["securityGroupIds"] = list(body["securityGroupIds"] or [])
    if "privateDnsEnabled" in body:
        assoc["privateDnsEnabled"] = bool(body["privateDnsEnabled"])
    if body.get("dnsOptions"):
        assoc["dnsOptions"] = body["dnsOptions"]
    assoc["lastUpdatedAt"] = _now()
    out_keys = ("id", "arn", "status", "createdBy", "securityGroupIds", "privateDnsEnabled", "dnsOptions")
    return _json(200, {k: assoc[k] for k in out_keys if k in assoc})


def _delete_vpc_association(identifier):
    assoc = _find_association(identifier)
    if not assoc:
        return _not_found("SERVICE_NETWORK_VPC_ASSOCIATION", identifier)
    _vpc_associations.pop(assoc["id"], None)
    _drop_resource(assoc["arn"])
    return _json(200, {"id": assoc["id"], "arn": assoc["arn"], "status": "DELETE_IN_PROGRESS"})


def _list_vpc_associations(query):
    sn_identifier = query.get("serviceNetworkIdentifier")
    vpc_id = query.get("vpcIdentifier")
    if not sn_identifier and not vpc_id:
        return _validation("Either serviceNetworkIdentifier or vpcIdentifier is required")
    sn_id = None
    if sn_identifier:
        sn = _find_service_network(sn_identifier)
        if not sn:
            return _not_found("SERVICE_NETWORK", sn_identifier)
        sn_id = sn["id"]
    summary_keys = ("id", "arn", "status", "createdBy", "createdAt", "serviceNetworkId",
                    "serviceNetworkName", "serviceNetworkArn", "privateDnsEnabled",
                    "dnsOptions", "vpcId", "lastUpdatedAt")
    items = [
        {k: v for k, v in _association_view(a).items() if k in summary_keys}
        for a in _vpc_associations.values()
        if (sn_id is None or a["serviceNetworkId"] == sn_id)
        and (not vpc_id or a["vpcId"] == vpc_id)
    ]
    return _json(200, {"items": items})


# ---------------------------------------------------------------------------
# Auth policies and access log subscriptions (service networks only)
# ---------------------------------------------------------------------------


def _resource_for(identifier):
    """Resolve an auth-policy / access-log resource identifier to a service network."""
    return _find_service_network(identifier)


def _put_auth_policy(identifier, body):
    sn = _resource_for(identifier)
    if not sn:
        return _not_found("SERVICE_NETWORK", identifier)
    policy = body.get("policy")
    if not policy:
        return _validation("policy is required", "policy")
    try:
        json.loads(policy)
    except (TypeError, ValueError):
        return _validation("policy must be a JSON policy document", "policy")
    now = _now()
    existing = _auth_policies.get(sn["arn"])
    _auth_policies[sn["arn"]] = {
        "policy": policy,
        "createdAt": existing["createdAt"] if existing else now,
        "lastUpdatedAt": now,
    }
    return _json(200, {"policy": policy, "state": _auth_policy_state(sn)})


def _auth_policy_state(sn):
    # A policy only takes effect when the network's auth type is AWS_IAM.
    return "Active" if sn["authType"] == "AWS_IAM" else "Inactive"


def _get_auth_policy(identifier):
    sn = _resource_for(identifier)
    if not sn:
        return _not_found("SERVICE_NETWORK", identifier)
    record = _auth_policies.get(sn["arn"])
    if not record:
        return _not_found("AUTH_POLICY", identifier)
    return _json(200, {**record, "state": _auth_policy_state(sn)})


def _delete_auth_policy(identifier):
    sn = _resource_for(identifier)
    if not sn:
        return _not_found("SERVICE_NETWORK", identifier)
    _auth_policies.pop(sn["arn"], None)
    return 204, {}, b""


def _subscription_out(sub):
    return {k: sub[k] for k in ("id", "arn", "resourceId", "resourceArn",
                                "serviceNetworkLogType", "destinationArn") if k in sub}


def _create_access_log_subscription(body):
    identifier = body.get("resourceIdentifier")
    destination = body.get("destinationArn")
    if not identifier:
        return _validation("resourceIdentifier is required", "resourceIdentifier")
    if not destination:
        return _validation("destinationArn is required", "destinationArn")
    if not re.match(r"^arn:aws[a-z-]*:(s3|logs|firehose):", destination):
        return _validation("destinationArn must be an S3 bucket, CloudWatch Logs log group or "
                           "Firehose delivery stream ARN", "destinationArn")
    sn = _resource_for(identifier)
    if not sn:
        return _not_found("SERVICE_NETWORK", identifier)
    log_type = body.get("serviceNetworkLogType", "SERVICE")
    if log_type not in _LOG_TYPES:
        return _validation(f"Invalid serviceNetworkLogType: {log_type}", "serviceNetworkLogType")
    dest_service = destination.split(":")[2]
    for existing in _access_log_subscriptions.values():
        if (existing["resourceId"] == sn["id"]
                and existing["destinationArn"].split(":")[2] == dest_service
                and existing.get("serviceNetworkLogType") == log_type):
            return _conflict("ACCESS_LOG_SUBSCRIPTION", existing["id"],
                             f"Service network {sn['id']} already has a {dest_service} access log subscription")
    sub_id = _new_id("als")
    now = _now()
    record = {
        "id": sub_id,
        "arn": _arn("accesslogsubscription", sub_id),
        "resourceId": sn["id"],
        "resourceArn": sn["arn"],
        "serviceNetworkLogType": log_type,
        "destinationArn": destination,
        "createdAt": now,
        "lastUpdatedAt": now,
    }
    _access_log_subscriptions[sub_id] = record
    _set_tags(record["arn"], body.get("tags"))
    return _json(201, _subscription_out(record))


def _find_subscription(identifier):
    return _access_log_subscriptions.get(_id_from_identifier(identifier))


def _get_access_log_subscription(identifier):
    sub = _find_subscription(identifier)
    if not sub:
        return _not_found("ACCESS_LOG_SUBSCRIPTION", identifier)
    return _json(200, sub)


def _update_access_log_subscription(identifier, body):
    sub = _find_subscription(identifier)
    if not sub:
        return _not_found("ACCESS_LOG_SUBSCRIPTION", identifier)
    destination = body.get("destinationArn")
    if not destination:
        return _validation("destinationArn is required", "destinationArn")
    if destination.split(":")[2:3] != sub["destinationArn"].split(":")[2:3]:
        return _validation("destinationArn must stay the same destination type", "destinationArn")
    sub["destinationArn"] = destination
    sub["lastUpdatedAt"] = _now()
    return _json(200, _subscription_out(sub))


def _delete_access_log_subscription(identifier):
    sub = _find_subscription(identifier)
    if not sub:
        return _not_found("ACCESS_LOG_SUBSCRIPTION", identifier)
    _access_log_subscriptions.pop(sub["id"], None)
    _tags.pop(sub["arn"], None)
    return 204, {}, b""


def _list_access_log_subscriptions(query):
    identifier = query.get("resourceIdentifier")
    if not identifier:
        return _validation("resourceIdentifier is required", "resourceIdentifier")
    sn = _resource_for(identifier)
    if not sn:
        return _not_found("SERVICE_NETWORK", identifier)
    items = [s for s in _access_log_subscriptions.values() if s["resourceId"] == sn["id"]]
    return _json(200, {"items": items})


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------


def _resource_exists(arn):
    resource_id = _id_from_identifier(arn)
    for store in (_service_networks, _vpc_associations, _access_log_subscriptions):
        record = store.get(resource_id)
        if record and record["arn"] == arn:
            return True
    return False


def _tag_resource(arn, body):
    if not _resource_exists(arn):
        return _not_found("RESOURCE", arn)
    tags = body.get("tags")
    if not tags:
        return _validation("tags is required", "tags")
    _set_tags(arn, tags)
    return _json(200, {})


def _untag_resource(arn, keys):
    if not _resource_exists(arn):
        return _not_found("RESOURCE", arn)
    existing = _tags.get(arn, {})
    for key in keys:
        existing.pop(key, None)
    if existing:
        _tags[arn] = existing
    else:
        _tags.pop(arn, None)
    return _json(200, {})


def _list_tags(arn):
    if not _resource_exists(arn):
        return _not_found("RESOURCE", arn)
    return _json(200, {"tags": _tags.get(arn, {})})


# ---------------------------------------------------------------------------
# Request router
# ---------------------------------------------------------------------------

# Identifiers may be ARNs, which contain "/".
_SN_PATH = re.compile(r"^/servicenetworks/(.+)$")
_SNVA_PATH = re.compile(r"^/servicenetworkvpcassociations/(.+)$")
_AUTH_PATH = re.compile(r"^/authpolicy/(.+)$")
_ALS_PATH = re.compile(r"^/accesslogsubscriptions/(.+)$")


async def handle_request(method, path, headers, body_bytes, query_params):
    try:
        body = json.loads(body_bytes) if body_bytes else {}
    except json.JSONDecodeError:
        return _validation("Request body is not valid JSON")
    query = {k: (v[0] if isinstance(v, list) and v else v) for k, v in query_params.items()}

    if path == "/servicenetworks":
        if method == "POST":
            return _create_service_network(body)
        if method == "GET":
            return _list_service_networks(query)
    m = _SN_PATH.match(path)
    if m:
        identifier = unquote(m.group(1))
        if method == "GET":
            return _get_service_network(identifier)
        if method == "PATCH":
            return _update_service_network(identifier, body)
        if method == "DELETE":
            return _delete_service_network(identifier)

    if path == "/servicenetworkvpcassociations":
        if method == "POST":
            return _create_vpc_association(body)
        if method == "GET":
            return _list_vpc_associations(query)
    m = _SNVA_PATH.match(path)
    if m:
        identifier = unquote(m.group(1))
        if method == "GET":
            return _get_vpc_association(identifier)
        if method == "PATCH":
            return _update_vpc_association(identifier, body)
        if method == "DELETE":
            return _delete_vpc_association(identifier)

    m = _AUTH_PATH.match(path)
    if m:
        identifier = unquote(m.group(1))
        if method == "PUT":
            return _put_auth_policy(identifier, body)
        if method == "GET":
            return _get_auth_policy(identifier)
        if method == "DELETE":
            return _delete_auth_policy(identifier)

    if path == "/accesslogsubscriptions":
        if method == "POST":
            return _create_access_log_subscription(body)
        if method == "GET":
            return _list_access_log_subscriptions(query)
    m = _ALS_PATH.match(path)
    if m:
        identifier = unquote(m.group(1))
        if method == "GET":
            return _get_access_log_subscription(identifier)
        if method == "PATCH":
            return _update_access_log_subscription(identifier, body)
        if method == "DELETE":
            return _delete_access_log_subscription(identifier)

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

    return _error(400, "ValidationException", f"No route for {method} {path}",
                  reason="unknownOperation")

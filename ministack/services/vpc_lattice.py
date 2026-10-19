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
create and gone after delete. VPC and security group IDs are checked for
shape only, not against EC2 state.
"""

import base64
import copy
import json
import logging
import random
import re
from datetime import datetime, timezone
from urllib.parse import unquote

from ministack.core.responses import (
    AccountRegionScopedDict,
    error_response_json,
    get_account_id,
    get_region,
    json_response,
)

logger = logging.getLogger("vpc-lattice")

_JSON_CT = "application/json"

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

_service_networks = AccountRegionScopedDict()   # sn_id -> service network record
_vpc_associations = AccountRegionScopedDict()   # snva_id -> VPC association record
_auth_policies = AccountRegionScopedDict()      # resource ARN -> auth policy record
_access_log_subscriptions = AccountRegionScopedDict()  # als_id -> subscription record
_tags = AccountRegionScopedDict()               # resource ARN -> {key: value}
_client_tokens = AccountRegionScopedDict()      # "<operation>:<token>" -> {"request", "id"}


def reset():
    _service_networks.clear()
    _vpc_associations.clear()
    _auth_policies.clear()
    _access_log_subscriptions.clear()
    _tags.clear()
    _client_tokens.clear()


def get_state():
    return {
        "service_networks": copy.deepcopy(_service_networks),
        "vpc_associations": copy.deepcopy(_vpc_associations),
        "auth_policies": copy.deepcopy(_auth_policies),
        "access_log_subscriptions": copy.deepcopy(_access_log_subscriptions),
        "tags": copy.deepcopy(_tags),
        "client_tokens": copy.deepcopy(_client_tokens),
    }


def load_persisted_state(data):
    if not data:
        return
    _service_networks.update(data.get("service_networks", {}))
    _vpc_associations.update(data.get("vpc_associations", {}))
    _auth_policies.update(data.get("auth_policies", {}))
    _access_log_subscriptions.update(data.get("access_log_subscriptions", {}))
    _tags.update(data.get("tags", {}))
    _client_tokens.update(data.get("client_tokens", {}))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_AUTH_TYPES = ("NONE", "AWS_IAM")
_LOG_TYPES = ("SERVICE", "RESOURCE")

# Patterns and lengths from the botocore vpc-lattice model.
_NAME_RE = re.compile(r"(?![-])(?!.*[-]$)(?!.*[-]{2})[a-z0-9-]{3,63}")
_ARN_PREFIX = r"arn:[a-z0-9\-]+:vpc-lattice:[a-zA-Z0-9\-]+:\d{12}:"
_SN_ID_RE = re.compile(rf"(sn-[0-9a-z]{{17}})|({_ARN_PREFIX}servicenetwork/sn-[0-9a-z]{{17}})")
_SNVA_ID_RE = re.compile(
    rf"(snva-[0-9a-z]{{17}})|({_ARN_PREFIX}servicenetworkvpcassociation/snva-[0-9a-z]{{17}})")
_ALS_ID_RE = re.compile(rf"(als-[0-9a-z]{{17}})|({_ARN_PREFIX}accesslogsubscription/als-[0-9a-z]{{17}})")
_RESOURCE_ID_RE = re.compile(
    r"((((sn)|(svc)|(rcfg))-[0-9a-z]{17})|(arn(:[a-z0-9]+([.-][a-z0-9]+)*){2}"
    r"(:([a-z0-9]+([.-][a-z0-9]+)*)?){2}:((servicenetwork/sn)|(resourceconfiguration/rcfg)"
    r"|(service/svc))-[0-9a-z]{17}))")
_VPC_ID_RE = re.compile(r"vpc-(([0-9a-z]{8})|([0-9a-z]{17}))")
# CreateAccessLogSubscription documents S3 buckets, CloudWatch Logs log groups
# and Firehose delivery streams as the supported destinations.
_DESTINATION_RE = re.compile(r"arn:aws[a-z-]*:(s3|logs|firehose):.+")


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _new_id(prefix):
    return f"{prefix}-" + "".join(random.choices("0123456789abcdefghijklmnopqrstuvwxyz", k=17))


def _arn(resource_type, resource_id):
    return f"arn:aws:vpc-lattice:{get_region()}:{get_account_id()}:{resource_type}/{resource_id}"


def _json(status, body):
    return json_response(body, status, content_type=_JSON_CT)


def _error(status, code, message, **fields):
    return error_response_json(code, message, status, extra=fields or None, content_type=_JSON_CT)


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


def _invalid_identifier(field, value):
    return _validation(f"Invalid {field}: {value}", field)


def _lookup(store, identifier):
    """Resolve an ID or ARN. An ARN must match the stored ARN exactly, so an
    ARN naming another account or region is not found in this one."""
    if identifier.startswith("arn:"):
        record = store.get(identifier.rsplit("/", 1)[-1])
        return record if record and record["arn"] == identifier else None
    return store.get(identifier)


def _find_service_network(identifier):
    return _lookup(_service_networks, identifier)


def _set_tags(arn, tags):
    if tags:
        existing = _tags.get(arn, {})
        existing.update(tags)
        _tags[arn] = existing


def _drop_resource(arn):
    _tags.pop(arn, None)
    _auth_policies.pop(arn, None)


def _idempotent_replay(operation, body, store, render):
    """Replay a create that repeats a clientToken.

    Returns a response when the token was seen before: the original output when
    the parameters match, a ConflictException when they differ. Returns None for
    a new token, or one whose resource has since been deleted.
    """
    token = body.get("clientToken")
    if not token:
        return None
    seen = _client_tokens.get(f"{operation}:{token}")
    if not seen:
        return None
    record = store.get(seen["id"])
    if not record:
        _client_tokens.pop(f"{operation}:{token}", None)
        return None
    if seen["request"] != _token_request(body):
        return _conflict(seen.get("resourceType", "RESOURCE"), seen["id"],
                         f"clientToken {token} was already used with different parameters")
    return render(record)


def _token_request(body):
    return {k: v for k, v in body.items() if k != "clientToken"}


def _remember_token(operation, body, resource_type, resource_id):
    token = body.get("clientToken")
    if token:
        _client_tokens[f"{operation}:{token}"] = {
            "request": _token_request(body), "id": resource_id, "resourceType": resource_type,
        }


_PAGE_DEFAULT = 100


def _paginate(items, query):
    """maxResults (1-100) and an opaque nextToken, as the model declares.
    Items come in store order, which is creation order."""
    raw_max = query.get("maxResults")
    if raw_max in (None, ""):
        max_results = _PAGE_DEFAULT
    else:
        try:
            max_results = int(raw_max)
        except (TypeError, ValueError):
            return None, _validation(f"Invalid maxResults: {raw_max}", "maxResults")
        if not 1 <= max_results <= 100:
            return None, _validation("maxResults must be between 1 and 100", "maxResults")
    start = 0
    token = query.get("nextToken")
    if token:
        try:
            start = int(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode())
        except (ValueError, UnicodeDecodeError):
            return None, _validation("Invalid nextToken", "nextToken")
        if start < 0:
            return None, _validation("Invalid nextToken", "nextToken")
    end = start + max_results
    page = {"items": items[start:end]}
    if end < len(items):
        page["nextToken"] = base64.urlsafe_b64encode(str(end).encode()).decode().rstrip("=")
    return page, None


# ---------------------------------------------------------------------------
# Service networks
# ---------------------------------------------------------------------------


def _sn_vpc_count(sn_id):
    return sum(1 for a in _vpc_associations.values() if a["serviceNetworkId"] == sn_id)


def _sn_create_out(sn):
    return {k: sn[k] for k in ("id", "name", "arn", "authType", "sharingConfig")}


def _create_service_network(body):
    replay = _idempotent_replay("CreateServiceNetwork", body, _service_networks,
                                lambda sn: _json(201, _sn_create_out(sn)))
    if replay:
        return replay
    name = body.get("name")
    if not name:
        return _validation("name is required", "name")
    if not _NAME_RE.fullmatch(name):
        return _validation(
            "name must be 3-63 characters of a-z, 0-9 and hyphens, and must not start or end "
            "with a hyphen or contain consecutive hyphens", "name")
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
    _remember_token("CreateServiceNetwork", body, "SERVICE_NETWORK", sn_id)
    return _json(201, _sn_create_out(record))


def _sn_view(sn):
    return {
        **sn,
        "numberOfAssociatedVPCs": _sn_vpc_count(sn["id"]),
        "numberOfAssociatedServices": 0,
    }


def _resolve_sn(identifier, field="serviceNetworkIdentifier"):
    """(record, error): validate the identifier shape, then look it up."""
    if not _SN_ID_RE.fullmatch(identifier or ""):
        return None, _invalid_identifier(field, identifier)
    sn = _find_service_network(identifier)
    if not sn:
        return None, _not_found("SERVICE_NETWORK", identifier)
    return sn, None


def _get_service_network(identifier):
    sn, err = _resolve_sn(identifier)
    if err:
        return err
    return _json(200, _sn_view(sn))


def _update_service_network(identifier, body):
    auth_type = body.get("authType")
    if not auth_type:
        return _validation("authType is required", "authType")
    if auth_type not in _AUTH_TYPES:
        return _validation(f"Invalid authType: {auth_type}", "authType")
    sn, err = _resolve_sn(identifier)
    if err:
        return err
    sn["authType"] = auth_type
    sn["lastUpdatedAt"] = _now()
    return _json(200, {k: sn[k] for k in ("id", "name", "arn", "authType")})


def _delete_service_network(identifier):
    sn, err = _resolve_sn(identifier)
    if err:
        return err
    if _sn_vpc_count(sn["id"]):
        return _conflict("SERVICE_NETWORK", sn["id"],
                         "Service network has VPC associations; delete them first")
    # The DeleteServiceNetwork documentation: deleting a network also deletes
    # its auth policy and access log subscriptions.
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
    page, err = _paginate(items, query)
    return err or _json(200, page)


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


_ASSOC_CREATE_KEYS = ("id", "status", "arn", "createdBy", "securityGroupIds", "privateDnsEnabled", "dnsOptions")


def _assoc_create_out(assoc):
    return {k: assoc[k] for k in _ASSOC_CREATE_KEYS if k in assoc}


def _create_vpc_association(body):
    replay = _idempotent_replay("CreateServiceNetworkVpcAssociation", body, _vpc_associations,
                                lambda a: _json(200, _assoc_create_out(a)))
    if replay:
        return replay
    sn_identifier = body.get("serviceNetworkIdentifier")
    vpc_id = body.get("vpcIdentifier")
    if not sn_identifier:
        return _validation("serviceNetworkIdentifier is required", "serviceNetworkIdentifier")
    if not vpc_id:
        return _validation("vpcIdentifier is required", "vpcIdentifier")
    if not _VPC_ID_RE.fullmatch(vpc_id):
        return _invalid_identifier("vpcIdentifier", vpc_id)
    sn, err = _resolve_sn(sn_identifier)
    if err:
        return err
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
    _remember_token("CreateServiceNetworkVpcAssociation", body, "SERVICE_NETWORK_VPC_ASSOCIATION", assoc_id)
    return _json(200, _assoc_create_out(record))


def _resolve_assoc(identifier):
    if not _SNVA_ID_RE.fullmatch(identifier or ""):
        return None, _invalid_identifier("serviceNetworkVpcAssociationIdentifier", identifier)
    assoc = _lookup(_vpc_associations, identifier)
    if not assoc:
        return None, _not_found("SERVICE_NETWORK_VPC_ASSOCIATION", identifier)
    return assoc, None


def _get_vpc_association(identifier):
    assoc, err = _resolve_assoc(identifier)
    if err:
        return err
    return _json(200, _association_view(assoc))


def _update_vpc_association(identifier, body):
    assoc, err = _resolve_assoc(identifier)
    if err:
        return err
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
    assoc, err = _resolve_assoc(identifier)
    if err:
        return err
    _vpc_associations.pop(assoc["id"], None)
    _drop_resource(assoc["arn"])
    return _json(200, {"id": assoc["id"], "arn": assoc["arn"], "status": "DELETE_IN_PROGRESS"})


def _list_vpc_associations(query):
    sn_identifier = query.get("serviceNetworkIdentifier")
    vpc_id = query.get("vpcIdentifier")
    # The ListServiceNetworkVpcAssociations documentation: you must provide
    # either the service network or the VPC.
    if not sn_identifier and not vpc_id:
        return _validation("Either serviceNetworkIdentifier or vpcIdentifier is required")
    if vpc_id and not _VPC_ID_RE.fullmatch(vpc_id):
        return _invalid_identifier("vpcIdentifier", vpc_id)
    sn_id = None
    if sn_identifier:
        sn, err = _resolve_sn(sn_identifier)
        if err:
            return err
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
    page, err = _paginate(items, query)
    return err or _json(200, page)


# ---------------------------------------------------------------------------
# Auth policies and access log subscriptions (service networks only)
# ---------------------------------------------------------------------------


def _resolve_resource(identifier, field="resourceIdentifier"):
    """Auth-policy / access-log resource: the model also accepts service and
    resource-configuration identifiers, which this emulator does not hold."""
    if not _RESOURCE_ID_RE.fullmatch(identifier or ""):
        return None, _invalid_identifier(field, identifier)
    sn = _find_service_network(identifier)
    if not sn:
        return None, _not_found("SERVICE_NETWORK", identifier)
    return sn, None


def _auth_policy_state(sn):
    # The model's AuthPolicyState documentation: the policy is only active when
    # the auth type is AWS_IAM; with NONE it remains inactive.
    return "Active" if sn["authType"] == "AWS_IAM" else "Inactive"


def _put_auth_policy(identifier, body):
    policy = body.get("policy")
    if not policy:
        return _validation("policy is required", "policy")
    try:
        parsed = json.loads(policy)
    except (TypeError, ValueError):
        parsed = None
    if not isinstance(parsed, dict):
        return _validation("policy must be a JSON policy document", "policy")
    sn, err = _resolve_resource(identifier)
    if err:
        return err
    now = _now()
    existing = _auth_policies.get(sn["arn"])
    _auth_policies[sn["arn"]] = {
        "policy": policy,
        "createdAt": existing["createdAt"] if existing else now,
        "lastUpdatedAt": now,
    }
    return _json(200, {"policy": policy, "state": _auth_policy_state(sn)})


def _get_auth_policy(identifier):
    sn, err = _resolve_resource(identifier)
    if err:
        return err
    record = _auth_policies.get(sn["arn"])
    if not record:
        return _not_found("AUTH_POLICY", identifier)
    return _json(200, {**record, "state": _auth_policy_state(sn)})


def _delete_auth_policy(identifier):
    sn, err = _resolve_resource(identifier)
    if err:
        return err
    _auth_policies.pop(sn["arn"], None)
    return 204, {}, b""


_ALS_CREATE_KEYS = ("id", "arn", "resourceId", "resourceArn", "serviceNetworkLogType", "destinationArn")
_ALS_UPDATE_KEYS = ("id", "arn", "resourceId", "resourceArn", "destinationArn")


def _als_create_out(sub):
    return {k: sub[k] for k in _ALS_CREATE_KEYS if k in sub}


def _create_access_log_subscription(body):
    replay = _idempotent_replay("CreateAccessLogSubscription", body, _access_log_subscriptions,
                                lambda s: _json(201, _als_create_out(s)))
    if replay:
        return replay
    identifier = body.get("resourceIdentifier")
    destination = body.get("destinationArn")
    if not identifier:
        return _validation("resourceIdentifier is required", "resourceIdentifier")
    if not destination:
        return _validation("destinationArn is required", "destinationArn")
    if not _DESTINATION_RE.fullmatch(destination):
        return _validation("destinationArn must be an S3 bucket, CloudWatch Logs log group or "
                           "Firehose delivery stream ARN", "destinationArn")
    log_type = body.get("serviceNetworkLogType", "SERVICE")
    if log_type not in _LOG_TYPES:
        return _validation(f"Invalid serviceNetworkLogType: {log_type}", "serviceNetworkLogType")
    sn, err = _resolve_resource(identifier)
    if err:
        return err
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
    _remember_token("CreateAccessLogSubscription", body, "ACCESS_LOG_SUBSCRIPTION", sub_id)
    return _json(201, _als_create_out(record))


def _resolve_subscription(identifier):
    if not _ALS_ID_RE.fullmatch(identifier or ""):
        return None, _invalid_identifier("accessLogSubscriptionIdentifier", identifier)
    sub = _lookup(_access_log_subscriptions, identifier)
    if not sub:
        return None, _not_found("ACCESS_LOG_SUBSCRIPTION", identifier)
    return sub, None


def _get_access_log_subscription(identifier):
    sub, err = _resolve_subscription(identifier)
    if err:
        return err
    return _json(200, sub)


def _update_access_log_subscription(identifier, body):
    destination = body.get("destinationArn")
    if not destination:
        return _validation("destinationArn is required", "destinationArn")
    if not _DESTINATION_RE.fullmatch(destination):
        return _validation("destinationArn must be an S3 bucket, CloudWatch Logs log group or "
                           "Firehose delivery stream ARN", "destinationArn")
    sub, err = _resolve_subscription(identifier)
    if err:
        return err
    sub["destinationArn"] = destination
    sub["lastUpdatedAt"] = _now()
    return _json(200, {k: sub[k] for k in _ALS_UPDATE_KEYS})


def _delete_access_log_subscription(identifier):
    sub, err = _resolve_subscription(identifier)
    if err:
        return err
    _access_log_subscriptions.pop(sub["id"], None)
    _tags.pop(sub["arn"], None)
    return 204, {}, b""


def _list_access_log_subscriptions(query):
    identifier = query.get("resourceIdentifier")
    if not identifier:
        return _validation("resourceIdentifier is required", "resourceIdentifier")
    sn, err = _resolve_resource(identifier)
    if err:
        return err
    items = [s for s in _access_log_subscriptions.values() if s["resourceId"] == sn["id"]]
    page, err = _paginate(items, query)
    return err or _json(200, page)


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------


def _resource_exists(arn):
    return any(_lookup(store, arn) for store in (_service_networks, _vpc_associations, _access_log_subscriptions))


def _tag_resource(arn, body):
    tags = body.get("tags")
    if not isinstance(tags, dict) or not tags:
        return _validation("tags is required", "tags")
    if not _resource_exists(arn):
        return _not_found("RESOURCE", arn)
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
    if not isinstance(body, dict):
        return _validation("Request body must be a JSON object")
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

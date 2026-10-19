"""VPC Lattice control plane: the calls the Terraform aws_vpclattice_* service-network resources make."""

import asyncio
import json
import uuid

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from conftest import ENDPOINT

_VPC = "vpc-0123456789abcdef0"
_POLICY = json.dumps({"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "vpc-lattice-svcs:Invoke", "Resource": "*"}]})


def _name(prefix="sn"):
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _vpc():
    return "vpc-" + uuid.uuid4().hex[:17]


def _err(exc):
    return exc.value.response["Error"]


def _status(resp):
    return resp["ResponseMetadata"]["HTTPStatusCode"]


def _client(region="us-east-1", access_key="test"):
    return boto3.client(
        "vpc-lattice", endpoint_url=ENDPOINT, region_name=region,
        aws_access_key_id=access_key, aws_secret_access_key="test",
        config=Config(retries={"total_max_attempts": 1}),
    )


# ---------------------------------------------------------------------------
# Service networks
# ---------------------------------------------------------------------------


def test_vpclattice_create_service_network(vpclattice):
    name = _name()
    created = vpclattice.create_service_network(name=name, authType="AWS_IAM")
    assert _status(created) == 201
    assert created["id"].startswith("sn-") and len(created["id"]) == 20
    assert created["arn"] == f"arn:aws:vpc-lattice:us-east-1:000000000000:servicenetwork/{created['id']}"
    assert created["authType"] == "AWS_IAM"
    assert created["sharingConfig"] == {"enabled": False}


def test_vpclattice_get_service_network_by_id_and_arn(vpclattice):
    name = _name()
    created = vpclattice.create_service_network(name=name)
    got = vpclattice.get_service_network(serviceNetworkIdentifier=created["id"])
    assert got["name"] == name
    assert got["authType"] == "NONE"
    assert got["numberOfAssociatedVPCs"] == 0
    assert got["createdAt"] is not None
    assert vpclattice.get_service_network(serviceNetworkIdentifier=created["arn"])["id"] == created["id"]


def test_vpclattice_get_service_network_rejects_name(vpclattice):
    """The model's identifier pattern allows an ID or an ARN, not a name."""
    name = _name()
    vpclattice.create_service_network(name=name)
    with pytest.raises(ClientError) as exc:
        vpclattice.get_service_network(serviceNetworkIdentifier=name)
    assert _err(exc)["Code"] == "ValidationException"
    assert _status(exc.value.response) == 400


def test_vpclattice_update_service_network(vpclattice):
    created = vpclattice.create_service_network(name=_name(), authType="AWS_IAM")
    updated = vpclattice.update_service_network(serviceNetworkIdentifier=created["id"], authType="NONE")
    assert _status(updated) == 200
    assert updated["authType"] == "NONE"
    assert vpclattice.get_service_network(serviceNetworkIdentifier=created["id"])["authType"] == "NONE"


def test_vpclattice_delete_service_network(vpclattice):
    created = vpclattice.create_service_network(name=_name())
    assert created["id"] in [n["id"] for n in vpclattice.list_service_networks(maxResults=100)["items"]]
    deleted = vpclattice.delete_service_network(serviceNetworkIdentifier=created["id"])
    assert _status(deleted) == 204
    with pytest.raises(ClientError) as exc:
        vpclattice.get_service_network(serviceNetworkIdentifier=created["id"])
    assert _err(exc)["Code"] == "ResourceNotFoundException"
    assert _status(exc.value.response) == 404
    with pytest.raises(ClientError) as exc:
        vpclattice.delete_service_network(serviceNetworkIdentifier=created["id"])
    assert _err(exc)["Code"] == "ResourceNotFoundException"


def test_vpclattice_duplicate_name_conflict(vpclattice):
    name = _name()
    first = vpclattice.create_service_network(name=name)
    with pytest.raises(ClientError) as exc:
        vpclattice.create_service_network(name=name)
    err = exc.value.response
    assert err["Error"]["Code"] == "ConflictException"
    assert _status(err) == 409
    assert name in err["Error"]["Message"]
    assert err["resourceId"] == first["id"]
    assert err["resourceType"] == "SERVICE_NETWORK"


@pytest.mark.parametrize("name", [
    "Bad_Name", "a" * 64, "-leading", "trailing-", "double--hyphen", "UPPER",
])
def test_vpclattice_invalid_names(vpclattice, name):
    with pytest.raises(ClientError) as exc:
        vpclattice.create_service_network(name=name)
    assert _err(exc)["Code"] == "ValidationException"
    assert exc.value.response["fieldList"][0]["name"] == "name"


@pytest.mark.parametrize("prefix,length", [
    ("", 3), ("a", 63), ("servicenetwork-", 30), ("a-b-c-", 20),
], ids=["shortest", "longest", "servicenetwork-prefix", "single-hyphens"])
def test_vpclattice_valid_name_edges(vpclattice, prefix, length):
    name = (prefix + uuid.uuid4().hex * 3)[:length]
    created = vpclattice.create_service_network(name=name)
    assert vpclattice.get_service_network(serviceNetworkIdentifier=created["id"])["name"] == name
    vpclattice.delete_service_network(serviceNetworkIdentifier=created["id"])


def test_vpclattice_invalid_auth_type(vpclattice):
    with pytest.raises(ClientError) as exc:
        vpclattice.create_service_network(name=_name(), authType="BASIC")
    assert _err(exc)["Code"] == "ValidationException"
    sn = vpclattice.create_service_network(name=_name())
    with pytest.raises(ClientError) as exc:
        vpclattice.update_service_network(serviceNetworkIdentifier=sn["id"], authType="BASIC")
    assert _err(exc)["Code"] == "ValidationException"


def test_vpclattice_create_service_network_client_token(vpclattice):
    token = uuid.uuid4().hex
    name = _name()
    first = vpclattice.create_service_network(name=name, clientToken=token)
    again = vpclattice.create_service_network(name=name, clientToken=token)
    assert again["id"] == first["id"]
    assert _status(again) == 201
    assert [n["id"] for n in vpclattice.list_service_networks()["items"]].count(first["id"]) == 1
    with pytest.raises(ClientError) as exc:
        vpclattice.create_service_network(name=name, authType="AWS_IAM", clientToken=token)
    assert _err(exc)["Code"] == "ConflictException"


def test_vpclattice_list_service_networks_paginates():
    client = _client(region="eu-north-1")
    ids = [client.create_service_network(name=_name())["id"] for _ in range(3)]
    try:
        seen, token = [], None
        while True:
            kwargs = {"maxResults": 1, **({"nextToken": token} if token else {})}
            page = client.list_service_networks(**kwargs)
            assert len(page["items"]) <= 1
            seen += [n["id"] for n in page["items"]]
            token = page.get("nextToken")
            if not token:
                break
        assert [i for i in seen if i in ids] == ids
        paged = [n["id"] for p in client.get_paginator("list_service_networks").paginate(
            PaginationConfig={"PageSize": 2}) for n in p["items"]]
        assert [i for i in paged if i in ids] == ids
        with pytest.raises(ClientError) as exc:
            client.list_service_networks(nextToken="not-a-token")
        assert _err(exc)["Code"] == "ValidationException"
    finally:
        for sn_id in ids:
            client.delete_service_network(serviceNetworkIdentifier=sn_id)


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------


def test_vpclattice_tags(vpclattice):
    created = vpclattice.create_service_network(name=_name(), tags={"team": "network"})
    arn = created["arn"]
    assert vpclattice.list_tags_for_resource(resourceArn=arn)["tags"] == {"team": "network"}
    vpclattice.tag_resource(resourceArn=arn, tags={"env": "dev"})
    vpclattice.untag_resource(resourceArn=arn, tagKeys=["team"])
    assert vpclattice.list_tags_for_resource(resourceArn=arn)["tags"] == {"env": "dev"}


def test_vpclattice_tags_require_the_exact_arn(vpclattice):
    """A real network's ID inside an ARN for another account is not that network."""
    created = vpclattice.create_service_network(name=_name())
    foreign = created["arn"].replace(":000000000000:", ":111111111111:")
    for call in (
        lambda: vpclattice.list_tags_for_resource(resourceArn=foreign),
        lambda: vpclattice.tag_resource(resourceArn=foreign, tags={"a": "b"}),
        lambda: vpclattice.untag_resource(resourceArn=foreign, tagKeys=["a"]),
    ):
        with pytest.raises(ClientError) as exc:
            call()
        assert _err(exc)["Code"] == "ResourceNotFoundException"
    with pytest.raises(ClientError) as exc:
        vpclattice.get_service_network(serviceNetworkIdentifier=foreign)
    assert _err(exc)["Code"] == "ResourceNotFoundException"


# ---------------------------------------------------------------------------
# VPC associations
# ---------------------------------------------------------------------------


def test_vpclattice_create_vpc_association(vpclattice):
    sn = vpclattice.create_service_network(name=_name())
    assoc = vpclattice.create_service_network_vpc_association(
        serviceNetworkIdentifier=sn["id"], vpcIdentifier=_VPC,
        securityGroupIds=["sg-0123456789abcdef0"], tags={"Name": "assoc"})
    assert _status(assoc) == 200
    assert assoc["id"].startswith("snva-")
    assert assoc["status"] == "ACTIVE"
    assert assoc["securityGroupIds"] == ["sg-0123456789abcdef0"]
    assert assoc["createdBy"] == "000000000000"
    assert vpclattice.list_tags_for_resource(resourceArn=assoc["arn"])["tags"] == {"Name": "assoc"}

    got = vpclattice.get_service_network_vpc_association(serviceNetworkVpcAssociationIdentifier=assoc["arn"])
    assert got["serviceNetworkId"] == sn["id"]
    assert got["serviceNetworkArn"] == sn["arn"]
    assert got["vpcId"] == _VPC
    assert vpclattice.get_service_network(serviceNetworkIdentifier=sn["id"])["numberOfAssociatedVPCs"] == 1


def test_vpclattice_duplicate_vpc_association_conflict(vpclattice):
    sn = vpclattice.create_service_network(name=_name())
    vpc = _vpc()
    assoc = vpclattice.create_service_network_vpc_association(serviceNetworkIdentifier=sn["id"], vpcIdentifier=vpc)
    with pytest.raises(ClientError) as exc:
        vpclattice.create_service_network_vpc_association(serviceNetworkIdentifier=sn["id"], vpcIdentifier=vpc)
    err = exc.value.response
    assert err["Error"]["Code"] == "ConflictException"
    assert _status(err) == 409
    assert err["resourceId"] == assoc["id"]
    assert err["resourceType"] == "SERVICE_NETWORK_VPC_ASSOCIATION"


def test_vpclattice_vpc_association_client_token(vpclattice):
    sn = vpclattice.create_service_network(name=_name())
    token = uuid.uuid4().hex
    vpc = _vpc()
    first = vpclattice.create_service_network_vpc_association(
        serviceNetworkIdentifier=sn["id"], vpcIdentifier=vpc, clientToken=token)
    again = vpclattice.create_service_network_vpc_association(
        serviceNetworkIdentifier=sn["id"], vpcIdentifier=vpc, clientToken=token)
    assert again["id"] == first["id"]


def test_vpclattice_list_vpc_associations(vpclattice):
    sn = vpclattice.create_service_network(name=_name())
    vpcs = [_vpc() for _ in range(3)]
    ids = [vpclattice.create_service_network_vpc_association(
        serviceNetworkIdentifier=sn["id"], vpcIdentifier=v)["id"] for v in vpcs]
    listed = vpclattice.list_service_network_vpc_associations(serviceNetworkIdentifier=sn["arn"])["items"]
    assert [a["id"] for a in listed] == ids
    by_vpc = vpclattice.list_service_network_vpc_associations(vpcIdentifier=vpcs[1])["items"]
    assert [a["id"] for a in by_vpc] == [ids[1]]

    first = vpclattice.list_service_network_vpc_associations(serviceNetworkIdentifier=sn["id"], maxResults=2)
    assert [a["id"] for a in first["items"]] == ids[:2]
    rest = vpclattice.list_service_network_vpc_associations(
        serviceNetworkIdentifier=sn["id"], maxResults=2, nextToken=first["nextToken"])
    assert [a["id"] for a in rest["items"]] == ids[2:]
    assert "nextToken" not in rest


def test_vpclattice_list_vpc_associations_requires_a_filter(vpclattice):
    with pytest.raises(ClientError) as exc:
        vpclattice.list_service_network_vpc_associations()
    assert _err(exc)["Code"] == "ValidationException"


def test_vpclattice_update_vpc_association(vpclattice):
    sn = vpclattice.create_service_network(name=_name())
    assoc = vpclattice.create_service_network_vpc_association(
        serviceNetworkIdentifier=sn["id"], vpcIdentifier=_vpc(), securityGroupIds=["sg-0123456789abcdef0"])
    updated = vpclattice.update_service_network_vpc_association(
        serviceNetworkVpcAssociationIdentifier=assoc["id"], securityGroupIds=["sg-0fedcba9876543210"])
    assert updated["securityGroupIds"] == ["sg-0fedcba9876543210"]


def test_vpclattice_delete_vpc_association(vpclattice):
    sn = vpclattice.create_service_network(name=_name())
    assoc = vpclattice.create_service_network_vpc_association(serviceNetworkIdentifier=sn["id"], vpcIdentifier=_vpc())
    with pytest.raises(ClientError) as exc:
        vpclattice.delete_service_network(serviceNetworkIdentifier=sn["id"])
    assert _err(exc)["Code"] == "ConflictException"
    assert _status(exc.value.response) == 409

    deleted = vpclattice.delete_service_network_vpc_association(serviceNetworkVpcAssociationIdentifier=assoc["id"])
    assert _status(deleted) == 200
    assert deleted["status"] == "DELETE_IN_PROGRESS"
    with pytest.raises(ClientError) as exc:
        vpclattice.get_service_network_vpc_association(serviceNetworkVpcAssociationIdentifier=assoc["id"])
    assert _err(exc)["Code"] == "ResourceNotFoundException"
    vpclattice.delete_service_network(serviceNetworkIdentifier=sn["id"])


@pytest.mark.parametrize("vpc", ["vpc-1", "subnet-0123456789abcdef0", "vpc-0123"])
def test_vpclattice_vpc_association_rejects_malformed_vpc(vpclattice, vpc):
    sn = vpclattice.create_service_network(name=_name())
    with pytest.raises(ClientError) as exc:
        vpclattice.create_service_network_vpc_association(serviceNetworkIdentifier=sn["id"], vpcIdentifier=vpc)
    assert _err(exc)["Code"] == "ValidationException"


# ---------------------------------------------------------------------------
# Auth policies
# ---------------------------------------------------------------------------


def test_vpclattice_auth_policy_lifecycle(vpclattice):
    sn = vpclattice.create_service_network(name=_name(), authType="AWS_IAM")
    with pytest.raises(ClientError) as exc:
        vpclattice.get_auth_policy(resourceIdentifier=sn["arn"])
    assert _err(exc)["Code"] == "ResourceNotFoundException"
    assert _status(exc.value.response) == 404

    put = vpclattice.put_auth_policy(resourceIdentifier=sn["arn"], policy=_POLICY)
    assert put["state"] == "Active"
    got = vpclattice.get_auth_policy(resourceIdentifier=sn["id"])
    assert json.loads(got["policy"]) == json.loads(_POLICY)
    assert got["createdAt"] is not None

    deleted = vpclattice.delete_auth_policy(resourceIdentifier=sn["arn"])
    assert _status(deleted) == 204
    with pytest.raises(ClientError) as exc:
        vpclattice.get_auth_policy(resourceIdentifier=sn["arn"])
    assert _err(exc)["Code"] == "ResourceNotFoundException"


def test_vpclattice_auth_policy_state_follows_auth_type(vpclattice):
    sn = vpclattice.create_service_network(name=_name())
    assert vpclattice.put_auth_policy(resourceIdentifier=sn["id"], policy=_POLICY)["state"] == "Inactive"
    assert vpclattice.get_auth_policy(resourceIdentifier=sn["id"])["state"] == "Inactive"
    vpclattice.update_service_network(serviceNetworkIdentifier=sn["id"], authType="AWS_IAM")
    assert vpclattice.get_auth_policy(resourceIdentifier=sn["id"])["state"] == "Active"
    vpclattice.update_service_network(serviceNetworkIdentifier=sn["id"], authType="NONE")
    assert vpclattice.get_auth_policy(resourceIdentifier=sn["id"])["state"] == "Inactive"


@pytest.mark.parametrize("policy", ["not json", "[]", '"a string"'])
def test_vpclattice_auth_policy_must_be_a_json_document(vpclattice, policy):
    sn = vpclattice.create_service_network(name=_name(), authType="AWS_IAM")
    with pytest.raises(ClientError) as exc:
        vpclattice.put_auth_policy(resourceIdentifier=sn["arn"], policy=policy)
    assert _err(exc)["Code"] == "ValidationException"


# ---------------------------------------------------------------------------
# Access log subscriptions
# ---------------------------------------------------------------------------


def test_vpclattice_create_access_log_subscription(vpclattice):
    sn = vpclattice.create_service_network(name=_name())
    destination = "arn:aws:s3:::example-logs/vpc-lattice"
    sub = vpclattice.create_access_log_subscription(
        resourceIdentifier=sn["id"], destinationArn=destination, tags={"Name": "logs"})
    assert _status(sub) == 201
    assert sub["id"].startswith("als-")
    assert sub["resourceId"] == sn["id"]
    assert sub["resourceArn"] == sn["arn"]
    assert vpclattice.list_tags_for_resource(resourceArn=sub["arn"])["tags"] == {"Name": "logs"}

    got = vpclattice.get_access_log_subscription(accessLogSubscriptionIdentifier=sub["arn"])
    assert got["destinationArn"] == destination
    assert got["serviceNetworkLogType"] == "SERVICE"


def test_vpclattice_access_log_subscription_client_token(vpclattice):
    sn = vpclattice.create_service_network(name=_name())
    token = uuid.uuid4().hex
    kwargs = {"resourceIdentifier": sn["id"], "destinationArn": "arn:aws:s3:::example-logs", "clientToken": token}
    first = vpclattice.create_access_log_subscription(**kwargs)
    again = vpclattice.create_access_log_subscription(**kwargs)
    assert again["id"] == first["id"]
    assert len(vpclattice.list_access_log_subscriptions(resourceIdentifier=sn["id"])["items"]) == 1


def test_vpclattice_update_and_list_access_log_subscriptions(vpclattice):
    sn = vpclattice.create_service_network(name=_name())
    sub = vpclattice.create_access_log_subscription(
        resourceIdentifier=sn["id"], destinationArn="arn:aws:s3:::example-logs")
    log_group = "arn:aws:logs:us-east-1:000000000000:log-group:lattice"
    other = vpclattice.create_access_log_subscription(resourceIdentifier=sn["id"], destinationArn=log_group)
    updated = vpclattice.update_access_log_subscription(
        accessLogSubscriptionIdentifier=sub["id"], destinationArn="arn:aws:s3:::example-logs/v2")
    assert updated["destinationArn"] == "arn:aws:s3:::example-logs/v2"
    listed = vpclattice.list_access_log_subscriptions(resourceIdentifier=sn["arn"])["items"]
    assert [s["id"] for s in listed] == [sub["id"], other["id"]]
    page = vpclattice.list_access_log_subscriptions(resourceIdentifier=sn["arn"], maxResults=1)
    assert [s["id"] for s in page["items"]] == [sub["id"]] and page["nextToken"]

    deleted = vpclattice.delete_access_log_subscription(accessLogSubscriptionIdentifier=sub["id"])
    assert _status(deleted) == 204
    with pytest.raises(ClientError) as exc:
        vpclattice.get_access_log_subscription(accessLogSubscriptionIdentifier=sub["id"])
    assert _err(exc)["Code"] == "ResourceNotFoundException"


@pytest.mark.parametrize("destination", [
    "arn:aws:sqs:us-east-1:000000000000:queue",
    "arn:aws:kinesis:us-east-1:000000000000:stream/s",
])
def test_vpclattice_access_log_destination_must_be_supported(vpclattice, destination):
    sn = vpclattice.create_service_network(name=_name())
    with pytest.raises(ClientError) as exc:
        vpclattice.create_access_log_subscription(resourceIdentifier=sn["id"], destinationArn=destination)
    assert _err(exc)["Code"] == "ValidationException"
    sub = vpclattice.create_access_log_subscription(
        resourceIdentifier=sn["id"], destinationArn="arn:aws:s3:::example-logs")
    with pytest.raises(ClientError) as exc:
        vpclattice.update_access_log_subscription(accessLogSubscriptionIdentifier=sub["id"], destinationArn=destination)
    assert _err(exc)["Code"] == "ValidationException"


def test_vpclattice_delete_service_network_cascades(vpclattice):
    """DeleteServiceNetwork's documentation: the auth policy and access log
    subscriptions go with the network."""
    sn = vpclattice.create_service_network(name=_name(), authType="AWS_IAM")
    sub = vpclattice.create_access_log_subscription(
        resourceIdentifier=sn["id"], destinationArn="arn:aws:s3:::example-logs", tags={"k": "v"})
    vpclattice.put_auth_policy(resourceIdentifier=sn["id"], policy=_POLICY)
    vpclattice.delete_service_network(serviceNetworkIdentifier=sn["id"])

    with pytest.raises(ClientError) as exc:
        vpclattice.get_access_log_subscription(accessLogSubscriptionIdentifier=sub["id"])
    assert _err(exc)["Code"] == "ResourceNotFoundException"
    with pytest.raises(ClientError) as exc:
        vpclattice.list_tags_for_resource(resourceArn=sub["arn"])
    assert _err(exc)["Code"] == "ResourceNotFoundException"
    with pytest.raises(ClientError) as exc:
        vpclattice.get_auth_policy(resourceIdentifier=sn["id"])
    assert _err(exc)["Code"] == "ResourceNotFoundException"


# ---------------------------------------------------------------------------
# Unknown and malformed identifiers
# ---------------------------------------------------------------------------


def test_vpclattice_unknown_identifiers(vpclattice):
    missing_sn = "sn-0000000000000000a"
    for call in (
        lambda: vpclattice.get_service_network(serviceNetworkIdentifier=missing_sn),
        lambda: vpclattice.delete_service_network(serviceNetworkIdentifier=missing_sn),
        lambda: vpclattice.create_service_network_vpc_association(
            serviceNetworkIdentifier=missing_sn, vpcIdentifier=_VPC),
        lambda: vpclattice.get_service_network_vpc_association(
            serviceNetworkVpcAssociationIdentifier="snva-0000000000000000a"),
        lambda: vpclattice.delete_access_log_subscription(accessLogSubscriptionIdentifier="als-0000000000000000a"),
        lambda: vpclattice.put_auth_policy(resourceIdentifier=missing_sn, policy=_POLICY),
    ):
        with pytest.raises(ClientError) as exc:
            call()
        assert _err(exc)["Code"] == "ResourceNotFoundException"
        assert _status(exc.value.response) == 404


@pytest.mark.parametrize("call", [
    lambda c: c.get_service_network(serviceNetworkIdentifier="sn-short"),
    lambda c: c.get_service_network_vpc_association(serviceNetworkVpcAssociationIdentifier="sn-0000000000000000a"),
    lambda c: c.get_access_log_subscription(accessLogSubscriptionIdentifier="als-NOT-A-VALID-ID-AT-ALL"),
    lambda c: c.get_auth_policy(resourceIdentifier="not-an-identifier"),
], ids=["service-network", "association", "subscription", "auth-policy"])
def test_vpclattice_malformed_identifiers(vpclattice, call):
    with pytest.raises(ClientError) as exc:
        call(vpclattice)
    assert _err(exc)["Code"] == "ValidationException"


def test_vpclattice_rejects_malformed_json():
    from ministack.services import vpc_lattice

    status, headers, body = asyncio.run(
        vpc_lattice.handle_request("POST", "/servicenetworks", {}, b"{not json", {}))
    assert status == 400
    assert headers["x-amzn-errortype"] == "ValidationException"
    assert json.loads(body)["__type"] == "ValidationException"


# ---------------------------------------------------------------------------
# Account and region isolation
# ---------------------------------------------------------------------------


def test_vpclattice_region_isolation():
    east, west = _client("us-east-1"), _client("us-west-2")
    name = _name()
    sn = east.create_service_network(name=name)
    try:
        with pytest.raises(ClientError) as exc:
            west.get_service_network(serviceNetworkIdentifier=sn["id"])
        assert _err(exc)["Code"] == "ResourceNotFoundException"
        assert sn["id"] not in [n["id"] for n in west.list_service_networks()["items"]]
        with pytest.raises(ClientError) as exc:
            west.delete_service_network(serviceNetworkIdentifier=sn["id"])
        assert _err(exc)["Code"] == "ResourceNotFoundException"
        # Names are unique per account and region, not globally.
        other = west.create_service_network(name=name)
        assert other["arn"].startswith("arn:aws:vpc-lattice:us-west-2:")
        west.delete_service_network(serviceNetworkIdentifier=other["id"])
        assert east.get_service_network(serviceNetworkIdentifier=sn["id"])["name"] == name
    finally:
        east.delete_service_network(serviceNetworkIdentifier=sn["id"])


def test_vpclattice_account_isolation(auth_enabled):
    if auth_enabled:
        pytest.skip("account selection by 12-digit access key needs AUTH=false")
    mine, theirs = _client(), _client(access_key="222222222222")
    name = _name()
    sn = mine.create_service_network(name=name)
    try:
        with pytest.raises(ClientError) as exc:
            theirs.get_service_network(serviceNetworkIdentifier=sn["id"])
        assert _err(exc)["Code"] == "ResourceNotFoundException"
        assert sn["id"] not in [n["id"] for n in theirs.list_service_networks()["items"]]
        other = theirs.create_service_network(name=name)
        assert ":222222222222:" in other["arn"]
        theirs.delete_service_network(serviceNetworkIdentifier=other["id"])
    finally:
        mine.delete_service_network(serviceNetworkIdentifier=sn["id"])


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------


@pytest.mark.auth_contract
def test_vpclattice_requires_permission(auth_enabled, iam_user):
    client = iam_user().client("vpc-lattice")
    if auth_enabled:
        with pytest.raises(ClientError) as exc:
            client.create_service_network(name=_name())
        assert _err(exc)["Code"] == "AccessDeniedException"
        assert _status(exc.value.response) == 403
        with pytest.raises(ClientError) as exc:
            client.list_service_networks()
        assert _err(exc)["Code"] == "AccessDeniedException"
    else:
        created = client.create_service_network(name=_name())
        assert client.get_service_network(serviceNetworkIdentifier=created["id"])["id"] == created["id"]
        client.delete_service_network(serviceNetworkIdentifier=created["id"])


@pytest.mark.auth_contract
def test_vpclattice_allowed_with_policy(auth_enabled, iam_user):
    policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "vpc-lattice:*", "Resource": "*"}]}
    client = iam_user(policy=policy).client("vpc-lattice")
    created = client.create_service_network(name=_name(), tags={"k": "v"})
    client.put_auth_policy(resourceIdentifier=created["arn"], policy=_POLICY)
    assert client.list_tags_for_resource(resourceArn=created["arn"])["tags"] == {"k": "v"}
    client.delete_service_network(serviceNetworkIdentifier=created["id"])


@pytest.mark.auth_contract
def test_vpclattice_permission_is_scoped_to_the_resource(auth_enabled, iam_user, vpclattice):
    allowed = vpclattice.create_service_network(name=_name())
    other = vpclattice.create_service_network(name=_name())
    policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "vpc-lattice:GetServiceNetwork", "Resource": allowed["arn"]}]}
    client = iam_user(policy=policy).client("vpc-lattice")
    assert client.get_service_network(serviceNetworkIdentifier=allowed["id"])["id"] == allowed["id"]
    if auth_enabled:
        with pytest.raises(ClientError) as exc:
            client.get_service_network(serviceNetworkIdentifier=other["id"])
        assert _err(exc)["Code"] == "AccessDeniedException"
        with pytest.raises(ClientError) as exc:
            client.delete_service_network(serviceNetworkIdentifier=allowed["id"])
        assert _err(exc)["Code"] == "AccessDeniedException"
    else:
        assert client.get_service_network(serviceNetworkIdentifier=other["id"])["id"] == other["id"]
    for sn in (allowed, other):
        vpclattice.delete_service_network(serviceNetworkIdentifier=sn["id"])

"""VPC Lattice control plane: the calls the Terraform aws_vpclattice_* service-network resources make."""

import json
import uuid

import pytest
from botocore.exceptions import ClientError


def _name(prefix="sn"):
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _code(exc):
    return exc.value.response["Error"]["Code"]


def test_vpclattice_service_network_lifecycle(vpclattice):
    name = _name()
    created = vpclattice.create_service_network(name=name, authType="AWS_IAM", tags={"team": "platform"})
    sn_id = created["id"]
    assert sn_id.startswith("sn-")
    assert created["arn"].endswith(f":servicenetwork/{sn_id}")
    assert created["authType"] == "AWS_IAM"
    assert created["ResponseMetadata"]["HTTPStatusCode"] == 201

    got = vpclattice.get_service_network(serviceNetworkIdentifier=sn_id)
    assert got["name"] == name
    assert got["numberOfAssociatedVPCs"] == 0
    assert got["createdAt"] is not None
    assert vpclattice.get_service_network(serviceNetworkIdentifier=created["arn"])["id"] == sn_id
    assert vpclattice.get_service_network(serviceNetworkIdentifier=name)["id"] == sn_id

    assert vpclattice.list_tags_for_resource(resourceArn=created["arn"])["tags"] == {"team": "platform"}
    vpclattice.tag_resource(resourceArn=created["arn"], tags={"env": "dev"})
    vpclattice.untag_resource(resourceArn=created["arn"], tagKeys=["team"])
    assert vpclattice.list_tags_for_resource(resourceArn=created["arn"])["tags"] == {"env": "dev"}

    updated = vpclattice.update_service_network(serviceNetworkIdentifier=sn_id, authType="NONE")
    assert updated["authType"] == "NONE"
    assert sn_id in [n["id"] for n in vpclattice.list_service_networks()["items"]]

    vpclattice.delete_service_network(serviceNetworkIdentifier=sn_id)
    with pytest.raises(ClientError) as exc:
        vpclattice.get_service_network(serviceNetworkIdentifier=sn_id)
    assert _code(exc) == "ResourceNotFoundException"


def test_vpclattice_service_network_name_rules(vpclattice):
    name = _name()
    vpclattice.create_service_network(name=name)
    with pytest.raises(ClientError) as exc:
        vpclattice.create_service_network(name=name)
    assert _code(exc) == "ConflictException"
    with pytest.raises(ClientError) as exc:
        vpclattice.create_service_network(name="Bad_Name")
    assert _code(exc) == "ValidationException"


def test_vpclattice_vpc_association_lifecycle(vpclattice):
    sn = vpclattice.create_service_network(name=_name())
    assoc = vpclattice.create_service_network_vpc_association(
        serviceNetworkIdentifier=sn["id"], vpcIdentifier="vpc-0123456789abcdef0",
        securityGroupIds=["sg-0123456789abcdef0"], tags={"Name": "assoc"})
    assoc_id = assoc["id"]
    assert assoc_id.startswith("snva-")
    assert assoc["status"] == "ACTIVE"
    assert assoc["securityGroupIds"] == ["sg-0123456789abcdef0"]

    got = vpclattice.get_service_network_vpc_association(serviceNetworkVpcAssociationIdentifier=assoc_id)
    assert got["serviceNetworkId"] == sn["id"]
    assert got["serviceNetworkArn"] == sn["arn"]
    assert got["vpcId"] == "vpc-0123456789abcdef0"
    assert vpclattice.get_service_network(serviceNetworkIdentifier=sn["id"])["numberOfAssociatedVPCs"] == 1
    assert vpclattice.list_tags_for_resource(resourceArn=assoc["arn"])["tags"] == {"Name": "assoc"}

    with pytest.raises(ClientError) as exc:
        vpclattice.create_service_network_vpc_association(
            serviceNetworkIdentifier=sn["id"], vpcIdentifier="vpc-0123456789abcdef0")
    assert _code(exc) == "ConflictException"

    listed = vpclattice.list_service_network_vpc_associations(serviceNetworkIdentifier=sn["id"])["items"]
    assert [a["id"] for a in listed] == [assoc_id]
    by_vpc = vpclattice.list_service_network_vpc_associations(vpcIdentifier="vpc-0123456789abcdef0")["items"]
    assert assoc_id in [a["id"] for a in by_vpc]

    updated = vpclattice.update_service_network_vpc_association(
        serviceNetworkVpcAssociationIdentifier=assoc_id, securityGroupIds=["sg-0fedcba9876543210"])
    assert updated["securityGroupIds"] == ["sg-0fedcba9876543210"]

    with pytest.raises(ClientError) as exc:
        vpclattice.delete_service_network(serviceNetworkIdentifier=sn["id"])
    assert _code(exc) == "ConflictException"

    deleted = vpclattice.delete_service_network_vpc_association(serviceNetworkVpcAssociationIdentifier=assoc_id)
    assert deleted["status"] == "DELETE_IN_PROGRESS"
    with pytest.raises(ClientError) as exc:
        vpclattice.get_service_network_vpc_association(serviceNetworkVpcAssociationIdentifier=assoc_id)
    assert _code(exc) == "ResourceNotFoundException"
    vpclattice.delete_service_network(serviceNetworkIdentifier=sn["id"])


def test_vpclattice_auth_policy(vpclattice):
    sn = vpclattice.create_service_network(name=_name(), authType="AWS_IAM")
    policy = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "vpc-lattice-svcs:Invoke", "Resource": "*"}]})
    with pytest.raises(ClientError) as exc:
        vpclattice.get_auth_policy(resourceIdentifier=sn["arn"])
    assert _code(exc) == "ResourceNotFoundException"

    put = vpclattice.put_auth_policy(resourceIdentifier=sn["arn"], policy=policy)
    assert put["state"] == "Active"
    got = vpclattice.get_auth_policy(resourceIdentifier=sn["id"])
    assert json.loads(got["policy"]) == json.loads(policy)
    assert got["createdAt"] is not None

    with pytest.raises(ClientError) as exc:
        vpclattice.put_auth_policy(resourceIdentifier=sn["arn"], policy="not json")
    assert _code(exc) == "ValidationException"

    vpclattice.delete_auth_policy(resourceIdentifier=sn["arn"])
    with pytest.raises(ClientError) as exc:
        vpclattice.get_auth_policy(resourceIdentifier=sn["arn"])
    assert _code(exc) == "ResourceNotFoundException"


def test_vpclattice_access_log_subscription(vpclattice):
    sn = vpclattice.create_service_network(name=_name())
    destination = "arn:aws:s3:::platform-logs/vpc-lattice/dev/access-logs"
    sub = vpclattice.create_access_log_subscription(
        resourceIdentifier=sn["id"], destinationArn=destination, tags={"Name": "logs"})
    sub_id = sub["id"]
    assert sub_id.startswith("als-")
    assert sub["resourceId"] == sn["id"]
    assert sub["resourceArn"] == sn["arn"]

    got = vpclattice.get_access_log_subscription(accessLogSubscriptionIdentifier=sub_id)
    assert got["destinationArn"] == destination
    assert got["serviceNetworkLogType"] == "SERVICE"

    with pytest.raises(ClientError) as exc:
        vpclattice.create_access_log_subscription(
            resourceIdentifier=sn["id"], destinationArn="arn:aws:s3:::other-bucket")
    assert _code(exc) == "ConflictException"

    updated = vpclattice.update_access_log_subscription(
        accessLogSubscriptionIdentifier=sub_id, destinationArn="arn:aws:s3:::platform-logs/v2")
    assert updated["destinationArn"] == "arn:aws:s3:::platform-logs/v2"
    listed = vpclattice.list_access_log_subscriptions(resourceIdentifier=sn["arn"])["items"]
    assert [s["id"] for s in listed] == [sub_id]

    vpclattice.delete_access_log_subscription(accessLogSubscriptionIdentifier=sub_id)
    with pytest.raises(ClientError) as exc:
        vpclattice.get_access_log_subscription(accessLogSubscriptionIdentifier=sub_id)
    assert _code(exc) == "ResourceNotFoundException"


def test_vpclattice_unknown_identifiers(vpclattice):
    with pytest.raises(ClientError) as exc:
        vpclattice.get_service_network(serviceNetworkIdentifier="sn-0000000000000000a")
    assert _code(exc) == "ResourceNotFoundException"
    with pytest.raises(ClientError) as exc:
        vpclattice.create_service_network_vpc_association(
            serviceNetworkIdentifier="sn-0000000000000000a", vpcIdentifier="vpc-1")
    assert _code(exc) == "ResourceNotFoundException"
    with pytest.raises(ClientError) as exc:
        vpclattice.list_tags_for_resource(
            resourceArn="arn:aws:vpc-lattice:us-east-1:000000000000:servicenetwork/sn-0000000000000000a")
    assert _code(exc) == "ResourceNotFoundException"

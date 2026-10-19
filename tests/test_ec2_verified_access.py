"""EC2 Verified Access control plane: the calls the Terraform aws_verifiedaccess_* resources make."""

import uuid

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from conftest import ENDPOINT, make_client

_POLICY = 'permit(principal, action, resource) when { context.oidc.email like "*@example.com" };'
_LB_ARN = "arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/web/0123456789abcdef"
_MISSING_INSTANCE = "vai-0000000000000000a"


def _client(region="us-east-1", account_id="test"):
    return boto3.client(
        "ec2", endpoint_url=ENDPOINT, region_name=region,
        aws_access_key_id=account_id, aws_secret_access_key="test",
        config=Config(region_name=region, retries={"total_max_attempts": 1}),
    )


def _oidc_trust_provider(ec2, **extra):
    return ec2.create_verified_access_trust_provider(
        TrustProviderType="user",
        UserTrustProviderType="oidc",
        PolicyReferenceName="idp",
        OidcOptions={
            "Issuer": "https://login.example.com",
            "AuthorizationEndpoint": "https://login.example.com/authorize",
            "TokenEndpoint": "https://login.example.com/token",
            "UserInfoEndpoint": "https://login.example.com/userinfo",
            "ClientId": "client",
            "ClientSecret": "secret",
            "Scope": "openid email",
        },
        **extra,
    )["VerifiedAccessTrustProvider"]


def _device_trust_provider(ec2, device_type="jamf"):
    return ec2.create_verified_access_trust_provider(
        TrustProviderType="device",
        DeviceTrustProviderType=device_type,
        PolicyReferenceName=device_type,
        DeviceOptions={"TenantId": "tenant-1", "PublicSigningKeyUrl": "https://keys.example.com"},
    )["VerifiedAccessTrustProvider"]


def _instance(ec2, **extra):
    return ec2.create_verified_access_instance(**extra)["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]


def _group(ec2, inst_id, **extra):
    return ec2.create_verified_access_group(
        VerifiedAccessInstanceId=inst_id, **extra)["VerifiedAccessGroup"]["VerifiedAccessGroupId"]


def _lb_endpoint(ec2, group_id, **extra):
    return ec2.create_verified_access_endpoint(
        VerifiedAccessGroupId=group_id, EndpointType="load-balancer", AttachmentType="vpc",
        DomainCertificateArn="arn:aws:acm:us-east-1:000000000000:certificate/abc",
        ApplicationDomain="app.example.com", EndpointDomainPrefix="app",
        LoadBalancerOptions={"Protocol": "https", "Port": 443, "LoadBalancerArn": _LB_ARN,
                             "SubnetIds": ["subnet-aaa"]},
        **extra,
    )["VerifiedAccessEndpoint"]


def _error_code(exc):
    return exc.value.response["Error"]["Code"]


def _instance_provider_ids(ec2, inst_id):
    inst = ec2.describe_verified_access_instances(VerifiedAccessInstanceIds=[inst_id])["VerifiedAccessInstances"][0]
    return [p["VerifiedAccessTrustProviderId"] for p in inst["VerifiedAccessTrustProviders"]]


def test_verified_access_trust_provider_lifecycle(ec2):
    tp = _oidc_trust_provider(
        ec2,
        Description="corp idp",
        TagSpecifications=[{"ResourceType": "verified-access-trust-provider",
                            "Tags": [{"Key": "team", "Value": "platform"}]}],
    )
    tp_id = tp["VerifiedAccessTrustProviderId"]
    assert tp_id.startswith("vatp-")
    assert tp["TrustProviderType"] == "user"
    assert tp["UserTrustProviderType"] == "oidc"
    assert tp["OidcOptions"]["Issuer"] == "https://login.example.com"
    assert "ClientSecret" not in tp["OidcOptions"]
    assert tp["Tags"] == [{"Key": "team", "Value": "platform"}]

    described = ec2.describe_verified_access_trust_providers(
        VerifiedAccessTrustProviderIds=[tp_id])["VerifiedAccessTrustProviders"]
    assert [d["VerifiedAccessTrustProviderId"] for d in described] == [tp_id]
    assert described[0]["PolicyReferenceName"] == "idp"

    modified = ec2.modify_verified_access_trust_provider(
        VerifiedAccessTrustProviderId=tp_id,
        Description="renamed",
        OidcOptions={"Scope": "openid"},
    )["VerifiedAccessTrustProvider"]
    assert modified["Description"] == "renamed"
    assert modified["OidcOptions"]["Scope"] == "openid"
    assert modified["OidcOptions"]["ClientId"] == "client"

    deleted = ec2.delete_verified_access_trust_provider(
        VerifiedAccessTrustProviderId=tp_id)["VerifiedAccessTrustProvider"]
    assert deleted["VerifiedAccessTrustProviderId"] == tp_id
    with pytest.raises(ClientError) as exc:
        ec2.describe_verified_access_trust_providers(VerifiedAccessTrustProviderIds=[tp_id])
    assert _error_code(exc) == "InvalidVerifiedAccessTrustProviderId.NotFound"


def test_verified_access_device_trust_provider(ec2):
    tp = _device_trust_provider(ec2, "jumpcloud")
    tp_id = tp["VerifiedAccessTrustProviderId"]
    assert tp["TrustProviderType"] == "device"
    assert tp["DeviceTrustProviderType"] == "jumpcloud"
    assert "UserTrustProviderType" not in tp
    assert tp["DeviceOptions"] == {"TenantId": "tenant-1", "PublicSigningKeyUrl": "https://keys.example.com"}

    modified = ec2.modify_verified_access_trust_provider(
        VerifiedAccessTrustProviderId=tp_id,
        DeviceOptions={"PublicSigningKeyUrl": "https://keys2.example.com"},
    )["VerifiedAccessTrustProvider"]
    assert modified["DeviceOptions"] == {"TenantId": "tenant-1", "PublicSigningKeyUrl": "https://keys2.example.com"}
    ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=tp_id)


@pytest.mark.parametrize("kwargs, code", [
    ({"TrustProviderType": "user", "DeviceTrustProviderType": "jamf"}, "InvalidParameterValue"),
    ({"TrustProviderType": "device", "UserTrustProviderType": "oidc"}, "InvalidParameterValue"),
    ({"TrustProviderType": "robot"}, "InvalidParameterValue"),
    ({"TrustProviderType": "user", "UserTrustProviderType": "oidc"}, "MissingParameter"),
])
def test_verified_access_trust_provider_create_validation(ec2, kwargs, code):
    before = len(ec2.describe_verified_access_trust_providers()["VerifiedAccessTrustProviders"])
    with pytest.raises(ClientError) as exc:
        ec2.create_verified_access_trust_provider(PolicyReferenceName="x", **kwargs)
    assert _error_code(exc) == code
    after = len(ec2.describe_verified_access_trust_providers()["VerifiedAccessTrustProviders"])
    assert after == before


def test_verified_access_iam_identity_center_provider_needs_no_oidc_options(ec2):
    tp = ec2.create_verified_access_trust_provider(
        TrustProviderType="user", UserTrustProviderType="iam-identity-center", PolicyReferenceName="sso",
    )["VerifiedAccessTrustProvider"]
    assert tp["UserTrustProviderType"] == "iam-identity-center"
    assert "OidcOptions" not in tp
    ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=tp["VerifiedAccessTrustProviderId"])


def test_verified_access_instance_attach_detach_and_tags(ec2):
    inst_id = _instance(
        ec2, Description="platform",
        TagSpecifications=[{"ResourceType": "verified-access-instance",
                            "Tags": [{"Key": "Name", "Value": "platform-va"}]}],
    )
    assert inst_id.startswith("vai-")
    inst = ec2.describe_verified_access_instances(VerifiedAccessInstanceIds=[inst_id])["VerifiedAccessInstances"][0]
    assert inst["VerifiedAccessTrustProviders"] == []
    assert inst["FipsEnabled"] is False
    tp_id = _oidc_trust_provider(ec2)["VerifiedAccessTrustProviderId"]

    attached = ec2.attach_verified_access_trust_provider(
        VerifiedAccessInstanceId=inst_id, VerifiedAccessTrustProviderId=tp_id)
    assert attached["VerifiedAccessTrustProvider"]["VerifiedAccessTrustProviderId"] == tp_id
    providers = attached["VerifiedAccessInstance"]["VerifiedAccessTrustProviders"]
    assert [(p["VerifiedAccessTrustProviderId"], p["UserTrustProviderType"]) for p in providers] == [(tp_id, "oidc")]

    # The Terraform attachment resource reads through DescribeVerifiedAccessInstances.
    assert _instance_provider_ids(ec2, inst_id) == [tp_id]

    with pytest.raises(ClientError) as exc:
        ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=tp_id)
    assert _error_code(exc) == "InvalidParameterValue"
    assert ec2.describe_verified_access_trust_providers(
        VerifiedAccessTrustProviderIds=[tp_id])["VerifiedAccessTrustProviders"]

    ec2.detach_verified_access_trust_provider(
        VerifiedAccessInstanceId=inst_id, VerifiedAccessTrustProviderId=tp_id)
    assert _instance_provider_ids(ec2, inst_id) == []

    # Detaching a provider that is not attached is refused and changes nothing.
    with pytest.raises(ClientError) as exc:
        ec2.detach_verified_access_trust_provider(
            VerifiedAccessInstanceId=inst_id, VerifiedAccessTrustProviderId=tp_id)
    assert _error_code(exc) == "InvalidParameterValue"

    ec2.modify_verified_access_instance(VerifiedAccessInstanceId=inst_id, Description="changed")
    assert ec2.describe_verified_access_instances(
        VerifiedAccessInstanceIds=[inst_id])["VerifiedAccessInstances"][0]["Description"] == "changed"

    deleted = ec2.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)["VerifiedAccessInstance"]
    assert deleted["VerifiedAccessInstanceId"] == inst_id
    ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=tp_id)
    with pytest.raises(ClientError) as exc:
        ec2.describe_verified_access_instances(VerifiedAccessInstanceIds=[inst_id])
    assert _error_code(exc) == "InvalidVerifiedAccessInstanceId.NotFound"


def test_verified_access_one_user_provider_several_device_providers(ec2):
    inst_id = _instance(ec2)
    first = _oidc_trust_provider(ec2)["VerifiedAccessTrustProviderId"]
    second = _oidc_trust_provider(ec2)["VerifiedAccessTrustProviderId"]
    jamf = _device_trust_provider(ec2, "jamf")["VerifiedAccessTrustProviderId"]
    crowdstrike = _device_trust_provider(ec2, "crowdstrike")["VerifiedAccessTrustProviderId"]
    ec2.attach_verified_access_trust_provider(VerifiedAccessInstanceId=inst_id, VerifiedAccessTrustProviderId=first)
    with pytest.raises(ClientError) as exc:
        ec2.attach_verified_access_trust_provider(VerifiedAccessInstanceId=inst_id, VerifiedAccessTrustProviderId=second)
    assert _error_code(exc) == "InvalidParameterValue"
    assert _instance_provider_ids(ec2, inst_id) == [first]

    for device in (jamf, crowdstrike):
        ec2.attach_verified_access_trust_provider(VerifiedAccessInstanceId=inst_id, VerifiedAccessTrustProviderId=device)
    assert _instance_provider_ids(ec2, inst_id) == [first, jamf, crowdstrike]

    for tp_id in (first, jamf, crowdstrike):
        ec2.detach_verified_access_trust_provider(VerifiedAccessInstanceId=inst_id, VerifiedAccessTrustProviderId=tp_id)
    for tp_id in (first, second, jamf, crowdstrike):
        ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=tp_id)
    ec2.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)


def test_verified_access_instance_refuses_cidr_subdomain(ec2):
    before = len(ec2.describe_verified_access_instances()["VerifiedAccessInstances"])
    with pytest.raises(ClientError) as exc:
        ec2.create_verified_access_instance(CidrEndpointsCustomSubDomain="corp.example.com")
    assert _error_code(exc) == "UnsupportedOperation"
    assert len(ec2.describe_verified_access_instances()["VerifiedAccessInstances"]) == before

    inst_id = _instance(ec2, Description="kept")
    with pytest.raises(ClientError) as exc:
        ec2.modify_verified_access_instance(
            VerifiedAccessInstanceId=inst_id, Description="dropped", CidrEndpointsCustomSubDomain="corp.example.com")
    assert _error_code(exc) == "UnsupportedOperation"
    assert ec2.describe_verified_access_instances(
        VerifiedAccessInstanceIds=[inst_id])["VerifiedAccessInstances"][0]["Description"] == "kept"
    ec2.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)


def test_verified_access_instance_logging_configuration(ec2):
    inst_id = _instance(ec2)
    default = ec2.describe_verified_access_instance_logging_configurations(
        VerifiedAccessInstanceIds=[inst_id])["LoggingConfigurations"][0]
    assert default["VerifiedAccessInstanceId"] == inst_id
    assert default["AccessLogs"]["S3"]["Enabled"] is False
    assert default["AccessLogs"]["IncludeTrustContext"] is False

    modified = ec2.modify_verified_access_instance_logging_configuration(
        VerifiedAccessInstanceId=inst_id,
        AccessLogs={
            "S3": {"Enabled": True, "BucketName": "va-logs", "Prefix": "platform/"},
            "CloudWatchLogs": {"Enabled": True, "LogGroup": "/aws/verified-access/platform"},
            "KinesisDataFirehose": {"Enabled": False},
            "LogVersion": "ocsf-1.0.0-rc.2",
            "IncludeTrustContext": True,
        },
    )["LoggingConfiguration"]["AccessLogs"]
    assert modified["S3"]["Enabled"] is True
    assert modified["S3"]["BucketName"] == "va-logs"
    # Nothing is delivered, so no delivery status is reported.
    assert "DeliveryStatus" not in modified["S3"]
    assert modified["CloudWatchLogs"]["LogGroup"] == "/aws/verified-access/platform"
    assert modified["KinesisDataFirehose"]["Enabled"] is False
    assert modified["LogVersion"] == "ocsf-1.0.0-rc.2"
    assert modified["IncludeTrustContext"] is True

    again = ec2.describe_verified_access_instance_logging_configurations(
        VerifiedAccessInstanceIds=[inst_id])["LoggingConfigurations"][0]["AccessLogs"]
    assert again["CloudWatchLogs"]["Enabled"] is True

    with pytest.raises(ClientError) as exc:
        ec2.modify_verified_access_instance_logging_configuration(
            VerifiedAccessInstanceId=inst_id, AccessLogs={"LogVersion": "ocsf-9"})
    assert _error_code(exc) == "InvalidParameterValue"
    assert ec2.describe_verified_access_instance_logging_configurations(
        VerifiedAccessInstanceIds=[inst_id])["LoggingConfigurations"][0]["AccessLogs"]["LogVersion"] == "ocsf-1.0.0-rc.2"

    with pytest.raises(ClientError) as exc:
        ec2.describe_verified_access_instance_logging_configurations(VerifiedAccessInstanceIds=[_MISSING_INSTANCE])
    assert _error_code(exc) == "InvalidVerifiedAccessInstanceId.NotFound"
    with pytest.raises(ClientError) as exc:
        ec2.modify_verified_access_instance_logging_configuration(
            VerifiedAccessInstanceId=_MISSING_INSTANCE, AccessLogs={"S3": {"Enabled": False}})
    assert _error_code(exc) == "InvalidVerifiedAccessInstanceId.NotFound"
    ec2.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)


def test_verified_access_group_and_policy(ec2):
    inst_id = _instance(ec2)
    group = ec2.create_verified_access_group(
        VerifiedAccessInstanceId=inst_id, Description="apps", PolicyDocument=_POLICY,
    )["VerifiedAccessGroup"]
    group_id = group["VerifiedAccessGroupId"]
    assert group_id.startswith("vagr-")
    assert group["VerifiedAccessGroupArn"].endswith(f":verified-access-group/{group_id}")
    assert group["Owner"]

    policy = ec2.get_verified_access_group_policy(VerifiedAccessGroupId=group_id)
    assert policy["PolicyEnabled"] is True
    assert policy["PolicyDocument"] == _POLICY

    # An SSE-only update (what the Terraform group resource sends for
    # sse_configuration) leaves the policy as it was.
    modified = ec2.modify_verified_access_group_policy(
        VerifiedAccessGroupId=group_id,
        SseSpecification={"CustomerManagedKeyEnabled": True,
                          "KmsKeyArn": "arn:aws:kms:us-east-1:000000000000:key/abc"})
    assert modified["SseSpecification"]["CustomerManagedKeyEnabled"] is True
    assert modified["PolicyEnabled"] is True
    assert modified["PolicyDocument"] == _POLICY
    policy = ec2.get_verified_access_group_policy(VerifiedAccessGroupId=group_id)
    assert (policy["PolicyEnabled"], policy["PolicyDocument"]) == (True, _POLICY)

    ec2.modify_verified_access_group_policy(VerifiedAccessGroupId=group_id, PolicyEnabled=False)
    policy = ec2.get_verified_access_group_policy(VerifiedAccessGroupId=group_id)
    assert policy["PolicyEnabled"] is False
    assert "PolicyDocument" not in policy

    listed = ec2.describe_verified_access_groups(VerifiedAccessInstanceId=inst_id)["VerifiedAccessGroups"]
    assert [g["VerifiedAccessGroupId"] for g in listed] == [group_id]

    with pytest.raises(ClientError) as exc:
        ec2.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)
    assert _error_code(exc) == "InvalidParameterValue"
    assert ec2.describe_verified_access_instances(VerifiedAccessInstanceIds=[inst_id])["VerifiedAccessInstances"]

    deleted = ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id)["VerifiedAccessGroup"]
    assert deleted["VerifiedAccessGroupId"] == group_id
    assert deleted["DeletionTime"]
    with pytest.raises(ClientError) as exc:
        ec2.describe_verified_access_groups(VerifiedAccessGroupIds=[group_id])
    assert _error_code(exc) == "InvalidVerifiedAccessGroupId.NotFound"

    with pytest.raises(ClientError) as exc:
        ec2.create_verified_access_group(VerifiedAccessInstanceId=_MISSING_INSTANCE)
    assert _error_code(exc) == "InvalidVerifiedAccessInstanceId.NotFound"
    ec2.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)


def test_verified_access_group_moves_to_another_instance(ec2):
    first, second = _instance(ec2), _instance(ec2)
    group_id = _group(ec2, first)
    ep_id = _lb_endpoint(ec2, group_id)["VerifiedAccessEndpointId"]

    with pytest.raises(ClientError) as exc:
        ec2.modify_verified_access_group(VerifiedAccessGroupId=group_id, VerifiedAccessInstanceId=_MISSING_INSTANCE)
    assert _error_code(exc) == "InvalidVerifiedAccessInstanceId.NotFound"

    moved = ec2.modify_verified_access_group(
        VerifiedAccessGroupId=group_id, VerifiedAccessInstanceId=second)["VerifiedAccessGroup"]
    assert moved["VerifiedAccessInstanceId"] == second
    ep = ec2.describe_verified_access_endpoints(VerifiedAccessEndpointIds=[ep_id])["VerifiedAccessEndpoints"][0]
    assert ep["VerifiedAccessInstanceId"] == second

    ec2.delete_verified_access_endpoint(VerifiedAccessEndpointId=ep_id)
    ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id)
    for inst_id in (first, second):
        ec2.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)


def test_verified_access_load_balancer_endpoint_lifecycle(ec2):
    inst_id = _instance(ec2)
    group_id = _group(ec2, inst_id)
    ep = _lb_endpoint(
        ec2, group_id,
        SecurityGroupIds=["sg-0123456789abcdef0"],
        PolicyDocument=_POLICY,
        TagSpecifications=[{"ResourceType": "verified-access-endpoint",
                            "Tags": [{"Key": "site", "Value": "app"}]}],
    )
    ep_id = ep["VerifiedAccessEndpointId"]
    assert ep_id.startswith("vae-")
    assert ep["Status"]["Code"] == "active"
    assert ep["VerifiedAccessInstanceId"] == inst_id
    assert ep["EndpointDomain"].startswith("app.edge-")
    assert ep["LoadBalancerOptions"]["LoadBalancerArn"] == _LB_ARN
    assert ep["LoadBalancerOptions"]["Port"] == 443
    assert ep["SecurityGroupIds"] == ["sg-0123456789abcdef0"]
    assert ep["Tags"] == [{"Key": "site", "Value": "app"}]
    assert "NetworkInterfaceOptions" not in ep

    assert ec2.get_verified_access_endpoint_policy(VerifiedAccessEndpointId=ep_id)["PolicyDocument"] == _POLICY
    ec2.modify_verified_access_endpoint_policy(
        VerifiedAccessEndpointId=ep_id, PolicyEnabled=True, PolicyDocument="permit(principal, action, resource);")
    assert ec2.get_verified_access_endpoint_policy(
        VerifiedAccessEndpointId=ep_id)["PolicyDocument"] == "permit(principal, action, resource);"
    # The Terraform endpoint resource removes policy_document this way and
    # reads the document back; it must come back empty.
    ec2.modify_verified_access_endpoint_policy(VerifiedAccessEndpointId=ep_id, PolicyEnabled=False)
    policy = ec2.get_verified_access_endpoint_policy(VerifiedAccessEndpointId=ep_id)
    assert policy["PolicyEnabled"] is False
    assert "PolicyDocument" not in policy

    modified = ec2.modify_verified_access_endpoint(
        VerifiedAccessEndpointId=ep_id, Description="web",
        LoadBalancerOptions={"Port": 8443, "SubnetIds": ["subnet-ccc"],
                             "PortRanges": [{"FromPort": 8000, "ToPort": 8100}]},
    )["VerifiedAccessEndpoint"]
    assert modified["Description"] == "web"
    assert modified["LoadBalancerOptions"]["Port"] == 8443
    assert modified["LoadBalancerOptions"]["SubnetIds"] == ["subnet-ccc"]
    assert modified["LoadBalancerOptions"]["PortRanges"] == [{"FromPort": 8000, "ToPort": 8100}]
    assert modified["LoadBalancerOptions"]["LoadBalancerArn"] == _LB_ARN

    # Options for another endpoint type are refused, not dropped.
    with pytest.raises(ClientError) as exc:
        ec2.modify_verified_access_endpoint(
            VerifiedAccessEndpointId=ep_id, Description="ignored", NetworkInterfaceOptions={"Port": 80})
    assert _error_code(exc) == "InvalidParameterValue"
    assert ec2.describe_verified_access_endpoints(
        VerifiedAccessEndpointIds=[ep_id])["VerifiedAccessEndpoints"][0]["Description"] == "web"

    listed = ec2.describe_verified_access_endpoints(VerifiedAccessGroupId=group_id)["VerifiedAccessEndpoints"]
    assert [e["VerifiedAccessEndpointId"] for e in listed] == [ep_id]

    with pytest.raises(ClientError) as exc:
        ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id)
    assert _error_code(exc) == "InvalidParameterValue"
    assert ec2.describe_verified_access_groups(VerifiedAccessGroupIds=[group_id])["VerifiedAccessGroups"]

    deleted = ec2.delete_verified_access_endpoint(VerifiedAccessEndpointId=ep_id)["VerifiedAccessEndpoint"]
    assert deleted["Status"]["Code"] == "deleting"
    assert deleted["DeletionTime"]
    with pytest.raises(ClientError) as exc:
        ec2.describe_verified_access_endpoints(VerifiedAccessEndpointIds=[ep_id])
    assert _error_code(exc) == "InvalidVerifiedAccessEndpointId.NotFound"
    ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id)
    ec2.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)


def test_verified_access_endpoint_moves_to_another_group(ec2):
    first_inst, second_inst = _instance(ec2), _instance(ec2)
    first_group, second_group = _group(ec2, first_inst), _group(ec2, second_inst)
    ep_id = _lb_endpoint(ec2, first_group)["VerifiedAccessEndpointId"]
    moved = ec2.modify_verified_access_endpoint(
        VerifiedAccessEndpointId=ep_id, VerifiedAccessGroupId=second_group)["VerifiedAccessEndpoint"]
    assert (moved["VerifiedAccessGroupId"], moved["VerifiedAccessInstanceId"]) == (second_group, second_inst)
    with pytest.raises(ClientError) as exc:
        ec2.modify_verified_access_endpoint(VerifiedAccessEndpointId=ep_id, VerifiedAccessGroupId="vagr-0000000000000000a")
    assert _error_code(exc) == "InvalidVerifiedAccessGroupId.NotFound"
    assert ec2.describe_verified_access_endpoints(
        VerifiedAccessEndpointIds=[ep_id])["VerifiedAccessEndpoints"][0]["VerifiedAccessGroupId"] == second_group

    ec2.delete_verified_access_endpoint(VerifiedAccessEndpointId=ep_id)
    for group_id in (first_group, second_group):
        ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id)
    for inst_id in (first_inst, second_inst):
        ec2.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)


def test_verified_access_network_interface_endpoint(ec2):
    inst_id = _instance(ec2)
    group_id = _group(ec2, inst_id)
    common = dict(VerifiedAccessGroupId=group_id, EndpointType="network-interface", AttachmentType="vpc",
                  DomainCertificateArn="arn:aws:acm:us-east-1:000000000000:certificate/abc",
                  ApplicationDomain="eni.example.com", EndpointDomainPrefix="eni")
    with pytest.raises(ClientError) as exc:
        ec2.create_verified_access_endpoint(**common)
    assert _error_code(exc) == "MissingParameter"
    with pytest.raises(ClientError) as exc:
        ec2.create_verified_access_endpoint(
            **common, NetworkInterfaceOptions={"NetworkInterfaceId": "eni-0123456789abcdef0"},
            LoadBalancerOptions={"LoadBalancerArn": _LB_ARN})
    assert _error_code(exc) == "InvalidParameterValue"
    assert ec2.describe_verified_access_endpoints(VerifiedAccessGroupId=group_id)["VerifiedAccessEndpoints"] == []

    ep = ec2.create_verified_access_endpoint(
        **common, NetworkInterfaceOptions={"NetworkInterfaceId": "eni-0123456789abcdef0", "Protocol": "http",
                                           "Port": 80})["VerifiedAccessEndpoint"]
    assert ep["EndpointType"] == "network-interface"
    assert ep["NetworkInterfaceOptions"]["NetworkInterfaceId"] == "eni-0123456789abcdef0"
    assert "LoadBalancerOptions" not in ep
    modified = ec2.modify_verified_access_endpoint(
        VerifiedAccessEndpointId=ep["VerifiedAccessEndpointId"], NetworkInterfaceOptions={"Port": 8080},
    )["VerifiedAccessEndpoint"]
    assert modified["NetworkInterfaceOptions"]["Port"] == 8080
    assert modified["NetworkInterfaceOptions"]["NetworkInterfaceId"] == "eni-0123456789abcdef0"

    ec2.delete_verified_access_endpoint(VerifiedAccessEndpointId=ep["VerifiedAccessEndpointId"])
    ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id)
    ec2.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)


def test_verified_access_endpoint_validation(ec2):
    inst_id = _instance(ec2)
    group_id = _group(ec2, inst_id)
    with pytest.raises(ClientError) as exc:
        ec2.create_verified_access_endpoint(
            VerifiedAccessGroupId=group_id, EndpointType="load-balancer", AttachmentType="vpc",
            DomainCertificateArn="arn:c", ApplicationDomain="a.example.com", EndpointDomainPrefix="a")
    assert _error_code(exc) == "MissingParameter"
    with pytest.raises(ClientError) as exc:
        ec2.create_verified_access_endpoint(
            VerifiedAccessGroupId="vagr-0000000000000000a", EndpointType="load-balancer", AttachmentType="vpc")
    assert _error_code(exc) == "InvalidVerifiedAccessGroupId.NotFound"
    for endpoint_type in ("cidr", "rds"):
        with pytest.raises(ClientError) as exc:
            ec2.create_verified_access_endpoint(
                VerifiedAccessGroupId=group_id, EndpointType=endpoint_type, AttachmentType="vpc")
        assert _error_code(exc) == "UnsupportedOperation"
    assert ec2.describe_verified_access_endpoints(VerifiedAccessGroupId=group_id)["VerifiedAccessEndpoints"] == []
    ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id)
    ec2.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)


def test_verified_access_describe_tags_and_tag_calls(ec2):
    inst_id = _instance(ec2)
    group_id = _group(ec2, inst_id)
    ep_id = _lb_endpoint(ec2, group_id)["VerifiedAccessEndpointId"]
    tp_id = _oidc_trust_provider(ec2)["VerifiedAccessTrustProviderId"]
    expected = {
        inst_id: "verified-access-instance",
        group_id: "verified-access-group",
        ep_id: "verified-access-endpoint",
        tp_id: "verified-access-trust-provider",
    }
    ec2.create_tags(Resources=list(expected), Tags=[{"Key": "env", "Value": "dev"}])
    tags = ec2.describe_tags(Filters=[{"Name": "resource-id", "Values": list(expected)}])["Tags"]
    assert {t["ResourceId"]: t["ResourceType"] for t in tags} == expected
    assert ec2.describe_verified_access_groups(
        VerifiedAccessGroupIds=[group_id])["VerifiedAccessGroups"][0]["Tags"] == [{"Key": "env", "Value": "dev"}]

    ec2.delete_tags(Resources=[group_id], Tags=[{"Key": "env"}])
    assert ec2.describe_verified_access_groups(
        VerifiedAccessGroupIds=[group_id])["VerifiedAccessGroups"][0].get("Tags", []) == []

    ec2.delete_verified_access_endpoint(VerifiedAccessEndpointId=ep_id)
    ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id)
    ec2.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)
    ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=tp_id)


def test_verified_access_describe_filters_and_pagination(ec2):
    marker = uuid.uuid4().hex
    tagged = [
        _instance(ec2, TagSpecifications=[{"ResourceType": "verified-access-instance",
                                           "Tags": [{"Key": "run", "Value": marker}]}])
        for _ in range(6)
    ]
    untagged = _instance(ec2)
    by_tag = ec2.describe_verified_access_instances(
        Filters=[{"Name": "tag:run", "Values": [marker]}])["VerifiedAccessInstances"]
    assert sorted(i["VerifiedAccessInstanceId"] for i in by_tag) == sorted(tagged)
    by_value = ec2.describe_verified_access_instances(
        Filters=[{"Name": "tag-value", "Values": [marker]}])["VerifiedAccessInstances"]
    assert len(by_value) == 6

    first = ec2.describe_verified_access_instances(
        Filters=[{"Name": "tag:run", "Values": [marker]}], MaxResults=5)
    assert len(first["VerifiedAccessInstances"]) == 5
    second = ec2.describe_verified_access_instances(
        Filters=[{"Name": "tag:run", "Values": [marker]}], MaxResults=5, NextToken=first["NextToken"])
    assert len(second["VerifiedAccessInstances"]) == 1
    assert "NextToken" not in second
    paged = [i["VerifiedAccessInstanceId"]
             for page in ec2.get_paginator("describe_verified_access_instances").paginate(
                 Filters=[{"Name": "tag:run", "Values": [marker]}], PaginationConfig={"PageSize": 5})
             for i in page["VerifiedAccessInstances"]]
    assert sorted(paged) == sorted(tagged)

    # A filter MiniStack does not apply is refused rather than ignored.
    with pytest.raises(ClientError) as exc:
        ec2.describe_verified_access_instances(Filters=[{"Name": "description", "Values": ["x"]}])
    assert _error_code(exc) == "InvalidParameterValue"

    for inst_id in tagged + [untagged]:
        ec2.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)


def test_verified_access_resources_are_regional():
    east, west = _client("us-east-1"), _client("eu-west-1")
    inst_id = _instance(east)
    group_id = _group(east, inst_id)
    ep_id = _lb_endpoint(east, group_id)["VerifiedAccessEndpointId"]
    tp_id = _oidc_trust_provider(east)["VerifiedAccessTrustProviderId"]
    for call, kwargs, code in (
        (west.describe_verified_access_instances, {"VerifiedAccessInstanceIds": [inst_id]}, "Instance"),
        (west.describe_verified_access_groups, {"VerifiedAccessGroupIds": [group_id]}, "Group"),
        (west.describe_verified_access_endpoints, {"VerifiedAccessEndpointIds": [ep_id]}, "Endpoint"),
        (west.describe_verified_access_trust_providers, {"VerifiedAccessTrustProviderIds": [tp_id]}, "TrustProvider"),
    ):
        with pytest.raises(ClientError) as exc:
            call(**kwargs)
        assert _error_code(exc) == f"InvalidVerifiedAccess{code}Id.NotFound"
    east.delete_verified_access_endpoint(VerifiedAccessEndpointId=ep_id)
    east.delete_verified_access_group(VerifiedAccessGroupId=group_id)
    east.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)
    east.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=tp_id)


def test_verified_access_resources_are_per_account():
    owner, other = _client(), _client(account_id="123456789012")
    inst_id = _instance(owner)
    tp_id = _oidc_trust_provider(owner)["VerifiedAccessTrustProviderId"]
    for call in (
        lambda: other.describe_verified_access_instances(VerifiedAccessInstanceIds=[inst_id]),
        lambda: other.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id),
        lambda: other.attach_verified_access_trust_provider(
            VerifiedAccessInstanceId=inst_id, VerifiedAccessTrustProviderId=tp_id),
    ):
        with pytest.raises(ClientError) as exc:
            call()
        assert _error_code(exc) == "InvalidVerifiedAccessInstanceId.NotFound"
    with pytest.raises(ClientError) as exc:
        other.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=tp_id)
    assert _error_code(exc) == "InvalidVerifiedAccessTrustProviderId.NotFound"
    assert inst_id not in [i["VerifiedAccessInstanceId"]
                           for i in other.describe_verified_access_instances()["VerifiedAccessInstances"]]

    # Nothing in the owning account was changed.
    assert _instance_provider_ids(owner, inst_id) == []
    assert owner.describe_verified_access_trust_providers(
        VerifiedAccessTrustProviderIds=[tp_id])["VerifiedAccessTrustProviders"]
    owner.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)
    owner.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=tp_id)


def test_verified_access_iam_resource_arns():
    from ministack.core.iam_actions import extract_resource_arn

    def arn(params):
        query = {k: [v] for k, v in params.items()}
        return extract_resource_arn("ec2", "POST", "/", {}, b"", query, "us-east-1", "123456789012")

    prefix = "arn:aws:ec2:us-east-1:123456789012:"
    assert arn({"Action": "DeleteVerifiedAccessInstance", "VerifiedAccessInstanceId": "vai-1"}) == \
        prefix + "verified-access-instance/vai-1"
    assert arn({"Action": "ModifyVerifiedAccessTrustProvider", "VerifiedAccessTrustProviderId": "vatp-1"}) == \
        prefix + "verified-access-trust-provider/vatp-1"
    assert arn({"Action": "CreateVerifiedAccessEndpoint", "VerifiedAccessGroupId": "vagr-1",
                "SecurityGroupId.1": "sg-1"}) == prefix + "verified-access-group/vagr-1"
    assert arn({"Action": "GetVerifiedAccessEndpointPolicy", "VerifiedAccessEndpointId": "vae-1"}) == \
        prefix + "verified-access-endpoint/vae-1"
    assert arn({"Action": "DescribeVerifiedAccessGroups", "VerifiedAccessInstanceId": "vai-1"}) == "*"


@pytest.mark.auth_contract
@pytest.mark.parametrize("permission", ["none", "allow", "other-resource", "explicit-deny"])
def test_verified_access_modify_permission_contract(auth_enabled, iam_user, permission):
    admin = make_client("ec2")
    inst_id = _instance(admin, Description="before")
    resource = f"arn:aws:ec2:us-east-1:000000000000:verified-access-instance/{inst_id}"
    statements = []
    if permission != "none":
        target = resource.replace(inst_id, "vai-00000000000000000") if permission == "other-resource" else resource
        statements.append({"Effect": "Allow", "Action": "ec2:ModifyVerifiedAccessInstance", "Resource": target})
    if permission == "explicit-deny":
        statements.append({"Effect": "Deny", "Action": "ec2:ModifyVerifiedAccessInstance", "Resource": resource})
    policy = {"Version": "2012-10-17", "Statement": statements} if statements else None
    client = iam_user(policy=policy).client("ec2")
    try:
        if auth_enabled and permission != "allow":
            with pytest.raises(ClientError) as exc:
                client.modify_verified_access_instance(VerifiedAccessInstanceId=inst_id, Description="after")
            assert _error_code(exc) == "UnauthorizedOperation"
            expected = "before"
        else:
            client.modify_verified_access_instance(VerifiedAccessInstanceId=inst_id, Description="after")
            expected = "after"
        assert admin.describe_verified_access_instances(
            VerifiedAccessInstanceIds=[inst_id])["VerifiedAccessInstances"][0]["Description"] == expected
    finally:
        admin.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)


@pytest.mark.auth_contract
def test_verified_access_create_permission_contract(auth_enabled, iam_user):
    allowed = iam_user(policy={"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["ec2:CreateVerifiedAccessInstance", "ec2:DeleteVerifiedAccessInstance"],
         "Resource": "*"}]}).client("ec2")
    denied = iam_user().client("ec2")
    inst_id = _instance(allowed)
    allowed.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)
    if auth_enabled:
        with pytest.raises(ClientError) as exc:
            denied.create_verified_access_instance()
        assert _error_code(exc) == "UnauthorizedOperation"
    else:
        inst_id = _instance(denied)
        denied.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)

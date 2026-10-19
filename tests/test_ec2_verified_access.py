"""EC2 Verified Access control plane: the calls the Terraform aws_verifiedaccess_* resources make."""

import pytest
from botocore.exceptions import ClientError

_POLICY = 'permit(principal, action, resource) when { context.oidc.email like "*@example.com" };'


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


def _error_code(exc):
    return exc.value.response["Error"]["Code"]


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

    ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=tp_id)
    with pytest.raises(ClientError) as exc:
        ec2.describe_verified_access_trust_providers(VerifiedAccessTrustProviderIds=[tp_id])
    assert _error_code(exc) == "InvalidVerifiedAccessTrustProviderId.NotFound"


def test_verified_access_trust_provider_requires_matching_subtype(ec2):
    with pytest.raises(ClientError) as exc:
        ec2.create_verified_access_trust_provider(
            TrustProviderType="user", DeviceTrustProviderType="jamf", PolicyReferenceName="x")
    assert _error_code(exc) == "InvalidParameterValue"


def test_verified_access_instance_attach_detach_and_tags(ec2):
    inst = ec2.create_verified_access_instance(
        Description="platform",
        TagSpecifications=[{"ResourceType": "verified-access-instance",
                            "Tags": [{"Key": "Name", "Value": "platform-va"}]}],
    )["VerifiedAccessInstance"]
    inst_id = inst["VerifiedAccessInstanceId"]
    assert inst_id.startswith("vai-")
    assert inst["VerifiedAccessTrustProviders"] == []
    assert inst["FipsEnabled"] is False
    tp_id = _oidc_trust_provider(ec2)["VerifiedAccessTrustProviderId"]

    attached = ec2.attach_verified_access_trust_provider(
        VerifiedAccessInstanceId=inst_id, VerifiedAccessTrustProviderId=tp_id)
    assert attached["VerifiedAccessTrustProvider"]["VerifiedAccessTrustProviderId"] == tp_id
    providers = attached["VerifiedAccessInstance"]["VerifiedAccessTrustProviders"]
    assert [(p["VerifiedAccessTrustProviderId"], p["UserTrustProviderType"]) for p in providers] == [(tp_id, "oidc")]

    # The Terraform attachment resource reads through DescribeVerifiedAccessInstances.
    described = ec2.describe_verified_access_instances(VerifiedAccessInstanceIds=[inst_id])
    assert described["VerifiedAccessInstances"][0]["VerifiedAccessTrustProviders"][0][
        "VerifiedAccessTrustProviderId"] == tp_id

    with pytest.raises(ClientError) as exc:
        ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=tp_id)
    assert _error_code(exc) == "InvalidParameterValue"

    tags = ec2.describe_tags(Filters=[{"Name": "resource-id", "Values": [inst_id]}])["Tags"]
    assert tags[0]["ResourceType"] == "verified-access-instance"

    ec2.detach_verified_access_trust_provider(
        VerifiedAccessInstanceId=inst_id, VerifiedAccessTrustProviderId=tp_id)
    assert ec2.describe_verified_access_instances(
        VerifiedAccessInstanceIds=[inst_id])["VerifiedAccessInstances"][0]["VerifiedAccessTrustProviders"] == []

    ec2.modify_verified_access_instance(VerifiedAccessInstanceId=inst_id, Description="changed")
    assert ec2.describe_verified_access_instances(
        VerifiedAccessInstanceIds=[inst_id])["VerifiedAccessInstances"][0]["Description"] == "changed"

    ec2.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)
    ec2.delete_verified_access_trust_provider(VerifiedAccessTrustProviderId=tp_id)
    with pytest.raises(ClientError) as exc:
        ec2.describe_verified_access_instances(VerifiedAccessInstanceIds=[inst_id])
    assert _error_code(exc) == "InvalidVerifiedAccessInstanceId.NotFound"


def test_verified_access_one_trust_provider_per_type(ec2):
    inst_id = ec2.create_verified_access_instance()["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
    first = _oidc_trust_provider(ec2)["VerifiedAccessTrustProviderId"]
    second = _oidc_trust_provider(ec2)["VerifiedAccessTrustProviderId"]
    ec2.attach_verified_access_trust_provider(VerifiedAccessInstanceId=inst_id, VerifiedAccessTrustProviderId=first)
    with pytest.raises(ClientError) as exc:
        ec2.attach_verified_access_trust_provider(VerifiedAccessInstanceId=inst_id, VerifiedAccessTrustProviderId=second)
    assert _error_code(exc) == "InvalidParameterValue"


def test_verified_access_instance_logging_configuration(ec2):
    inst_id = ec2.create_verified_access_instance()["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
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
    assert modified["S3"]["DeliveryStatus"]["Code"] == "success"
    assert modified["CloudWatchLogs"]["LogGroup"] == "/aws/verified-access/platform"
    assert modified["KinesisDataFirehose"]["Enabled"] is False
    assert modified["LogVersion"] == "ocsf-1.0.0-rc.2"
    assert modified["IncludeTrustContext"] is True

    again = ec2.describe_verified_access_instance_logging_configurations(
        VerifiedAccessInstanceIds=[inst_id])["LoggingConfigurations"][0]["AccessLogs"]
    assert again["CloudWatchLogs"]["Enabled"] is True

    with pytest.raises(ClientError) as exc:
        ec2.describe_verified_access_instance_logging_configurations(VerifiedAccessInstanceIds=["vai-0000000000000000a"])
    assert _error_code(exc) == "InvalidVerifiedAccessInstanceId.NotFound"


def test_verified_access_group_and_policy(ec2):
    inst_id = ec2.create_verified_access_instance()["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
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

    ec2.modify_verified_access_group_policy(VerifiedAccessGroupId=group_id, PolicyEnabled=False)
    assert ec2.get_verified_access_group_policy(VerifiedAccessGroupId=group_id)["PolicyEnabled"] is False

    listed = ec2.describe_verified_access_groups(VerifiedAccessInstanceId=inst_id)["VerifiedAccessGroups"]
    assert [g["VerifiedAccessGroupId"] for g in listed] == [group_id]

    with pytest.raises(ClientError) as exc:
        ec2.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)
    assert _error_code(exc) == "InvalidParameterValue"

    ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id)
    with pytest.raises(ClientError) as exc:
        ec2.describe_verified_access_groups(VerifiedAccessGroupIds=[group_id])
    assert _error_code(exc) == "InvalidVerifiedAccessGroupId.NotFound"

    with pytest.raises(ClientError) as exc:
        ec2.create_verified_access_group(VerifiedAccessInstanceId="vai-0000000000000000a")
    assert _error_code(exc) == "InvalidVerifiedAccessInstanceId.NotFound"


def test_verified_access_load_balancer_endpoint_lifecycle(ec2):
    inst_id = ec2.create_verified_access_instance()["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
    group_id = ec2.create_verified_access_group(
        VerifiedAccessInstanceId=inst_id)["VerifiedAccessGroup"]["VerifiedAccessGroupId"]
    lb_arn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/web/0123456789abcdef"
    ep = ec2.create_verified_access_endpoint(
        VerifiedAccessGroupId=group_id,
        EndpointType="load-balancer",
        AttachmentType="vpc",
        DomainCertificateArn="arn:aws:acm:us-east-1:000000000000:certificate/abc",
        ApplicationDomain="app.example.com",
        EndpointDomainPrefix="app",
        SecurityGroupIds=["sg-0123456789abcdef0"],
        LoadBalancerOptions={"Protocol": "https", "Port": 443, "LoadBalancerArn": lb_arn,
                             "SubnetIds": ["subnet-aaa", "subnet-bbb"]},
        PolicyDocument=_POLICY,
        TagSpecifications=[{"ResourceType": "verified-access-endpoint",
                            "Tags": [{"Key": "site", "Value": "app"}]}],
    )["VerifiedAccessEndpoint"]
    ep_id = ep["VerifiedAccessEndpointId"]
    assert ep_id.startswith("vae-")
    assert ep["Status"]["Code"] == "active"
    assert ep["VerifiedAccessInstanceId"] == inst_id
    assert ep["EndpointDomain"].startswith("app.edge-")
    assert ep["EndpointDomain"].endswith(".amazonaws.com")
    assert ep["LoadBalancerOptions"]["LoadBalancerArn"] == lb_arn
    assert ep["LoadBalancerOptions"]["Port"] == 443
    assert ep["LoadBalancerOptions"]["SubnetIds"] == ["subnet-aaa", "subnet-bbb"]
    assert ep["SecurityGroupIds"] == ["sg-0123456789abcdef0"]
    assert ep["Tags"] == [{"Key": "site", "Value": "app"}]

    assert ec2.get_verified_access_endpoint_policy(VerifiedAccessEndpointId=ep_id)["PolicyDocument"] == _POLICY
    ec2.modify_verified_access_endpoint_policy(
        VerifiedAccessEndpointId=ep_id, PolicyEnabled=True, PolicyDocument="permit(principal, action, resource);")
    assert ec2.get_verified_access_endpoint_policy(
        VerifiedAccessEndpointId=ep_id)["PolicyDocument"] == "permit(principal, action, resource);"

    modified = ec2.modify_verified_access_endpoint(
        VerifiedAccessEndpointId=ep_id, Description="web",
        LoadBalancerOptions={"Port": 8443, "SubnetIds": ["subnet-ccc"]},
    )["VerifiedAccessEndpoint"]
    assert modified["Description"] == "web"
    assert modified["LoadBalancerOptions"]["Port"] == 8443
    assert modified["LoadBalancerOptions"]["SubnetIds"] == ["subnet-ccc"]
    assert modified["LoadBalancerOptions"]["LoadBalancerArn"] == lb_arn

    listed = ec2.describe_verified_access_endpoints(VerifiedAccessGroupId=group_id)["VerifiedAccessEndpoints"]
    assert [e["VerifiedAccessEndpointId"] for e in listed] == [ep_id]

    with pytest.raises(ClientError) as exc:
        ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id)
    assert _error_code(exc) == "InvalidParameterValue"

    deleted = ec2.delete_verified_access_endpoint(VerifiedAccessEndpointId=ep_id)["VerifiedAccessEndpoint"]
    assert deleted["Status"]["Code"] == "deleting"
    with pytest.raises(ClientError) as exc:
        ec2.describe_verified_access_endpoints(VerifiedAccessEndpointIds=[ep_id])
    assert _error_code(exc) == "InvalidVerifiedAccessEndpointId.NotFound"
    ec2.delete_verified_access_group(VerifiedAccessGroupId=group_id)
    ec2.delete_verified_access_instance(VerifiedAccessInstanceId=inst_id)


def test_verified_access_endpoint_validation(ec2):
    inst_id = ec2.create_verified_access_instance()["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
    group_id = ec2.create_verified_access_group(
        VerifiedAccessInstanceId=inst_id)["VerifiedAccessGroup"]["VerifiedAccessGroupId"]
    with pytest.raises(ClientError) as exc:
        ec2.create_verified_access_endpoint(
            VerifiedAccessGroupId=group_id, EndpointType="load-balancer", AttachmentType="vpc",
            DomainCertificateArn="arn:c", ApplicationDomain="a.example.com", EndpointDomainPrefix="a")
    assert _error_code(exc) == "MissingParameter"
    with pytest.raises(ClientError) as exc:
        ec2.create_verified_access_endpoint(
            VerifiedAccessGroupId="vagr-0000000000000000a", EndpointType="load-balancer", AttachmentType="vpc")
    assert _error_code(exc) == "InvalidVerifiedAccessGroupId.NotFound"
    with pytest.raises(ClientError) as exc:
        ec2.create_verified_access_endpoint(
            VerifiedAccessGroupId=group_id, EndpointType="cidr", AttachmentType="vpc")
    assert _error_code(exc) == "UnsupportedOperation"


def test_verified_access_resources_are_regional(ec2):
    import boto3
    inst_id = ec2.create_verified_access_instance()["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
    other = boto3.client(
        "ec2", region_name="eu-west-1", endpoint_url=ec2.meta.endpoint_url,
        aws_access_key_id="test", aws_secret_access_key="test")
    with pytest.raises(ClientError) as exc:
        other.describe_verified_access_instances(VerifiedAccessInstanceIds=[inst_id])
    assert _error_code(exc) == "InvalidVerifiedAccessInstanceId.NotFound"

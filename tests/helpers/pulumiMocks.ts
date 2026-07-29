import * as pulumi from "@pulumi/pulumi";
import {
  compileAwsApplyLaneIamConstraint,
  createReferenceAwsBootstrapAccessPlan,
} from "../../src/adapters/aws";

export function testDatabaseIamRoleConstraint(accountName = "platform-dev") {
  return compileAwsApplyLaneIamConstraint(
    createReferenceAwsBootstrapAccessPlan(),
    accountName,
    "database",
  );
}

export interface CapturedResource {
  type: string;
  name: string;
  inputs: Record<string, any>;
}

export interface CapturedCall {
  token: string;
  inputs: Record<string, any>;
}

export async function installPulumiMocks() {
  const resources: CapturedResource[] = [];
  const calls: CapturedCall[] = [];
  pulumi.runtime.setConfig("aws:region", "us-east-1");

  await pulumi.runtime.setMocks(
    {
      newResource(
        args: pulumi.runtime.MockResourceArgs,
      ): pulumi.runtime.MockResourceResult {
        resources.push({
          type: args.type,
          name: args.name,
          inputs: args.inputs,
        });

        const id =
          args.type === "aws:ec2/vpcEndpoint:VpcEndpoint"
            ? "vpce-0123456789abcdef0"
            : `${args.name}_id`;
        return {
          id,
          state: {
            ...args.inputs,
            id,
            arn:
              args.type === "aws:rds/proxy:Proxy"
                ? "arn:aws:rds:us-east-1:111111111111:db-proxy:prx-0123456789abcdef0"
                : mockArn(args.type, args.name),
            name: args.inputs.name ?? args.name,
            keyId: args.type === "aws:kms/key:Key" ? id : args.inputs.keyId,
            clusterResourceId:
              args.type === "aws:rds/cluster:Cluster"
                ? `cluster-${args.name}`
                : args.inputs.clusterResourceId,
            associationId:
              args.type ===
              "aws:eks/podIdentityAssociation:PodIdentityAssociation"
                ? `${args.name}_associationId`
                : args.inputs.associationId,
            masterUserSecrets:
              args.type === "aws:rds/cluster:Cluster"
                ? [
                    {
                      kmsKeyId: args.inputs.masterUserSecretKmsKeyId,
                      secretArn:
                        "arn:aws:secretsmanager:us-east-1:111111111111:secret:rds!cluster-mock",
                      secretStatus: "active",
                    },
                  ]
                : args.inputs.masterUserSecrets,
            endpoint:
              args.type === "aws:eks/cluster:Cluster"
                ? `https://${args.name}.eks.local`
                : args.type === "aws:rds/proxy:Proxy"
                  ? `${args.name}.proxy.us-east-1.rds.amazonaws.com`
                  : args.type === "aws:rds/cluster:Cluster"
                    ? `${args.name}.cluster.us-east-1.rds.amazonaws.com`
                    : args.inputs.endpoint,
            certificateAuthority:
              args.type === "aws:eks/cluster:Cluster"
                ? { data: "test-certificate-authority" }
                : args.inputs.certificateAuthority,
            firewallStatuses:
              args.type === "aws:networkfirewall/firewall:Firewall"
                ? [
                    {
                      syncStates: [
                        endpointState("us-east-1a", "vpce-fw-a"),
                        endpointState("us-east-1b", "vpce-fw-b"),
                        endpointState("us-east-1c", "vpce-fw-c"),
                        endpointState("us-east-1d", "vpce-fw-d"),
                      ],
                      transitGatewayAttachmentSyncStates: [],
                    },
                  ]
                : args.inputs.firewallStatuses,
            domainValidationOptions:
              args.type === "aws:acm/certificate:Certificate"
                ? [
                    args.inputs.domainName,
                    ...(args.inputs.subjectAlternativeNames ?? []),
                  ].map((domain: string) => ({
                    domainName: domain,
                    resourceRecordName: `_acm-${domain}.`,
                    resourceRecordType: "CNAME",
                    resourceRecordValue: `_acm-${domain}-validation.acm.aws`,
                  }))
                : args.inputs.domainValidationOptions,
            domainName:
              args.type === "aws:cloudfront/distribution:Distribution"
                ? `${args.name}.cloudfront.net`
                : args.inputs.domainName,
            hostedZoneId:
              args.type === "aws:cloudfront/distribution:Distribution"
                ? "Z2FDTNDATAQYW2"
                : args.inputs.hostedZoneId,
            bucketDomainName:
              args.type === "aws:s3/bucket:Bucket"
                ? `${args.inputs.bucket ?? args.name}.s3.amazonaws.com`
                : args.inputs.bucketDomainName,
            fqdn:
              args.type === "aws:route53/record:Record"
                ? `${args.inputs.name}.example.com`
                : args.inputs.fqdn,
            roots:
              args.type === "aws:organizations/organization:Organization"
                ? [
                    {
                      id: "r-root",
                      arn: "arn:aws:organizations::111111111111:root/o-example/r-root",
                      name: "Root",
                    },
                  ]
                : args.inputs.roots,
            outputs:
              args.type === "pulumi:pulumi:StackReference"
                ? {
                    transitGatewayId: "tgw-shared",
                    spokeTransitGatewayRouteTableId: "tgw-rtb-spoke",
                    egressTransitGatewayRouteTableId: "tgw-rtb-egress",
                    egressPublicRouteTableIds: [
                      "rtb-public-a",
                      "rtb-public-b",
                      "rtb-public-c",
                    ],
                    egressFirewallRouteTableIds: [
                      "rtb-firewall-a",
                      "rtb-firewall-b",
                      "rtb-firewall-c",
                    ],
                    egressFirewallEndpointIdsForPublicRoutes: [
                      "vpce-fw-a",
                      "vpce-fw-b",
                      "vpce-fw-c",
                    ],
                    spokeTransitGatewayAttachmentId: "tgw-attach-spoke",
                    spokeName: "execution-shared-net",
                    spokeCidr: "10.10.0.0/16",
                    spokeZoneId: "execution-shared",
                    spokeNetworkDomainId: "execution-shared-net",
                    logArchiveBucketName: "audit-logs-bucket",
                    logArchiveKmsKeyArn:
                      "arn:aws:kms:us-east-1:111111111111:key/log-archive",
                    logArchiveOrganizationTrailName: "deus-organization-trail",
                    logArchiveCloudTrailSourceAccountId: "111111111111",
                    organizationAccountIds: {
                      "security-tooling": "111111111112",
                      "log-archive": "111111111113",
                      network: "111111111114",
                      "shared-services": "111111111115",
                      "platform-dev": "111111111116",
                      "execution-dev": "111111111117",
                      "platform-staging": "111111111118",
                      "execution-staging": "111111111119",
                      "platform-prod": "111111111120",
                      "execution-prod": "111111111121",
                    },
                    eksClusters: {
                      "platform-dev": {
                        name: "platform-dev",
                        endpoint: "https://platform-dev.eks.local",
                        certificateAuthority: {
                          data: "test-certificate-authority",
                        },
                      },
                      "execution-dev": {
                        name: "execution-dev",
                        endpoint: "https://execution-dev.eks.local",
                        certificateAuthority: {
                          data: "test-certificate-authority",
                        },
                      },
                    },
                  }
                : args.inputs.outputs,
          },
        };
      },
      call(args: pulumi.runtime.MockCallArgs): pulumi.runtime.MockCallResult {
        calls.push({
          token: args.token,
          inputs: args.inputs,
        });

        if (args.token.includes("getAvailabilityZones")) {
          return {
            names: ["us-east-1a", "us-east-1b", "us-east-1c", "us-east-1d"],
            zoneIds: ["use1-az1", "use1-az2", "use1-az3", "use1-az4"],
          };
        }

        if (args.token.includes("getOrganization")) {
          return {
            id: "o-example",
            arn: "arn:aws:organizations::111111111111:organization/o-example",
            featureSet: "ALL",
            masterAccountArn:
              "arn:aws:organizations::111111111111:account/o-example/111111111111",
            masterAccountEmail: "aws-management@example.com",
            masterAccountId: "111111111111",
            masterAccountName: "management",
            accounts: [],
            nonMasterAccounts: [],
            awsServiceAccessPrincipals: [],
            enabledPolicyTypes: ["SERVICE_CONTROL_POLICY"],
            roots: [
              {
                id: "r-root",
                arn: "arn:aws:organizations::111111111111:root/o-example/r-root",
                name: "Root",
              },
            ],
          };
        }

        if (args.token.includes("getCallerIdentity")) {
          return {
            accountId: "111111111111",
            arn: "arn:aws:iam::111111111111:root",
            id: "111111111111",
            userId: "AIDAEXAMPLE",
          };
        }

        if (args.token.includes("getPartition")) {
          return {
            partition: "aws",
            dnsSuffix: "amazonaws.com",
            reverseDnsPrefix: "com.amazonaws",
          };
        }

        if (args.token.includes("getRegion")) {
          return {
            name: "us-east-1",
            description: "US East (N. Virginia)",
          };
        }

        if (args.token.includes("getInstances")) {
          return {
            arns: ["arn:aws:sso:::instance/ssoins-1234567890abcdef"],
            identityStoreIds: ["d-1234567890"],
          };
        }

        if (args.token.includes("getGroup")) {
          return {
            groupId: "group-existing",
            identityStoreId: args.inputs.identityStoreId,
            displayName:
              args.inputs.alternateIdentifier?.uniqueAttribute
                ?.attributeValue ??
              args.inputs.displayName ??
              "Existing Group",
          };
        }

        if (args.token.includes("getRoles")) {
          const match = /^\^AWSReservedSSO_(.+)_\[A-Fa-f0-9\]\{16\}\$$/.exec(
            args.inputs.nameRegex ?? "",
          );
          const permissionSetName =
            match?.[1]?.replace(/\\(.)/g, "$1") ?? "Unknown";
          const roleName = `AWSReservedSSO_${permissionSetName}_0123456789abcdef`;
          return {
            arns: [
              `arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/us-east-1/${roleName}`,
            ],
            names: [roleName],
            nameRegex: args.inputs.nameRegex,
            pathPrefix: args.inputs.pathPrefix,
            id: "mock-identity-center-roles",
          };
        }

        return args.inputs;
      },
    },
    "secure-saas-infra",
    "unit",
    false,
    "deus",
  );

  return { resources, calls };
}

export async function flushPulumiMocks() {
  for (let index = 0; index < 10; index++) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

export function resourcesOfType(resources: CapturedResource[], type: string) {
  return resources.filter((resource) => resource.type === type);
}

function endpointState(availabilityZone: string, endpointId: string) {
  return {
    availabilityZone,
    attachments: [{ endpointId, subnetId: `subnet-${availabilityZone}` }],
  };
}

function mockArn(type: string, name: string) {
  if (type === "aws:kms/key:Key") {
    return "arn:aws:kms:us-east-1:111111111111:key/12345678-1234-1234-1234-123456789abc";
  }
  if (type === "aws:eks/cluster:Cluster") {
    return `arn:aws:eks:us-east-1:111111111111:cluster/${name}`;
  }
  const service = type.split(":")[1]?.split("/")[0] ?? "mock";
  return `arn:aws:${service}:us-east-1:111111111111:${name}`;
}

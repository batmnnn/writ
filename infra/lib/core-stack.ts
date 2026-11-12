import { Aws, CfnOutput, Duration, RemovalPolicy, SecretValue, Stack, type StackProps, Tags } from "aws-cdk-lib";
import {
  BlockDeviceVolume,
  CfnEIP,
  CfnEIPAssociation,
  EbsDeviceVolumeType,
  GatewayVpcEndpointAwsService,
  HttpTokens,
  Instance,
  InstanceType,
  InterfaceVpcEndpointAwsService,
  IpAddresses,
  MachineImage,
  Peer,
  Port,
  SecurityGroup,
  SubnetType,
  UserData,
  Vpc,
} from "aws-cdk-lib/aws-ec2";
import { ArnPrincipal, Effect, ManagedPolicy, PolicyDocument, PolicyStatement, Role, ServicePrincipal } from "aws-cdk-lib/aws-iam";
import { Key, KeySpec, KeyUsage } from "aws-cdk-lib/aws-kms";
import { BlockPublicAccess, Bucket, BucketEncryption, ObjectLockRetention } from "aws-cdk-lib/aws-s3";
import { Secret } from "aws-cdk-lib/aws-secretsmanager";
import type { Construct } from "constructs";

export interface CoreStackProps extends StackProps {
  /** SHA384 of the enclave image, 96 hex chars. Passed as -c pcr0=. */
  pcr0: string;
  /** Amazon Linux 2023 x86_64 AMI in us-west-2. Passed as -c ami= so synth needs no AWS API calls. */
  ami: string;
}

/** A literal name, so the key policy can name the role without a CloudFormation cycle. */
export const HOST_ROLE_NAME = "writ-enclave-host";

/**
 * Hosts baked into the instance user data. Port 443 only.
 * Adding a host here replaces the EC2 instance: CloudFormation replaces an instance when user data changes.
 * The running host's allowlist is enclave/parent/vsock-proxy.yaml, copied onto /etc/nitro_enclaves/vsock-proxy.yaml.
 * Staging ACME is in that file and in EGRESS_ALLOWLIST, not here, so a PCR0 deploy does not destroy the host.
 */
export const VSOCK_ALLOWLIST = [
  "api.sandbox.airwallex.com",
  "kms.us-west-2.amazonaws.com",
  "s3.us-west-2.amazonaws.com",
  "secretsmanager.us-west-2.amazonaws.com",
  "acme-v02.api.letsencrypt.org",
] as const;

/**
 * What the account root may do on a Writ key. It is a short list on purpose.
 * Left out: kms:Decrypt, kms:GenerateDataKey*, kms:ReEncrypt* (ReEncryptFrom reads plaintext
 * into a key the caller picks), kms:CreateGrant (a grant can carry Decrypt with no attestation),
 * kms:Sign. A root principal statement also enables IAM policies, but only for these actions.
 */
function manageStatement(account: string, withEncrypt: boolean): PolicyStatement {
  return new PolicyStatement({
    sid: withEncrypt ? "ManageAndEncrypt" : "Manage",
    principals: [new ArnPrincipal(`arn:aws:iam::${account}:root`)],
    actions: [
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:GetPublicKey",
      "kms:ListAliases",
      "kms:ListResourceTags",
      "kms:ListKeyPolicies",
      "kms:CreateAlias",
      "kms:UpdateAlias",
      "kms:DeleteAlias",
      "kms:EnableKey",
      "kms:DisableKey",
      "kms:EnableKeyRotation",
      "kms:DisableKeyRotation",
      "kms:PutKeyPolicy",
      "kms:UpdateKeyDescription",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion",
      ...(withEncrypt ? ["kms:Encrypt"] : []),
    ],
    resources: ["*"],
  });
}

export class CoreStack extends Stack {
  readonly vpc: Vpc;

  constructor(scope: Construct, id: string, props: CoreStackProps) {
    super(scope, id, props);
    Tags.of(this).add("project", "writ");
    // Aws.ACCOUNT_ID is a CloudFormation token. No account id is written into the repo.
    const account = Aws.ACCOUNT_ID;
    const hostRoleArn = `arn:aws:iam::${account}:role/${HOST_ROLE_NAME}`;

    this.vpc = new Vpc(this, "Vpc", {
      ipAddresses: IpAddresses.cidr("10.42.0.0/16"),
      availabilityZones: ["us-west-2a", "us-west-2b"],
      natGateways: 0,
      subnetConfiguration: [
        { name: "public", subnetType: SubnetType.PUBLIC, cidrMask: 24 },
        { name: "isolated", subnetType: SubnetType.PRIVATE_ISOLATED, cidrMask: 24 },
      ],
    });
    this.vpc.addGatewayEndpoint("S3", {
      service: GatewayVpcEndpointAwsService.S3,
      subnets: [{ subnetType: SubnetType.PUBLIC }, { subnetType: SubnetType.PRIVATE_ISOLATED }],
    });

    const isolated = { subnetType: SubnetType.PRIVATE_ISOLATED };
    const endpointSg = new SecurityGroup(this, "EndpointSg", {
      vpc: this.vpc,
      description: "Interface endpoints accept HTTPS from the VPC",
      allowAllOutbound: false,
    });
    endpointSg.addIngressRule(Peer.ipv4(this.vpc.vpcCidrBlock), Port.tcp(443), "HTTPS from the VPC");
    const endpoints = [
      ["Kms", InterfaceVpcEndpointAwsService.KMS],
      ["Secrets", InterfaceVpcEndpointAwsService.SECRETS_MANAGER],
      ["Ssm", InterfaceVpcEndpointAwsService.SSM],
      ["SsmMessages", InterfaceVpcEndpointAwsService.SSM_MESSAGES],
      ["Ec2Messages", InterfaceVpcEndpointAwsService.EC2_MESSAGES],
      ["Ecr", InterfaceVpcEndpointAwsService.ECR],
      ["EcrDocker", InterfaceVpcEndpointAwsService.ECR_DOCKER],
      ["Logs", InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS],
      ["Bedrock", InterfaceVpcEndpointAwsService.BEDROCK_RUNTIME],
    ] as const;
    for (const [name, service] of endpoints) {
      this.vpc.addInterfaceEndpoint(name, {
        service,
        subnets: isolated,
        securityGroups: [endpointSg],
        open: false,
        privateDnsEnabled: true,
        lookupSupportedAzs: false,
      });
    }

    const bucket = new Bucket(this, "Ledger", {
      bucketName: `writ-ledger-${account}`,
      versioned: true,
      objectLockEnabled: true,
      objectLockDefaultRetention: ObjectLockRetention.compliance(Duration.days(30)),
      removalPolicy: RemovalPolicy.RETAIN,
      autoDeleteObjects: false,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      encryption: BucketEncryption.S3_MANAGED,
    });

    const hostRole = new Role(this, "HostRole", {
      roleName: HOST_ROLE_NAME,
      assumedBy: new ServicePrincipal("ec2.amazonaws.com"),
      description: "Enclave host. Holds ciphertext and relays bytes. Cannot decrypt and cannot delete the ledger.",
      managedPolicies: [ManagedPolicy.fromAwsManagedPolicyName("AmazonSSMManagedInstanceCore")],
    });

    // The bucket policy names the role, and S3 rejects a policy that names a missing principal.
    bucket.addToResourcePolicy(
      new PolicyStatement({
        sid: "DenyHostLedgerDelete",
        effect: Effect.DENY,
        principals: [new ArnPrincipal(hostRoleArn)],
        actions: ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObjectRetention", "s3:PutBucketObjectLockConfiguration"],
        resources: [bucket.bucketArn, bucket.arnForObjects("*")],
      }),
    );
    bucket.policy?.node.addDependency(hostRole);

    // Decrypt and GenerateDataKey go to one role, and only with the enclave image hash.
    // The role has no reference to the key, so the key may depend on the role (no cycle).
    const devKey = new Key(this, "WritDev", {
      alias: "alias/writ-dev",
      description: "Seals the Airwallex API key. Decrypt only for the published enclave image.",
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN,
      policy: new PolicyDocument({
        statements: [
          manageStatement(account, true),
          new PolicyStatement({
            sid: "EnclaveDecryptOnly",
            principals: [new ArnPrincipal(hostRoleArn)],
            actions: ["kms:Decrypt", "kms:GenerateDataKey"],
            resources: ["*"],
            conditions: {
              StringEqualsIgnoreCase: { "kms:RecipientAttestation:ImageSha384": props.pcr0 },
            },
          }),
        ],
      }),
    });
    devKey.node.addDependency(hostRole);

    const taintKey = new Key(this, "TaintSigner", {
      alias: "alias/writ-taint-signer",
      description: "Signs taint events. Only the taint interceptor role may Sign.",
      keySpec: KeySpec.ECC_NIST_P256,
      keyUsage: KeyUsage.SIGN_VERIFY,
      removalPolicy: RemovalPolicy.RETAIN,
      policy: new PolicyDocument({
        statements: [
          manageStatement(account, false),
          // The role is created by WritAgent. KMS refuses a principal that does not exist yet.
          new PolicyStatement({
            sid: "InterceptorSignOnly",
            effect: Effect.ALLOW,
            principals: [new ArnPrincipal(`arn:aws:iam::${account}:role/writ-taint-interceptor`)],
            actions: ["kms:Sign"],
            resources: ["*"],
            conditions: { StringEquals: { "kms:SigningAlgorithm": "ECDSA_SHA_256", "kms:MessageType": "RAW" } },
          }),
        ],
      }),
    });

    const sealed = new Secret(this, "AirwallexKeyCipher", {
      secretName: "writ/airwallex/api-key.kms",
      description: "KMS ciphertext of the Airwallex API key. Not the key itself.",
      secretStringValue: SecretValue.unsafePlainText('{"ciphertext":"SEAL_ME"}'),
    });

    hostRole.addToPolicy(
      new PolicyStatement({
        sid: "ReadSealedKey",
        actions: ["secretsmanager:GetSecretValue"],
        resources: [sealed.secretArn],
      }),
    );
    hostRole.addToPolicy(
      new PolicyStatement({
        sid: "LedgerWrite",
        actions: ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket", "s3:ListBucketVersions"],
        resources: [bucket.bucketArn, bucket.arnForObjects("*")],
      }),
    );
    hostRole.addToPolicy(
      new PolicyStatement({
        sid: "DenyLedgerDelete",
        effect: Effect.DENY,
        actions: ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObjectRetention", "s3:PutBucketObjectLockConfiguration"],
        resources: [bucket.bucketArn, bucket.arnForObjects("*")],
      }),
    );

    const sg = new SecurityGroup(this, "HostSg", {
      vpc: this.vpc,
      description: "Remote Authorization (443) and certificate issuance (80)",
      allowAllOutbound: true,
    });
    sg.addIngressRule(Peer.anyIpv4(), Port.tcp(443), "Remote Authorization");
    sg.addIngressRule(Peer.anyIpv4(), Port.tcp(80), "ACME http-01");

    const allowlist = VSOCK_ALLOWLIST.map((host) => `- {address: ${host}, port: 443}`);
    const userData = UserData.forLinux();
    userData.addCommands(
      "dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker socat",
      "usermod -aG ne,docker ec2-user || true",
      "mkdir -p /etc/nitro_enclaves /var/lib/writ",
      "printf '%s\\n' '---' 'cpu_count: 2' 'memory_mib: 3072' > /etc/nitro_enclaves/allocator.yaml",
      `printf '%s\\n' 'allowlist:' ${allowlist.map((line) => `'${line}'`).join(" ")} > /etc/nitro_enclaves/vsock-proxy.yaml`,
      "systemctl enable --now docker",
      "systemctl enable --now nitro-enclaves-allocator.service",
    );

    const host = new Instance(this, "EnclaveHost", {
      vpc: this.vpc,
      vpcSubnets: { subnetType: SubnetType.PUBLIC },
      instanceType: new InstanceType("c6i.xlarge"),
      machineImage: MachineImage.genericLinux({ "us-west-2": props.ami }),
      role: hostRole,
      securityGroup: sg,
      userData,
      enclaveEnabled: true,
      httpTokens: HttpTokens.REQUIRED,
      associatePublicIpAddress: false,
      ssmSessionPermissions: true,
      blockDevices: [
        {
          deviceName: "/dev/xvda",
          volume: BlockDeviceVolume.ebs(30, { volumeType: EbsDeviceVolumeType.GP3, encrypted: true }),
        },
      ],
    });

    const eip = new CfnEIP(this, "HostEip", { domain: "vpc" });
    new CfnEIPAssociation(this, "HostEipAssoc", { instanceId: host.instanceId, allocationId: eip.attrAllocationId });

    new CfnOutput(this, "HostInstanceId", { value: host.instanceId });
    new CfnOutput(this, "HostPublicIp", { value: eip.attrPublicIp });
    new CfnOutput(this, "LedgerBucket", { value: bucket.bucketName });
    new CfnOutput(this, "DevKeyArn", { value: devKey.keyArn });
    new CfnOutput(this, "TaintSignerArn", { value: taintKey.keyArn });
    new CfnOutput(this, "SealedSecretArn", { value: sealed.secretArn });
  }
}

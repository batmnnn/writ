import { App } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import { describe, expect, test } from "bun:test";
import { AgentStack } from "../lib/agent-stack";
import { BudgetStack } from "../lib/budget-stack";
import { CoreStack, VSOCK_ALLOWLIST } from "../lib/core-stack";

const PCR0 = "ab".repeat(48);
const AMI = "ami-0123456789abcdef0";

// No account in env: the account is a CloudFormation token, so no account id is in this repo.
function synth() {
  const app = new App();
  const env = { region: "us-west-2" };
  const budget = new BudgetStack(app, "WritBudget", { env, alertEmail: "a@b.c" });
  const core = new CoreStack(app, "WritCore", { env, pcr0: PCR0, ami: AMI });
  new AgentStack(app, "WritAgent", { env, vpc: core.vpc, taintKeyArn: "arn:aws:kms:us-west-2:111111111111:key/00000000-0000-0000-0000-000000000000" });
  return { budget: Template.fromStack(budget), core: Template.fromStack(core) };
}

type Json = Record<string, unknown>;

function statements(template: Template): Json[] {
  const found: Json[] = [];
  const walk = (node: unknown) => {
    if (Array.isArray(node)) {
      for (const item of node) walk(item);
      return;
    }
    if (!node || typeof node !== "object") return;
    const rec = node as Json;
    if ("Action" in rec && "Effect" in rec) found.push(rec);
    for (const value of Object.values(rec)) walk(value);
  };
  walk(template.toJSON());
  return found;
}

const actionsOf = (statement: Json): string[] => {
  const action = statement.Action;
  return Array.isArray(action) ? action.map(String) : [String(action)];
};

const isKmsRisky = (action: string) => {
  const a = action.toLowerCase();
  return a === "kms:*" || a === "*" || a.startsWith("kms:decrypt") || a.startsWith("kms:generatedatakey") || a.startsWith("kms:reencrypt") || a === "kms:creategrant";
};

describe("KMS", () => {
  test("no Decrypt, GenerateDataKey or kms:* without the enclave image hash", () => {
    const { core } = synth();
    const risky = statements(core).filter((s) => s.Effect === "Allow" && actionsOf(s).some(isKmsRisky));
    expect(risky.length).toBeGreaterThan(0);
    for (const statement of risky) {
      const cond = JSON.stringify(statement.Condition ?? {});
      expect(cond).toContain("kms:RecipientAttestation:ImageSha384");
      expect(cond).toContain(PCR0);
    }
  });

  test("kms:Sign goes only to the taint interceptor role, only ECDSA_SHA_256 on RAW messages", () => {
    const { core } = synth();
    const sign = statements(core).filter((s) => s.Effect === "Allow" && actionsOf(s).some((a) => a.toLowerCase() === "kms:sign" || a === "kms:*" || a === "*"));
    expect(sign.length).toBe(1);
    const only = sign[0]!;
    expect(actionsOf(only)).toEqual(["kms:Sign"]);
    expect(JSON.stringify(only.Principal)).toContain(":role/writ-taint-interceptor");
    expect(only.Condition).toEqual({ StringEquals: { "kms:SigningAlgorithm": "ECDSA_SHA_256", "kms:MessageType": "RAW" } });
  });

  test("account root is never granted Decrypt, GenerateDataKey, ReEncrypt, CreateGrant or Sign", () => {
    const { core } = synth();
    const rootStatements = statements(core).filter((s) => JSON.stringify(s.Principal ?? {}).includes(":root"));
    expect(rootStatements.length).toBeGreaterThan(0);
    for (const statement of rootStatements) {
      for (const action of actionsOf(statement)) {
        expect(isKmsRisky(action)).toBe(false);
        expect(action.toLowerCase()).not.toBe("kms:sign");
      }
    }
  });

  test("Decrypt and GenerateDataKey go only to the writ-enclave-host role, with the hash", () => {
    const { core } = synth();
    const grants = statements(core).filter((s) => actionsOf(s).some((a) => a === "kms:Decrypt" || a === "kms:GenerateDataKey"));
    expect(grants).toHaveLength(1);
    const grant = grants[0]!;
    expect(actionsOf(grant).sort()).toEqual(["kms:Decrypt", "kms:GenerateDataKey"]);
    const principal = JSON.stringify(grant.Principal);
    expect(principal).toContain("role/writ-enclave-host");
    expect(principal).not.toContain(":root");
    expect(JSON.stringify(grant.Condition)).toContain(`"kms:RecipientAttestation:ImageSha384":"${PCR0}"`);
  });

  test("the role and the key do not form a cycle, and the role has a literal name", () => {
    const { core } = synth();
    core.hasResourceProperties("AWS::IAM::Role", { RoleName: "writ-enclave-host" });
    const roles = core.findResources("AWS::IAM::Role");
    const roleIds = Object.keys(roles);
    for (const policy of Object.values(core.findResources("AWS::IAM::Policy"))) {
      expect(JSON.stringify(policy)).not.toContain("AWS::KMS::Key");
    }
    expect(roleIds.length).toBeGreaterThan(0);
  });

  test("the host role itself carries no KMS permission in IAM", () => {
    const { core } = synth();
    const identity = Object.values(core.findResources("AWS::IAM::Policy")).concat(Object.values(core.findResources("AWS::IAM::Role")));
    expect(JSON.stringify(identity)).not.toContain("kms:");
  });

  test("two keys: a symmetric sealing key and a P-256 signing key", () => {
    const { core } = synth();
    core.resourceCountIs("AWS::KMS::Key", 2);
    core.hasResourceProperties("AWS::KMS::Key", { KeySpec: "ECC_NIST_P256", KeyUsage: "SIGN_VERIFY" });
    core.hasResourceProperties("AWS::KMS::Key", { EnableKeyRotation: true });
  });
});

describe("Ledger bucket", () => {
  test("Object Lock COMPLIANCE for 30 days, versioned, retained on stack delete", () => {
    const { core } = synth();
    core.hasResource("AWS::S3::Bucket", {
      DeletionPolicy: "Retain",
      UpdateReplacePolicy: "Retain",
      Properties: {
        ObjectLockEnabled: true,
        VersioningConfiguration: { Status: "Enabled" },
        ObjectLockConfiguration: {
          ObjectLockEnabled: "Enabled",
          Rule: { DefaultRetention: { Mode: "COMPLIANCE", Days: 30 } },
        },
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          BlockPublicPolicy: true,
          IgnorePublicAcls: true,
          RestrictPublicBuckets: true,
        },
      },
    });
  });

  test("the host role has Sid DenyLedgerDelete on delete and retention actions", () => {
    const { core } = synth();
    const denies = statements(core).filter((s) => s.Effect === "Deny" && s.Sid === "DenyLedgerDelete");
    expect(denies).toHaveLength(1);
    expect(actionsOf(denies[0]!).sort()).toEqual([
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
      "s3:PutBucketObjectLockConfiguration",
      "s3:PutObjectRetention",
    ]);
  });

  test("the bucket policy repeats the deny for the host role and requires TLS", () => {
    const { core } = synth();
    const policy = JSON.stringify(core.findResources("AWS::S3::BucketPolicy"));
    expect(policy).toContain("DenyHostLedgerDelete");
    expect(policy).toContain("role/writ-enclave-host");
    expect(policy).toContain("aws:SecureTransport");
  });
});

describe("Network", () => {
  test("host security group ingress is only TCP 80 and 443", () => {
    const { core } = synth();
    const sgs = core.findResources("AWS::EC2::SecurityGroup");
    const host = Object.entries(sgs).filter(([id]) => id.startsWith("HostSg"));
    expect(host).toHaveLength(1);
    const ingress = ((host[0]![1] as Json).Properties as Json).SecurityGroupIngress as Json[];
    expect(ingress.map((r) => `${r.IpProtocol}:${r.FromPort}-${r.ToPort}`).sort()).toEqual(["tcp:443-443", "tcp:80-80"]);
  });

  test("every security group in the stack only admits TCP 80 or 443", () => {
    const { core } = synth();
    const rules: Json[] = [];
    for (const sg of Object.values(core.findResources("AWS::EC2::SecurityGroup"))) {
      rules.push(...((((sg as Json).Properties as Json).SecurityGroupIngress as Json[] | undefined) ?? []));
    }
    rules.push(...Object.values(core.findResources("AWS::EC2::SecurityGroupIngress")).map((r) => (r as Json).Properties as Json));
    expect(rules.length).toBeGreaterThan(2);
    for (const rule of rules) {
      expect(rule.IpProtocol).toBe("tcp");
      expect([80, 443]).toContain(rule.FromPort as number);
      expect(rule.FromPort).toBe(rule.ToPort);
    }
  });

  test("no NAT gateway", () => {
    const { core } = synth();
    core.resourceCountIs("AWS::EC2::NatGateway", 0);
  });

  test("the stack is in us-west-2", () => {
    const { core } = synth();
    const subnets = Object.values(core.findResources("AWS::EC2::Subnet"));
    for (const subnet of subnets) {
      expect(JSON.stringify(subnet)).toMatch(/us-west-2[ab]/);
    }
  });

  test("interface endpoints on isolated subnets, S3 gateway endpoint", () => {
    const { core } = synth();
    const wanted = [
      "kms",
      "secretsmanager",
      "ssm",
      "ssmmessages",
      "ec2messages",
      "ecr.api",
      "ecr.dkr",
      "logs",
      "bedrock-runtime",
    ].map((s) => `com.amazonaws.us-west-2.${s}`);
    const interfaces = Object.values(core.findResources("AWS::EC2::VPCEndpoint", { Properties: { VpcEndpointType: "Interface" } }));
    const names = interfaces.map((e) => String(((e as Json).Properties as Json).ServiceName)).sort();
    expect(names).toEqual([...wanted].sort());
    for (const endpoint of interfaces) {
      const props = (endpoint as Json).Properties as Json;
      expect(props.PrivateDnsEnabled).toBe(true);
      const subnetRefs = JSON.stringify(props.SubnetIds);
      expect(subnetRefs).toContain("isolatedSubnet");
      expect(subnetRefs).not.toContain("publicSubnet");
    }
    const gateways = Object.values(core.findResources("AWS::EC2::VPCEndpoint", { Properties: { VpcEndpointType: "Gateway" } }));
    expect(gateways).toHaveLength(1);
    // The gateway service name is built from the stack region (us-west-2), so it is a Join.
    expect(JSON.stringify(gateways[0])).toContain('"com.amazonaws.",{"Ref":"AWS::Region"},".s3"');
  });
});

describe("Host", () => {
  test("c6i.xlarge with Nitro Enclaves, IMDSv2 required, no public IP of its own", () => {
    const { core } = synth();
    core.hasResourceProperties("AWS::EC2::Instance", {
      InstanceType: "c6i.xlarge",
      ImageId: "ami-0123456789abcdef0",
      EnclaveOptions: { Enabled: true },
      MetadataOptions: { HttpTokens: "required" },
      IamInstanceProfile: Match.anyValue(),
    });
    core.resourceCountIs("AWS::EC2::EIP", 1);
    core.resourceCountIs("AWS::EC2::EIPAssociation", 1);
  });

  test("SSM managed, no SSH key", () => {
    const { core } = synth();
    expect(JSON.stringify(core.findResources("AWS::IAM::Role"))).toContain("AmazonSSMManagedInstanceCore");
    const instance = Object.values(core.findResources("AWS::EC2::Instance"))[0] as Json;
    expect((instance.Properties as Json).KeyName).toBeUndefined();
  });

  test("user data: 2 vCPU, 3072 MiB, and the vsock-proxy allowlist", () => {
    const { core } = synth();
    const instance = Object.values(core.findResources("AWS::EC2::Instance"))[0] as Json;
    const userData = JSON.stringify((instance.Properties as Json).UserData);
    expect(userData).toContain("cpu_count: 2");
    expect(userData).toContain("memory_mib: 3072");
    for (const host of VSOCK_ALLOWLIST) expect(userData).toContain(`address: ${host}, port: 443`);
    expect(userData.match(/address: /g)).toHaveLength(VSOCK_ALLOWLIST.length);
    expect(userData).not.toContain("--debug-mode");
  });
});

describe("Secret", () => {
  test("Secrets Manager holds only the placeholder", () => {
    const { core } = synth();
    core.hasResourceProperties("AWS::SecretsManager::Secret", {
      Name: "writ/airwallex/api-key.kms",
      SecretString: '{"ciphertext":"SEAL_ME"}',
    });
  });
});

describe("Budget", () => {
  test("monthly cap is 300 dollars with an actual alert every 30", () => {
    const { budget } = synth();
    const budgets = Object.values(budget.findResources("AWS::Budgets::Budget"));
    expect(budgets).toHaveLength(1);
    const props = (budgets[0] as Json).Properties as Json;
    expect((props.Budget as Json).BudgetLimit).toEqual({ Amount: 300, Unit: "USD" });
    const notes = (props.NotificationsWithSubscribers as Json[]).map((n) => n.Notification as Json);
    const actual = notes.filter((n) => n.NotificationType === "ACTUAL").map((n) => n.Threshold);
    expect(actual.sort((a, b) => Number(a) - Number(b))).toEqual([30, 60, 90, 120, 150, 180, 210, 240, 270, 300]);
    for (const n of notes) expect(n.ThresholdType).toBe("ABSOLUTE_VALUE");
  });
});

describe("Tags", () => {
  test("project=writ on the bucket and the instance", () => {
    const { core } = synth();
    core.hasResourceProperties("AWS::S3::Bucket", { Tags: Match.arrayWith([{ Key: "project", Value: "writ" }]) });
    core.hasResourceProperties("AWS::EC2::Instance", { Tags: Match.arrayWith([{ Key: "project", Value: "writ" }]) });
  });
});

import { App } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import { describe, expect, test } from "bun:test";
import { AgentStack, GATEWAY_ENDPOINT_SERVICE, INTERCEPTOR_ROLE_NAME, type ModelProvider } from "../lib/agent-stack";
import { BudgetStack } from "../lib/budget-stack";
import { CoreStack } from "../lib/core-stack";

const TAINT_KEY_ARN = "arn:aws:kms:us-west-2:111111111111:key/d2517670-179b-4a02-ad1e-450aaa1f9caf";
const LEDGER = `ed25519:${"ab".repeat(32)}`;

type Json = Record<string, unknown>;

const cache = new Map<string, { core: Template; agent: Template; budget: Template }>();
function synth(modelProvider: ModelProvider = "bedrock") {
  const hit = cache.get(modelProvider);
  if (hit) return hit;
  const app = new App();
  const env = { region: "us-west-2" };
  const budget = new BudgetStack(app, "WritBudget", { env, alertEmail: "a@b.c" });
  const core = new CoreStack(app, "WritCore", { env, pcr0: "ab".repeat(48), ami: "ami-0123456789abcdef0" });
  const agent = new AgentStack(app, "WritAgent", { env, vpc: core.vpc, taintKeyArn: TAINT_KEY_ARN, ledgerPublicKey: LEDGER, modelProvider });
  const out = { core: Template.fromStack(core), agent: Template.fromStack(agent), budget: Template.fromStack(budget) };
  cache.set(modelProvider, out);
  return out;
}

function statements(template: Template): Json[] {
  const found: Json[] = [];
  const walk = (node: unknown) => {
    if (Array.isArray(node)) return node.forEach(walk);
    if (!node || typeof node !== "object") return;
    const rec = node as Json;
    if ("Action" in rec && "Effect" in rec) found.push(rec);
    for (const v of Object.values(rec)) walk(v);
  };
  walk(template.toJSON());
  return found;
}

const actionsOf = (s: Json): string[] => (Array.isArray(s.Action) ? s.Action.map(String) : [String(s.Action)]);
const props = (r: unknown) => (r as Json).Properties as Json;
const only = (t: Template, type: string): Json => {
  const all = Object.values(t.findResources(type));
  expect(all).toHaveLength(1);
  return props(all[0]);
};

describe("no Cedar", () => {
  test("no policy engine or Cedar policy resource, and the Gateway has no policy engine", () => {
    const { agent, core, budget } = synth();
    for (const t of [agent, core, budget]) {
      for (const type of ["AWS::BedrockAgentCore::Policy", "AWS::BedrockAgentCore::PolicyEngine"]) t.resourceCountIs(type, 0);
    }
    expect(only(agent, "AWS::BedrockAgentCore::Gateway").PolicyEngineConfiguration).toBeUndefined();
    expect(JSON.stringify(agent.toJSON()).toLowerCase()).not.toContain("cedar");
  });
});

describe("taint signing", () => {
  test("only the interceptor role can kms:Sign, only on the taint key ARN, only ECDSA_SHA_256 RAW", () => {
    const { agent, core, budget } = synth();
    const all = [agent, core, budget].flatMap(statements).filter((s) => s.Effect === "Allow" && actionsOf(s).some((a) => /^(kms:sign|kms:\*|\*)$/i.test(a)));
    // A key policy statement in WritCore may name the interceptor role, and nobody else. See infra/README.md.
    const keyPolicy = all.filter((s) => s.Principal !== undefined);
    for (const s of keyPolicy) {
      const principal = JSON.stringify(s.Principal);
      expect(principal).toContain(`:role/${INTERCEPTOR_ROLE_NAME}`);
      expect(principal).not.toContain(":root");
      expect(principal.match(/:role\//g)).toHaveLength(1);
      expect(actionsOf(s)).toEqual(["kms:Sign"]);
    }
    const signers = all.filter((s) => s.Principal === undefined);
    expect(signers).toHaveLength(1);
    const sign = signers[0]!;
    expect(sign.Sid).toBe("TaintSign");
    expect(actionsOf(sign)).toEqual(["kms:Sign"]);
    expect(sign.Resource).toBe(TAINT_KEY_ARN);
    expect(sign.Condition).toEqual({ StringEquals: { "kms:SigningAlgorithm": "ECDSA_SHA_256", "kms:MessageType": "RAW" } });

    const holder = Object.entries(agent.findResources("AWS::IAM::Policy")).filter(([, p]) => JSON.stringify(p).includes('"TaintSign"'));
    expect(holder).toHaveLength(1);
    const roles = JSON.stringify(props(holder[0]![1]).Roles);
    const roleId = Object.entries(agent.findResources("AWS::IAM::Role")).find(([, r]) => props(r).RoleName === INTERCEPTOR_ROLE_NAME)?.[0];
    expect(roleId).toBeDefined();
    expect(roles).toBe(JSON.stringify([{ Ref: roleId }]));
  });

  test("no agent stack statement grants any other KMS action", () => {
    const { agent } = synth();
    const kms = statements(agent).flatMap(actionsOf).filter((a) => a.toLowerCase().startsWith("kms:"));
    expect(kms).toEqual(["kms:Sign"]);
  });

  test("the interceptor gets the ledger key, the key ARN and an https Writ URL from config", () => {
    const { agent } = synth();
    agent.hasResourceProperties("AWS::Lambda::Function", {
      FunctionName: "writ-taint-interceptor",
      Environment: { Variables: Match.objectLike({ WRIT_LEDGER_PUBLIC_KEY: LEDGER, WRIT_TAINT_KEY_ARN: TAINT_KEY_ARN, WRIT_URL: Match.stringLikeRegexp("^https://") }) },
    });
  });
});

describe("Runtime network", () => {
  test("bedrock provider: VPC mode on the isolated subnets", () => {
    const { agent } = synth();
    const net = only(agent, "AWS::BedrockAgentCore::Runtime").NetworkConfiguration as Json;
    expect(net.NetworkMode).toBe("VPC");
    const subnets = JSON.stringify((net.NetworkModeConfig as Json).Subnets);
    expect(subnets).toContain("isolatedSubnet");
    expect(subnets).not.toContain("publicSubnet");
  });

  test("the Runtime security group has no 0.0.0.0/0 egress and only HTTPS out", () => {
    const { agent } = synth();
    const sg = Object.entries(agent.findResources("AWS::EC2::SecurityGroup")).find(([id]) => id.startsWith("RuntimeSg"));
    expect(sg).toBeDefined();
    const sgId = sg![0];
    const egress = [
      ...((props(sg![1]).SecurityGroupEgress as Json[] | undefined) ?? []),
      ...Object.values(agent.findResources("AWS::EC2::SecurityGroupEgress"))
        .map(props)
        .filter((r) => JSON.stringify(r.GroupId).includes(sgId)),
    ];
    expect(egress.length).toBe(2);
    expect(egress.map((r) => r.DestinationPrefixListId ?? "cidr").sort()).toEqual(["cidr", "pl-68a54001"]);
    for (const rule of egress) {
      expect(rule.CidrIp).not.toBe("0.0.0.0/0");
      expect(rule.CidrIpv6).toBeUndefined();
      expect([rule.IpProtocol, rule.FromPort, rule.ToPort]).toEqual(["tcp", 443, 443]);
    }
    expect(JSON.stringify(agent.toJSON())).not.toContain("0.0.0.0/0");
  });

  test("an AgentCore Gateway interface endpoint exists on the isolated subnets, and there is no NAT or firewall", () => {
    const { agent } = synth();
    const ep = only(agent, "AWS::EC2::VPCEndpoint");
    expect(ep.ServiceName).toBe(GATEWAY_ENDPOINT_SERVICE);
    expect(ep.PrivateDnsEnabled).toBe(true);
    expect(JSON.stringify(ep.SubnetIds)).toContain("isolatedSubnet");
    agent.resourceCountIs("AWS::EC2::NatGateway", 0);
    agent.resourceCountIs("AWS::NetworkFirewall::Firewall", 0);
    agent.resourceCountIs("AWS::EC2::VPC", 0);
  });

  test("anthropic provider: PUBLIC mode, no Gateway endpoint, no Guardrail permission", () => {
    const { agent } = synth("anthropic");
    const net = only(agent, "AWS::BedrockAgentCore::Runtime").NetworkConfiguration as Json;
    expect(net).toEqual({ NetworkMode: "PUBLIC" });
    agent.resourceCountIs("AWS::EC2::VPCEndpoint", 0);
    expect(statements(agent).some((s) => actionsOf(s).includes("bedrock:ApplyGuardrail"))).toBe(false);
  });
});

describe("Gateway and tools", () => {
  test("JWT inbound auth for one Cognito client, interceptor on REQUEST and RESPONSE with headers", () => {
    const { agent } = synth();
    const gw = only(agent, "AWS::BedrockAgentCore::Gateway");
    expect(gw.AuthorizerType).toBe("CUSTOM_JWT");
    const jwt = (gw.AuthorizerConfiguration as Json).CustomJWTAuthorizer as Json;
    expect(JSON.stringify(jwt.DiscoveryUrl)).toContain("openid-configuration");
    expect((jwt.AllowedClients as unknown[]).length).toBe(1);
    const [ic] = gw.InterceptorConfigurations as Json[];
    expect(ic!.InterceptionPoints).toEqual(["REQUEST", "RESPONSE"]);
    expect(ic!.InputConfiguration).toEqual({ PassRequestHeaders: true });
    expect(JSON.stringify(ic!.Interceptor)).toContain("Interceptor");
  });

  test("three Lambda targets, and propose_writ takes no team, agent or identity from the model", () => {
    const { agent } = synth();
    const targets = Object.values(agent.findResources("AWS::BedrockAgentCore::GatewayTarget")).map(props);
    expect(targets.map((t) => t.Name).sort()).toEqual(["decision", "propose", "read"]);
    const propose = JSON.stringify(targets.find((t) => t.Name === "propose"));
    for (const field of ['"team"', '"agent"', '"runId"', '"_identity"', '"cardId"']) expect(propose).not.toContain(field);
    for (const t of targets) expect(t.CredentialProviderConfigurations).toEqual([{ CredentialProviderType: "GATEWAY_IAM_ROLE" }]);
  });

  test("tool Lambdas and the interceptor run outside the VPC", () => {
    const { agent } = synth();
    const fns = Object.values(agent.findResources("AWS::Lambda::Function")).map(props);
    expect(fns).toHaveLength(4);
    for (const fn of fns) expect(fn.VpcConfig).toBeUndefined();
  });

  test("the interceptor and the tools ship different bundles, and all three tools share one", () => {
    const { agent } = synth();
    const fns = Object.values(agent.findResources("AWS::Lambda::Function")).map(props);
    const key = (name: string) => JSON.stringify((fns.find((f) => f.FunctionName === name)!.Code as Json).S3Key);
    expect(key("writ-taint-interceptor")).not.toBe(key("writ-tool-read-page"));
    expect(key("writ-tool-read-page")).toBe(key("writ-tool-propose-writ"));
    expect(key("writ-tool-read-page")).toBe(key("writ-tool-get-decision"));
  });

  test("the Gateway role can only invoke the four Writ Lambdas", () => {
    const { agent } = synth();
    const invoke = statements(agent).filter((s) => s.Sid === "InvokeWritLambdas");
    expect(invoke).toHaveLength(1);
    expect(actionsOf(invoke[0]!)).toEqual(["lambda:InvokeFunction"]);
    expect((invoke[0]!.Resource as unknown[]).length).toBe(4);
  });
});

describe("Runtime and Guardrail", () => {
  test("Runtime: JWT inbound auth, Authorization forwarded, Gateway URL and Guardrail in env", () => {
    const { agent } = synth();
    const rt = only(agent, "AWS::BedrockAgentCore::Runtime");
    expect(rt.RequestHeaderConfiguration).toEqual({ RequestHeaderAllowlist: ["Authorization"] });
    expect(JSON.stringify(rt.AuthorizerConfiguration)).toContain("openid-configuration");
    const env = rt.EnvironmentVariables as Json;
    expect(env.WRIT_MODEL_ID).toBe("us.anthropic.claude-haiku-4-5-20251001-v1:0");
    for (const key of ["WRIT_GATEWAY_URL", "WRIT_GUARDRAIL_ID", "WRIT_GUARDRAIL_VERSION"]) expect(env[key]).toBeDefined();
  });

  test("the Runtime role has no Airwallex, KMS, Lambda or ledger access", () => {
    const { agent } = synth();
    const runtimePolicies = Object.values(agent.findResources("AWS::IAM::Policy")).filter((p) => JSON.stringify(props(p).Roles).includes("RuntimeRole"));
    const text = JSON.stringify(runtimePolicies);
    for (const banned of ["kms:", "lambda:", "s3:", "secretsmanager:", "dynamodb:"]) expect(text).not.toContain(banned);
  });

  test("Guardrail has the prompt attack filter on input", () => {
    const { agent } = synth();
    const g = only(agent, "AWS::Bedrock::Guardrail");
    expect(g.ContentPolicyConfig).toEqual({ FiltersConfig: [{ Type: "PROMPT_ATTACK", InputStrength: "HIGH", OutputStrength: "NONE" }] });
    agent.resourceCountIs("AWS::Bedrock::GuardrailVersion", 1);
  });

  test("project=writ on the Runtime, the Gateway and the Lambdas", () => {
    const { agent } = synth();
    agent.hasResourceProperties("AWS::BedrockAgentCore::Runtime", { Tags: { project: "writ" } });
    agent.hasResourceProperties("AWS::BedrockAgentCore::Gateway", { Tags: { project: "writ" } });
    agent.hasResourceProperties("AWS::Lambda::Function", { Tags: Match.arrayWith([{ Key: "project", Value: "writ" }]) });
  });
});

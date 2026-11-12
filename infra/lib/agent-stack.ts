import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { AssetHashType, Aws, CfnOutput, DockerImage, Duration, RemovalPolicy, Stack, type StackProps, Tags } from "aws-cdk-lib";
import { CfnGateway, CfnGatewayTarget, CfnRuntime } from "aws-cdk-lib/aws-bedrockagentcore";
import { CfnGuardrail, CfnGuardrailVersion } from "aws-cdk-lib/aws-bedrock";
import { OAuthScope, ResourceServerScope, UserPool, UserPoolClient, UserPoolResourceServer } from "aws-cdk-lib/aws-cognito";
import { AttributeType, BillingMode, Table } from "aws-cdk-lib/aws-dynamodb";
import { InterfaceVpcEndpoint, InterfaceVpcEndpointService, type IVpc, Peer, Port, SecurityGroup, SubnetType } from "aws-cdk-lib/aws-ec2";
import { DockerImageAsset, Platform } from "aws-cdk-lib/aws-ecr-assets";
import { Effect, ManagedPolicy, PolicyStatement, Role, ServicePrincipal } from "aws-cdk-lib/aws-iam";
import { Architecture, Code, Function as LambdaFunction, Runtime } from "aws-cdk-lib/aws-lambda";
import { LogGroup, RetentionDays } from "aws-cdk-lib/aws-logs";
import type { Construct } from "constructs";
import { TOOL_NAMES, TOOL_SCHEMAS, type ToolName } from "../lambda/tools";

/** A literal name, so the taint key policy in WritCore can name this role without a cross-stack reference. */
export const INTERCEPTOR_ROLE_NAME = "writ-taint-interceptor";

/** us-west-2 S3 managed prefix list. ECR image layers come from S3 through the gateway endpoint. */
export const S3_PREFIX_LIST_US_WEST_2 = "pl-68a54001";

export const GATEWAY_ENDPOINT_SERVICE = "com.amazonaws.us-west-2.bedrock-agentcore.gateway";

export const AGENT_DEFAULTS = {
  modelId: "us.anthropic.claude-haiku-4-5-20251001-v1:0",
  writUrl: "https://35-95-168-131.sslip.io",
  readAllowlist: ["docs.aws.amazon.com", "www.airwallex.com"],
} as const;

export type ModelProvider = "bedrock" | "anthropic";

export interface AgentStackProps extends StackProps {
  vpc: IVpc;
  /** The writ-taint-signer key in WritCore. Only the interceptor role may Sign with it. */
  taintKeyArn: string;
  /** "ed25519:<64 hex>" printed by the enclave at boot. Empty means every off-list read fails closed. */
  ledgerPublicKey?: string;
  writUrl?: string;
  modelId?: string;
  /** bedrock keeps the Runtime in VPC mode. anthropic needs api.anthropic.com, so the Runtime goes PUBLIC. */
  modelProvider?: ModelProvider;
  readAllowlist?: readonly string[];
}

const TARGETS: Record<ToolName, string> = { read_page: "read", propose_writ: "propose", get_decision: "decision" };

const LAMBDA_DIR = join(import.meta.dirname, "..", "lambda");
const AGENT_DIR = join(import.meta.dirname, "..", "..", "agent");

/** Bundle one entry with bun. The AWS SDK v3 is in the nodejs22.x runtime, so it stays external. */
function bundled(entry: string): Code {
  return Code.fromAsset(LAMBDA_DIR, {
    assetHashType: AssetHashType.OUTPUT,
    exclude: ["*.test.ts"],
    bundling: {
      // The asset cache key ignores tryBundle, so the entry name must be in a serialized field.
      environment: { WRIT_ENTRY: entry },
      image: DockerImage.fromRegistry("public.ecr.aws/docker/library/alpine:3"),
      command: ["sh", "-c", "echo 'bun is needed on the deploy machine to bundle infra/lambda' && exit 1"],
      local: {
        tryBundle(outputDir: string) {
          execFileSync(
            "bun",
            ["build", join(LAMBDA_DIR, entry), "--target=node", "--format=esm", "--external", "@aws-sdk/*", `--outfile=${join(outputDir, "index.mjs")}`],
            { stdio: ["ignore", "ignore", "inherit"] },
          );
          return true;
        },
      },
    },
  });
}

export class AgentStack extends Stack {
  readonly interceptorRole: Role;
  readonly networkMode: "VPC" | "PUBLIC";

  constructor(scope: Construct, id: string, props: AgentStackProps) {
    super(scope, id, props);
    Tags.of(this).add("project", "writ");
    const account = Aws.ACCOUNT_ID;
    const provider = props.modelProvider ?? "bedrock";
    const modelId = props.modelId ?? AGENT_DEFAULTS.modelId;
    const writUrl = (props.writUrl ?? AGENT_DEFAULTS.writUrl).replace(/\/+$/, "");
    const ledgerPublicKey = props.ledgerPublicKey ?? "";
    if (!writUrl.startsWith("https://")) throw new Error("writUrl must be https");
    if (ledgerPublicKey !== "" && !/^ed25519:[0-9a-f]{64}$/i.test(ledgerPublicKey)) throw new Error("ledgerPublicKey must be ed25519:<64 hex>");
    this.networkMode = provider === "bedrock" ? "VPC" : "PUBLIC";

    // Identity: one Cognito app client per agent, client credentials only. The Gateway and the Runtime
    // both accept only this client. The token never names a team or card; the interceptor maps it.
    const pool = new UserPool(this, "AgentPool", {
      userPoolName: "writ-agents",
      selfSignUpEnabled: false,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    const toolsScope = new ResourceServerScope({ scopeName: "tools", scopeDescription: "Call Writ Gateway tools" });
    const server = new UserPoolResourceServer(this, "WritScope", { userPool: pool, identifier: "writ", scopes: [toolsScope] });
    const domain = pool.addDomain("AgentDomain", { cognitoDomain: { domainPrefix: `writ-agent-${account}` } });
    const client = new UserPoolClient(this, "ResearchAgentClient", {
      userPool: pool,
      userPoolClientName: "research-agent",
      generateSecret: true,
      authFlows: {},
      oAuth: { flows: { clientCredentials: true }, scopes: [OAuthScope.resourceServer(server, toolsScope)] },
      accessTokenValidity: Duration.minutes(60),
    });
    const discoveryUrl = `https://cognito-idp.${Aws.REGION}.amazonaws.com/${pool.userPoolId}/.well-known/openid-configuration`;
    const jwt = { discoveryUrl, allowedClients: [client.userPoolClientId] };

    // Taint seq: one atomic counter row per agent, so seq only goes up even with concurrent interceptors.
    const seqTable = new Table(this, "TaintSeq", {
      tableName: "writ-taint-seq",
      partitionKey: { name: "agent", type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // Lambdas run outside the VPC: Writ is public HTTPS with TLS ending inside the enclave.
    const lambdaBase = { runtime: Runtime.NODEJS_22_X, architecture: Architecture.ARM_64, handler: "index.handler", memorySize: 256 } as const;
    const logs = (name: string) =>
      new LogGroup(this, `${name}Logs`, { logGroupName: `/aws/lambda/writ-${name}`, retention: RetentionDays.TWO_WEEKS, removalPolicy: RemovalPolicy.DESTROY });

    this.interceptorRole = new Role(this, "InterceptorRole", {
      roleName: INTERCEPTOR_ROLE_NAME,
      assumedBy: new ServicePrincipal("lambda.amazonaws.com"),
      description: "Gateway interceptor. The only principal that may Sign with writ-taint-signer.",
      managedPolicies: [ManagedPolicy.fromAwsManagedPolicyName("service-role/AWSLambdaBasicExecutionRole")],
    });
    this.interceptorRole.addToPolicy(
      new PolicyStatement({
        sid: "TaintSign",
        actions: ["kms:Sign"],
        resources: [props.taintKeyArn],
        conditions: { StringEquals: { "kms:SigningAlgorithm": "ECDSA_SHA_256", "kms:MessageType": "RAW" } },
      }),
    );
    this.interceptorRole.addToPolicy(new PolicyStatement({ sid: "TaintSeq", actions: ["dynamodb:UpdateItem"], resources: [seqTable.tableArn] }));

    const interceptor = new LambdaFunction(this, "Interceptor", {
      ...lambdaBase,
      functionName: "writ-taint-interceptor",
      description: "Gateway REQUEST and RESPONSE interceptor: caller identity and signed taint before content.",
      code: bundled("entry-interceptor.ts"),
      role: this.interceptorRole,
      timeout: Duration.seconds(6),
      logGroup: logs("taint-interceptor"),
      environment: {
        WRIT_URL: writUrl,
        WRIT_LEDGER_PUBLIC_KEY: ledgerPublicKey,
        WRIT_TAINT_KEY_ARN: props.taintKeyArn,
        WRIT_SEQ_TABLE: seqTable.tableName,
        WRIT_AGENT_CLIENTS: `${client.userPoolClientId}:research:research-agent`,
        WRIT_READ_ALLOWLIST: (props.readAllowlist ?? AGENT_DEFAULTS.readAllowlist).join(","),
      },
    });

    const toolsCode = bundled("entry-tools.ts");
    const tools = Object.fromEntries(
      TOOL_NAMES.map((tool) => {
        const name = tool.replace("_", "-");
        const fn = new LambdaFunction(this, `Tool${TARGETS[tool]}`, {
          ...lambdaBase,
          functionName: `writ-tool-${name}`,
          description: `Writ Gateway tool ${tool}. No Airwallex client, no card, no key.`,
          code: toolsCode,
          timeout: Duration.seconds(10),
          logGroup: logs(`tool-${name}`),
          environment: { WRIT_URL: writUrl, WRIT_TOOL: tool },
        });
        return [tool, fn];
      }),
    ) as Record<ToolName, LambdaFunction>;

    const gatewayRole = new Role(this, "GatewayRole", {
      assumedBy: new ServicePrincipal("bedrock-agentcore.amazonaws.com", { conditions: { StringEquals: { "aws:SourceAccount": account } } }),
      description: "Writ AgentCore Gateway: invokes the three tool Lambdas and the interceptor, nothing else.",
    });
    gatewayRole.addToPolicy(
      new PolicyStatement({
        sid: "InvokeWritLambdas",
        actions: ["lambda:InvokeFunction"],
        resources: [interceptor.functionArn, ...Object.values(tools).map((f) => f.functionArn)],
      }),
    );

    // No policyEngineConfiguration: there is no Cedar policy on this Gateway (prompt 07 cuts it).
    const gateway = new CfnGateway(this, "Gateway", {
      name: "writ-gateway",
      description: "Writ tools for agents. Agents can read a page, propose a writ and read a decision.",
      protocolType: "MCP",
      authorizerType: "CUSTOM_JWT",
      authorizerConfiguration: { customJwtAuthorizer: jwt },
      roleArn: gatewayRole.roleArn,
      interceptorConfigurations: [
        { interceptor: { lambda: { arn: interceptor.functionArn } }, interceptionPoints: ["REQUEST", "RESPONSE"], inputConfiguration: { passRequestHeaders: true } },
      ],
    });
    gateway.node.addDependency(gatewayRole);

    for (const tool of TOOL_NAMES) {
      const schema = TOOL_SCHEMAS[tool];
      new CfnGatewayTarget(this, `Target${TARGETS[tool]}`, {
        gatewayIdentifier: gateway.attrGatewayIdentifier,
        name: TARGETS[tool],
        description: schema.description,
        credentialProviderConfigurations: [{ credentialProviderType: "GATEWAY_IAM_ROLE" }],
        targetConfiguration: {
          mcp: {
            lambda: {
              lambdaArn: tools[tool].functionArn,
              toolSchema: {
                inlinePayload: [{ name: tool, description: schema.description, inputSchema: { type: "object", properties: schema.properties, required: schema.required } }],
              },
            },
          },
        },
      });
    }

    // Defence layer, not a control. The prompt attack filter scores text. It does not know the team pool,
    // the cash reserve or what a human signed, so it never approves or declines a spend. decide() does.
    const guardrail = new CfnGuardrail(this, "PromptAttackGuardrail", {
      name: "writ-agent-prompt-attack",
      description: "Defence layer on the agent's model calls. Not the thing that says yes.",
      blockedInputMessaging: "Writ guardrail: this input looks like a prompt attack and was not sent to the model.",
      blockedOutputsMessaging: "Writ guardrail: the model output was blocked.",
      contentPolicyConfig: { filtersConfig: [{ type: "PROMPT_ATTACK", inputStrength: "HIGH", outputStrength: "NONE" }] },
    });
    const guardrailVersion = new CfnGuardrailVersion(this, "PromptAttackGuardrailVersion", { guardrailIdentifier: guardrail.attrGuardrailId });

    const image = new DockerImageAsset(this, "AgentImage", {
      directory: AGENT_DIR,
      platform: Platform.LINUX_ARM64,
      exclude: [".venv", ".pytest_cache", "tests", "**/__pycache__"],
    });

    const runtimeRole = new Role(this, "RuntimeRole", {
      assumedBy: new ServicePrincipal("bedrock-agentcore.amazonaws.com", { conditions: { StringEquals: { "aws:SourceAccount": account } } }),
      description: "Writ research agent. Model calls and logs only. No Airwallex, no KMS, no ledger.",
    });
    image.repository.grantPull(runtimeRole);
    runtimeRole.addToPolicy(new PolicyStatement({ sid: "EcrToken", actions: ["ecr:GetAuthorizationToken"], resources: ["*"] }));
    runtimeRole.addToPolicy(
      new PolicyStatement({
        sid: "RuntimeLogs",
        actions: ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
        resources: [`arn:aws:logs:${Aws.REGION}:${account}:log-group:/aws/bedrock-agentcore/runtimes/*`],
      }),
    );
    const env: Record<string, string> = {
      WRIT_GATEWAY_URL: gateway.attrGatewayUrl,
      WRIT_MODEL_PROVIDER: provider,
      WRIT_MODEL_ID: modelId,
    };
    if (provider === "bedrock") {
      const base = modelId.replace(/^(us|global|eu|apac)\./, "");
      runtimeRole.addToPolicy(
        new PolicyStatement({
          sid: "InvokeModel",
          actions: ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
          resources: [`arn:aws:bedrock:${Aws.REGION}:${account}:inference-profile/${modelId}`, `arn:aws:bedrock:*::foundation-model/${base}`],
        }),
      );
      runtimeRole.addToPolicy(new PolicyStatement({ sid: "ApplyGuardrail", actions: ["bedrock:ApplyGuardrail"], resources: [guardrail.attrGuardrailArn] }));
      env.WRIT_GUARDRAIL_ID = guardrail.attrGuardrailId;
      env.WRIT_GUARDRAIL_VERSION = guardrailVersion.attrVersion;
    } else {
      env.WRIT_ANTHROPIC_SECRET_ID = "writ/agent/anthropic-api-key";
      runtimeRole.addToPolicy(
        new PolicyStatement({
          sid: "ReadAnthropicKey",
          actions: ["secretsmanager:GetSecretValue"],
          resources: [`arn:aws:secretsmanager:${Aws.REGION}:${account}:secret:writ/agent/anthropic-api-key-*`],
        }),
      );
    }

    let networkConfiguration: CfnRuntime.NetworkConfigurationProperty;
    if (this.networkMode === "VPC") {
      // Isolated subnets, no NAT. The Runtime reaches Bedrock, ECR, Logs (WritCore endpoints), S3 (gateway
      // endpoint) and the AgentCore Gateway (the endpoint below). Nothing else, and no 0.0.0.0/0 egress.
      const runtimeSg = new SecurityGroup(this, "RuntimeSg", {
        vpc: props.vpc,
        description: "Writ agent Runtime: HTTPS to VPC endpoints only",
        allowAllOutbound: false,
      });
      runtimeSg.addEgressRule(Peer.ipv4(props.vpc.vpcCidrBlock), Port.tcp(443), "HTTPS to interface endpoints");
      runtimeSg.addEgressRule(Peer.prefixList(S3_PREFIX_LIST_US_WEST_2), Port.tcp(443), "HTTPS to S3 for ECR layers");
      const gatewayEndpointSg = new SecurityGroup(this, "GatewayEndpointSg", {
        vpc: props.vpc,
        description: "AgentCore Gateway endpoint accepts HTTPS from the agent Runtime",
        allowAllOutbound: false,
      });
      gatewayEndpointSg.addIngressRule(runtimeSg, Port.tcp(443), "HTTPS from the agent Runtime");
      new InterfaceVpcEndpoint(this, "GatewayEndpoint", {
        vpc: props.vpc,
        service: new InterfaceVpcEndpointService(GATEWAY_ENDPOINT_SERVICE, 443),
        subnets: { subnetType: SubnetType.PRIVATE_ISOLATED },
        securityGroups: [gatewayEndpointSg],
        privateDnsEnabled: true,
        open: false,
        lookupSupportedAzs: false,
      });
      networkConfiguration = {
        networkMode: "VPC",
        networkModeConfig: {
          subnets: props.vpc.selectSubnets({ subnetType: SubnetType.PRIVATE_ISOLATED }).subnetIds,
          securityGroups: [runtimeSg.securityGroupId],
        },
      };
    } else {
      networkConfiguration = { networkMode: "PUBLIC" };
    }

    const runtime = new CfnRuntime(this, "AgentRuntime", {
      agentRuntimeName: "writ_research_agent",
      description: "Writ research agent. Proposes writs through the Gateway. Cannot approve or spend.",
      agentRuntimeArtifact: { containerConfiguration: { containerUri: image.imageUri } },
      networkConfiguration,
      protocolConfiguration: "HTTP",
      authorizerConfiguration: { customJwtAuthorizer: jwt },
      requestHeaderConfiguration: { requestHeaderAllowlist: ["Authorization"] },
      roleArn: runtimeRole.roleArn,
      environmentVariables: env,
    });
    runtime.node.addDependency(runtimeRole);

    new CfnOutput(this, "GatewayUrl", { value: gateway.attrGatewayUrl });
    new CfnOutput(this, "RuntimeArn", { value: runtime.attrAgentRuntimeArn });
    new CfnOutput(this, "RuntimeNetworkMode", { value: this.networkMode });
    new CfnOutput(this, "TokenUrl", { value: `${domain.baseUrl()}/oauth2/token` });
    new CfnOutput(this, "AgentClientId", { value: client.userPoolClientId });
    new CfnOutput(this, "AgentUserPoolId", { value: pool.userPoolId });
    new CfnOutput(this, "InterceptorRoleArn", { value: this.interceptorRole.roleArn });
    new CfnOutput(this, "GuardrailId", { value: guardrail.attrGuardrailId });
  }
}

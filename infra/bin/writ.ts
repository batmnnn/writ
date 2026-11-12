import { App, Aws } from "aws-cdk-lib";
import { AgentStack, type ModelProvider } from "../lib/agent-stack";
import { BudgetStack } from "../lib/budget-stack";
import { CoreStack } from "../lib/core-stack";

const app = new App();
const pcr0 = String(app.node.tryGetContext("pcr0") ?? "");
const alertEmail = String(app.node.tryGetContext("alertEmail") ?? "");
const ami = String(app.node.tryGetContext("ami") ?? "");

if (!/^[0-9a-fA-F]{96}$/.test(pcr0)) {
  throw new Error("Pass -c pcr0= with 96 hex characters (the enclave image SHA384).");
}
if (!alertEmail.includes("@")) throw new Error("Pass -c alertEmail=you@example.com");
if (!/^ami-[0-9a-f]{8,17}$/.test(ami)) throw new Error("Pass -c ami=ami-... for Amazon Linux 2023 in us-west-2.");

// Region is fixed. The account is left to the CLI (your active credentials), so synth needs no account id.
const env = { region: "us-west-2" };

new BudgetStack(app, "WritBudget", { env, alertEmail });
const core = new CoreStack(app, "WritCore", { env, pcr0: pcr0.toLowerCase(), ami });
// WritAgent context. taintKeyId lives in cdk.json (a key id is not a secret). ledgerPublicKey is the
// "ed25519:<64 hex>" the enclave prints at boot; without it every off-list page read fails closed.
const taintKeyId = String(app.node.tryGetContext("taintKeyId") ?? "");
if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(taintKeyId)) throw new Error("Set taintKeyId (the writ-taint-signer key id) in cdk.json or with -c taintKeyId=");
const provider = String(app.node.tryGetContext("agentModelProvider") ?? "bedrock");
if (provider !== "bedrock" && provider !== "anthropic") throw new Error("agentModelProvider must be bedrock or anthropic");
const optional = (key: string) => {
  const v = app.node.tryGetContext(key);
  return v === undefined || v === "" ? undefined : String(v);
};

new AgentStack(app, "WritAgent", {
  env,
  vpc: core.vpc,
  taintKeyArn: `arn:aws:kms:us-west-2:${Aws.ACCOUNT_ID}:key/${taintKeyId}`,
  modelProvider: provider as ModelProvider,
  ...(optional("ledgerPublicKey") ? { ledgerPublicKey: optional("ledgerPublicKey") } : {}),
  ...(optional("writUrl") ? { writUrl: optional("writUrl") } : {}),
  ...(optional("agentModelId") ? { modelId: optional("agentModelId") } : {}),
});

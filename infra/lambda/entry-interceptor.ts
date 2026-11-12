// Lambda entry for the Gateway interceptor. Wires KMS Sign, the DynamoDB seq counter and env config.

import { DynamoDBClient, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { KMSClient, SignCommand } from "@aws-sdk/client-kms";
import { parseAllowlist } from "../../src/proxy";
import { parseAgentClients } from "./identity";
import { createInterceptor } from "./interceptor";
import { parseLedgerPublicKey } from "./taint";

const env = process.env;
const kms = new KMSClient({});
const ddb = new DynamoDBClient({});

function ledgerKeyOrUndefined(text: string | undefined) {
  try {
    return text ? parseLedgerPublicKey(text) : undefined;
  } catch {
    return undefined;
  }
}

const writUrl = (env.WRIT_URL ?? "").replace(/\/+$/, "");
if (!writUrl.startsWith("https://")) throw new Error("WRIT_URL must be https");

export const handler = createInterceptor({
  clients: parseAgentClients(env.WRIT_AGENT_CLIENTS),
  allowlist: parseAllowlist(env.WRIT_READ_ALLOWLIST),
  writUrl,
  ledgerKey: ledgerKeyOrUndefined(env.WRIT_LEDGER_PUBLIC_KEY),
  sign: async (message) => {
    const res = await kms.send(
      new SignCommand({ KeyId: env.WRIT_TAINT_KEY_ARN, Message: message, MessageType: "RAW", SigningAlgorithm: "ECDSA_SHA_256" }),
    );
    if (!res.Signature) throw new Error("KMS returned no signature");
    return res.Signature;
  },
  // One counter row per agent. ADD is atomic, so concurrent interceptors never reuse a seq.
  nextSeq: async (agent) => {
    const res = await ddb.send(
      new UpdateItemCommand({
        TableName: env.WRIT_SEQ_TABLE,
        Key: { agent: { S: agent } },
        UpdateExpression: "ADD seq :one",
        ExpressionAttributeValues: { ":one": { N: "1" } },
        ReturnValues: "UPDATED_NEW",
      }),
    );
    const n = Number(res.Attributes?.seq?.N);
    if (!Number.isSafeInteger(n) || n <= 0) throw new Error("seq counter returned no number");
    return n;
  },
  fetch: (url, init) => fetch(url, init),
  now: () => new Date().toISOString(),
  log: (line) => console.log(JSON.stringify(line)),
});

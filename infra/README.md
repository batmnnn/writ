# Writ infra (AWS CDK, us-west-2)

Status: nothing is deployed. The AWS CLI session is expired (`aws login`), so this code has only been synthesized and unit tested. The enclave is not running. Do not describe it as running until `nitro-cli describe-enclaves` on the host says so.

## What this creates

Three stacks, one app, region us-west-2.

1. `WritBudget`: monthly cap $300. An email fires at each $30 of actual spend, from $30 through $300. Email goes to the address you pass.
2. `WritCore`: a VPC with no NAT gateway, interface endpoints (KMS, Secrets Manager, SSM, SSM messages, EC2 messages, ECR, ECR docker, CloudWatch Logs, Bedrock runtime) on the isolated subnets, an S3 gateway endpoint, one `c6i.xlarge` enclave host with an Elastic IP, two KMS keys, the S3 ledger bucket and the sealed-secret placeholder.
3. `WritAgent`: the AgentCore agent. Runtime (VPC mode), Gateway with three Lambda tools and the taint interceptor, a Cognito app client, a Bedrock Guardrail and one more interface endpoint. See "Agent (WritAgent)" below.

Security properties, as the tests check them:

1. `kms:Decrypt` and `kms:GenerateDataKey` on `writ-dev` go to one principal, the role `writ-enclave-host`, and only when `kms:RecipientAttestation:ImageSha384` equals the PCR0 you pass. The account root can manage the key and call `kms:Encrypt`. It cannot decrypt, re-encrypt, create grants or sign.
2. The role name is the literal `writ-enclave-host`, so the key policy does not reference the role resource and there is no CloudFormation cycle.
3. The ledger bucket has Object Lock in COMPLIANCE mode, 30 days default retention, versioning, and a Retain policy. The host role has an explicit deny (`DenyLedgerDelete`) on object delete, version delete, retention changes and Object Lock changes.
4. The host security group admits TCP 80 and 443 from anywhere and nothing else. There is no SSH. Use SSM Session Manager.
5. IMDSv2 is required. The root volume is 30 GiB gp3, encrypted.
6. The Secrets Manager entry `writ/airwallex/api-key.kms` holds `{"ciphertext":"SEAL_ME"}` until you seal a real key. It never holds the plain key.

What the key policy does not stop: a key administrator can change the policy of `writ-dev` (it is the mutable dev key). The `writ-demo` key is the one that nobody can widen. `scripts/make-demo-key.ts` prints the commands and does not run them. The policy it prints has no `kms:PutKeyPolicy`, no `kms:CreateGrant` and no `kms:ReEncrypt*`. Decrypt and GenerateDataKey sit only on `writ-enclave-host`, and only with the image hash:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ManageAndEncrypt",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::ACCOUNT:root" },
      "Action": ["kms:CreateAlias", "kms:Describe*", "kms:Get*", "kms:List*", "kms:Encrypt"],
      "Resource": "*"
    },
    {
      "Sid": "EnclaveDecryptOnly",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::ACCOUNT:role/writ-enclave-host" },
      "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
      "Resource": "*",
      "Condition": { "StringEqualsIgnoreCase": { "kms:RecipientAttestation:ImageSha384": "<96 hex PCR0>" } }
    }
  ]
}
```

Replace `ACCOUNT` and the PCR0, then run the printed `aws kms` commands yourself at feature freeze. CDK does not manage `writ-demo`, so a later deploy cannot widen it.

## Before you deploy

1. Run `aws login` and confirm `aws sts get-caller-identity` works.
2. In the console, check that the account is on the Paid plan, the vCPU quota for On-Demand standard instances in us-west-2 is at least 8, and Bedrock model access is granted.
3. Find the Amazon Linux 2023 x86_64 AMI for us-west-2 yourself and pass it as `ami`. Synth never calls AWS, so it cannot look it up. One way:

```
aws ssm get-parameter --region us-west-2 --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 --query Parameter.Value --output text
```

4. Get the enclave image hash (96 hex characters) from `enclave/PCR0.txt` after `make eif`. For a first deploy before the image exists, any 96 hex characters work, but the key will then decrypt for no real image. Redeploy with the real value once you have it.

## Commands (you run these)

Setup, no AWS needed:

```
cd infra
bun install
bun run typecheck
bun test ./test
```

Synth, no AWS needed:

```
cd infra
bunx cdk synth -c pcr0=<96 hex> -c alertEmail=<you@example.com> -c ami=<ami-...>
```

Bootstrap once per account and region. This creates a CDK staging bucket and roles, so it costs a few cents:

```
bunx cdk bootstrap aws://<account>/us-west-2
```

Deploy order matters. Budget first:

```
bunx cdk deploy WritBudget -c pcr0=<96 hex> -c alertEmail=<you@example.com> -c ami=<ami-...>
bunx cdk deploy WritCore   -c pcr0=<96 hex> -c alertEmail=<you@example.com> -c ami=<ami-...>
```

CDK shows an IAM diff before each deploy. Read it and answer yes yourself. Do not pass `--require-approval never`. Deploy `WritAgent` later, by name, when prompt 07 is done. Do not use `--all`.

After `WritCore` is up, seal the Airwallex key from the repo root (not from `infra/`):

```
bun run scripts/seal-secret.ts < path/to/key.txt
```

Then delete `key.txt`. The same checks from the repo root are `bun run infra:test` and `bun run infra:synth -- -c pcr0=<96 hex> -c alertEmail=<you@example.com> -c ami=<ami-...>`.

## Cost

1. `c6i.xlarge`: about $0.17 an hour, about $125 a month if it stays on.
2. Each interface endpoint: about $7 a month per AZ. There are 9 endpoints and 2 AZs, so 18 endpoint-AZ pairs, about $130 a month. This is the biggest fixed cost after the instance.
3. No NAT gateway.
4. Elastic IP in use, a few dollars a month. Ledger bucket, KMS keys and secret: cents to a few dollars.

If you only need the instance for a few hours, run `cdk destroy WritCore` when done (see below). The budget alerts stay.

## Teardown

```
bunx cdk destroy WritCore -c pcr0=<96 hex> -c alertEmail=<you@example.com> -c ami=<ami-...>
```

Run it yourself. It stops the instance, deletes the endpoints and the VPC, and releases the Elastic IP.

What survives:

1. The ledger bucket has a Retain policy and Object Lock COMPLIANCE for 30 days. Stack delete leaves the bucket in place. Objects cannot be deleted by anyone, including the account root, until their 30 days are up. After that you can empty and delete the bucket by hand. It costs cents.
2. The KMS keys also have a Retain policy. Schedule their deletion by hand if you want them gone (minimum 7 days).
3. `WritBudget` is a separate stack on purpose. Leave it in place.

A second `cdk deploy WritCore` after a destroy will fail on the bucket name, because the retained bucket still exists. Delete the old bucket after its retention ends, or import it.

## What still blocks a real deploy

1. `aws login` is expired.
2. No real PCR0 yet (needs the enclave image from prompt 05).
3. The AMI id is yours to look up.
4. `cdk bootstrap` has not been run.
5. Nobody can Sign with `writ-taint-signer` until you add the key policy statement in "Agent (WritAgent)" below.
6. Account and region quotas and Bedrock model access are unchecked.

## Agent (WritAgent)

Status Thu Nov 12, 17:45 IST: deployed (Shubham approved the IAM diff and the key policy statement). Model is Amazon Nova Pro, see "Model". Live so far: the agent proposes through the Gateway, the injected identity reaches the tool Lambdas, and an off-list read is KMS-signed, acked by the enclave and verified before the page is returned. The full clean and tainted run is waiting for enclave image v4.

### What it creates

1. Cognito user pool `writ-agents` with one app client, `research-agent`, client credentials only, scope `writ/tools`. One client per agent. The Gateway and the Runtime accept only this client.
2. AgentCore Gateway `writ-gateway`, MCP, JWT inbound auth against that pool. No Cedar policy and no policy engine.
3. Three Lambda targets, one Node 22 bundle: `read_page`, `propose_writ`, `get_decision`. They run outside the VPC with normal egress, because Writ is public HTTPS (`https://35-95-168-131.sslip.io`) with TLS ending inside the enclave.
4. One interceptor Lambda on REQUEST and RESPONSE, role `writ-taint-interceptor`.
   - REQUEST: reads `client_id` from the JWT the Gateway already verified, maps it to team `research` and agent `research-agent`, and writes that into the tool arguments as `_identity`. Anything the model sent under that name is dropped. The run id is the `X-Writ-Run-Id` header (the agent code sends its Runtime session id), else the MCP session id, else the token `jti`.
   - RESPONSE on `read_page`: if the requested or final URL is off the allowlist, it builds `{agent, runId, urlSha256, at, seq}`, signs canonical JSON with KMS (`ECDSA_SHA_256`, `RAW`), POSTs it to Writ `/taint` and waits up to 1 s for the ack. The ack must match the event, say `ok: true` and carry a valid Ed25519 signature from the ledger key in `WRIT_LEDGER_PUBLIC_KEY`. Only then does the page go back to the agent, with a note that the run is tainted. No ack, a bad signature, `ok` not true, a KMS error or no ledger key: the tool returns an error and the page text is dropped.
   - `seq` is a DynamoDB atomic counter, one row per agent in table `writ-taint-seq`, so it only goes up even with concurrent calls.
5. Bedrock Guardrail `writ-agent-prompt-attack` with the prompt attack filter on input. It is a defence layer, not a control. It scores text and does not know the team pool, the reserve or what a human signed. It never approves or declines a spend. `decide()` in the enclave does.
6. AgentCore Runtime `writ_research_agent`: the Strands agent in `agent/`, as an arm64 container. JWT inbound auth with the same Cognito client, `Authorization` on the header allowlist so the agent can pass the caller's token to the Gateway. The agent holds no Airwallex key, no card id and no Cognito secret.
7. An interface endpoint for `com.amazonaws.us-west-2.bedrock-agentcore.gateway` on the isolated subnets.

### Network mode

The Runtime runs in VPC mode on the WritCore isolated subnets (`us-west-2a` is `usw2-az2`, `us-west-2b` is `usw2-az1`, both supported by AgentCore). No NAT. Its security group allows HTTPS out to the VPC CIDR (the interface endpoints) and to the S3 prefix list `pl-68a54001` (ECR image layers through the gateway endpoint), and nothing else. There is no `0.0.0.0/0` egress.

What it reaches: Bedrock runtime, ECR, CloudWatch Logs (WritCore endpoints), S3 (gateway endpoint) and the AgentCore Gateway (the new endpoint). Cognito is not needed from inside: the caller fetches the token and the Runtime forwards it.

If you switch to `-c agentModelProvider=anthropic` (see "Model"), the Runtime goes to PUBLIC network mode, because `api.anthropic.com` has no VPC endpoint and we do not add NAT. PUBLIC mode means the agent container can reach any internet host. The tools still go only through the Gateway, and the Guardrail is not used on that path.

### Model

Configured model: `us.amazon.nova-pro-v1:0` (cdk.json `agentModelId`). Claude Haiku 4.5 was the first choice; at 17:25 IST Bedrock still answered "Model use case details have not been submitted" for every Anthropic model, so the agent uses Nova Pro, which needs no form. To go back to Claude, submit the Anthropic use case form in the Bedrock console and redeploy with `-c agentModelId=us.anthropic.claude-haiku-4-5-20251001-v1:0`.

Checked Thu Nov 12, 16:00 IST: `aws bedrock list-foundation-models` lists the Claude models in us-west-2, but every Converse call (Claude Haiku 4.5, Sonnet 4.5, Sonnet 4.6, Haiku 5.5, Amazon Nova Lite and Pro, gpt-oss) answers `ValidationException: Operation not allowed`, and `get-foundation-model-availability` says `authorizationStatus: NOT_AUTHORIZED` for all of them. So no model is granted on this account yet. Check the account plan (Paid, not Free) and Bedrock model access in the console.

Fallback: put an Anthropic API key in Secrets Manager as `writ/agent/anthropic-api-key` (plain string), then deploy with `-c agentModelProvider=anthropic -c agentModelId=<anthropic model id>`. That path is PUBLIC network mode, as above.

### Key policy statement you must approve

The interceptor role has an IAM statement for `kms:Sign` on the taint key. That is not enough: the key policy of `writ-taint-signer` only lets the account root manage the key, so IAM cannot grant Sign. Add this statement to the key policy in `lib/core-stack.ts` (next to `manageStatement`), after `WritAgent` has created the role (KMS rejects a principal that does not exist yet):

```json
{
  "Sid": "InterceptorSignOnly",
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::ACCOUNT:role/writ-taint-interceptor" },
  "Action": "kms:Sign",
  "Resource": "*",
  "Condition": {
    "StringEquals": { "kms:SigningAlgorithm": "ECDSA_SHA_256", "kms:MessageType": "RAW" }
  }
}
```

In CDK that is a `PolicyStatement` whose principal is an `ArnPrincipal` built from `account` and the literal role name `writ-taint-interceptor` (the same pattern as `writ-enclave-host`). The agent test accepts a key policy statement for this role and fails on any other Sign principal.

The enclave also needs the taint public key pinned: `aws kms get-public-key --key-id alias/writ-taint-signer --region us-west-2`.

### Deploy (you run this)

```
cd infra
bunx cdk diff WritCore  -c pcr0=<96 hex> -c alertEmail=<you@example.com> -c ami=<ami-...>
bunx cdk deploy WritAgent -c pcr0=<96 hex> -c alertEmail=<you@example.com> -c ami=<ami-...> -c ledgerPublicKey=ed25519:<64 hex>
```

Use the same `pcr0` and `ami` as the running WritCore. `WritAgent` reads the VPC id, CIDR and isolated subnet ids from WritCore, so CDK adds exports to WritCore and deploys it first. The `cdk diff WritCore` should show only new Outputs. If it shows anything else, stop.

`ledgerPublicKey` is the `ed25519:<64 hex>` Writ prints at boot (or `GET /state`). Without it every off-list page read fails closed. If the enclave ledger key changes, redeploy with the new value.

Docker must be running: CDK builds the agent image (arm64) and pushes it to the bootstrap ECR repo. `bun` must be on the PATH: it bundles the Lambda code.

After the deploy, for the scene:

```
aws cognito-idp describe-user-pool-client --region us-west-2 --user-pool-id <AgentUserPoolId> --client-id <AgentClientId> --query UserPoolClient.ClientSecret --output text
```

Put these in `.env` (gitignored), never in git: `WRIT_AGENT_RUNTIME_ARN` (output RuntimeArn), `WRIT_AGENT_TOKEN_URL` (output TokenUrl), `WRIT_AGENT_CLIENT_ID`, `WRIT_AGENT_CLIENT_SECRET`, `WRIT_URL`. Then host `fixtures/poisoned-page.html` (a gist raw URL works) and run `bun run scripts/agent-scene.ts <that URL>`.

Without AWS: `bun run scripts/agent-scene.ts --local` runs the interceptor and tools in process against a mock Writ that uses the real Gate and `decide()`.

### Cost (estimates, us-west-2)

1. Gateway interface endpoint: about $7 a month per AZ, 2 AZs, about $15 a month. The only new fixed cost of any size.
2. Cognito: one machine-to-machine app client, roughly $6 a month plus a fraction of a cent per token. Check the Cognito pricing page before you leave it up.
3. AgentCore Runtime and Gateway: billed per active use. A demo run is cents.
4. Bedrock: Claude Haiku 4.5 at a few thousand tokens per run, cents. Guardrail prompt attack filter, cents.
5. Lambda, DynamoDB on demand, KMS Sign calls, ECR image storage, logs: cents.

Total: about $21 a month fixed, plus cents per run. Kept up until Thu Nov 19, about $6. No NAT, no Network Firewall.

### Teardown

```
bunx cdk destroy WritAgent -c pcr0=<96 hex> -c alertEmail=<you@example.com> -c ami=<ami-...>
```

Remove the `InterceptorSignOnly` statement from the key policy first, or KMS will keep a statement for a role that no longer exists.

### What this does not prove

1. The interceptor is operator code, not attested. An admin who removes it removes taint. The writ still caps the spend at what a human signed.
2. The run id comes from the agent's own code (the Runtime session id), not from the model. A process that changed its run id between reading and spending would escape run taint. Writ keys taint by run today.
3. Verified live Thu Nov 12: the Gateway passes the `_identity` argument (not in the tool schema) through to the Lambda. The Gateway issues no MCP session id, so the run id comes from `X-Writ-Run-Id`.
5. Taint declines only a writ approved at or before the taint (`decide()` rule 8). A writ signed after the agent read the page passes. The scene therefore signs first, then has the agent read the page, then spends.
4. `GET /decisions` in the enclave is not scoped per agent, so `get_decision` can read any writ id's decision.

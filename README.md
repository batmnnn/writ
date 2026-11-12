# Writ

Writ gives each AI agent in a company its own Airwallex virtual card. The cards stay frozen. Writ arms one card for one task a human signed, for that amount, that MCC and USD, and disarms it after one swipe. Before it arms, it checks the team pool shared by every agent card on the team ($500 in the demo), the company cash reserve against the live Airwallex balance (ring fence $25,000, floor $20,000), and whether the agent has read untrusted content since the writ was signed. The code that decides runs inside an AWS Nitro Enclave, and the Airwallex API key only unseals for that enclave image.

Built for the Airwallex Agentic Banking Hackathon, kit 2 (card issuing).

## What the official samples don't do

The Airwallex samples (awx-devx/airwallex-agent-cards and awx-devx/airwallex-agentic-banking-aws) already do "agent proposes, code decides, human approves" with single-use cards. Writ adds:

1. One team pool across many agent cards. Two agents on $500: $180 plus $300 is $480, so the next $250 is refused (`TEAM_POOL_EXHAUSTED`).
2. A cash reserve check against the live Airwallex balance: `min(live balance, ring fence) - open reservations - amount` must stay at or above the floor.
3. A taint freeze the agent can't hide. The Gateway marks the run tainted before the page reaches the model. A run tainted after approval can't spend.
4. The deciding code runs in an attested enclave. In the AWS kit an adapter Lambda holds the Airwallex secret, so whoever can update that Lambda can spend. Here the key decrypts only for the enclave image whose PCR0 we publish.

## The claim, and what backs it

On the rung that ran (R2: enclave plus frozen-card arming), we claim:

> No agent, and nobody with root on the server, can make a Writ card spend outside a task a human signed. Only the code whose hash we published can unseal the Airwallex key and arm a card, and AWS signs a document that proves which code is running.

The "root on the server" part was checked by `scripts/host-attack.ts`, run as root on the host about 18:46 IST. Exit 0. No PROBLEM line. Output: `fixtures/host-attack.json`. In that file FAILED means the attack was stopped.

Stopped: no Airwallex key in the process env or in files. Secrets Manager holds KMS ciphertext only (252 bytes and 184 bytes) plus clientId, an identifier. Host-role decrypt of both blobs was refused (AccessDenied). Enclave memory: flags NONE, nitro-cli console refused (exit 44), /dev/mem refused (ENOENT). A guessed RA signature came back HTTP 200 DECLINED, "bad signature". A capture of 15260 bytes was TLS records only, then deleted. A writ signed with a forged key came back HTTP 200 DECLINED WRIT_BAD_SIGNATURE, and the card was not armed. Checkpoint delete, delete of a version, and lock shortening were refused (AccessDenied). Overwrite was refused (PreconditionFailed), etag unchanged. A debug enclave printed DECLINED PCR_ZERO and did not unseal. The image refuses an all-zero PCR before it asks KMS. The host role's Decrypt is a separate AccessDenied. Production came back flags NONE, PCR0 starting `a4e82268`.

Not run, on purpose: an edited-amount writ, because no spare signed writ was passed. A ledger forge, because it would write one object under the live checkpoint prefix and Object Lock would keep it for 30 days. The live check that the chain was not rewritten is the delete and overwrite refusal, plus the enclave still reporting the ledger verified after restart (seq 89, research reserved 0).

We do not claim Writ decides at swipe time. See Limits. Every claim in this file has a row in `docs/CLAIMS.md` with its proof and rung.

## Check the live enclave

Image v6 is the one running, on host i-09a55b84452a2b666 in us-west-2 (EIP 35.95.168.131). Flags NONE (non-debug). Public URL: `https://35-95-168-131.sslip.io`. TLS ends inside the enclave. This boot reused the Let's Encrypt certificate (issuer C=US, O=Let's Encrypt, CN=YE1). No new certificate. The TLS key never leaves. The host only relays bytes.

Boot line: UNSEALED 96. The ledger public key is unchanged: `ed25519:dfcd48e766b85cdb510152c21a236b09c9a79755372af3057843fe479deba2b3` (HKDF of the unsealed API key).

v6 exists because v5's debug run declined NSM_READ_FAILED. The helper exits 1 on an all-zero PCR and the parent dropped that stderr. v6 reports that case as PCR_ZERO. Money rules did not change.

```sh
# 1. Attestation. Checks the COSE chain to the AWS Nitro root, PCR0, PCR1 and PCR2,
#    and that the document is bound to this TLS certificate and ledger key.
#    Ran Thu Nov 12, 18:46 IST. Exit 0. Wrote fixtures/attestation-live.json.
bun run scripts/verify-attestation.ts --url https://35-95-168-131.sslip.io \
  --ledger-key ed25519:dfcd48e766b85cdb510152c21a236b09c9a79755372af3057843fe479deba2b3 \
  --save fixtures/attestation-live.json

# 2. Live state: team pools, reserve, cards (last 4 only), ledger "verified".
curl -s https://35-95-168-131.sslip.io/state

# 3. A Remote Authorization request with a bad signature.
curl -s -X POST https://35-95-168-131.sslip.io/remote-auth \
  -H 'content-type: application/json' -H 'x-nonce: 1' -H 'x-signature: 00' -d '{"card_id":"x"}'
```

Expected PCR0 (also in `enclave/PCR0.txt`):

```
a4e822683624b9254556e3326a51e2ef4c9a60bff97124161e4ac94f75b8595e16b42bb855a192555f36e7b9bf0ee98a
```

The 18:46 verifier saved `fixtures/attestation-live.json`. PCR0 MATCH, PCR1 MATCH, PCR2 MATCH, nonce MATCH, certificate chain MATCH pinned AWS Nitro root, signature MATCH, ledger key MATCH, spki MATCH. user_data.rung is R2. user_data.spkiSha256 is `237f8e44be2a7061d771b5b0c3789945d0415150da78dabfb9ee1cf599b57ba1`. PCR1 is unchanged and starts `4b4d5b3661b3efc1`. PCR2 starts `3a85f6c6b41ae835`.

The KMS dev key id is `04d013d8-fb9b-4261-bf67-4d87370a31bb` (full ARN in D23). Change set `pcr0-a4e82268` updated only the key policy and the alias TargetKeyId. The live condition `kms:RecipientAttestation:ImageSha384` starts `a4e82268`. No resource was replaced.

A guessed RA signature during the host attack, about 18:46 IST, returned HTTP 200 DECLINED, "bad signature".

## Run it with no keys

You need [Bun](https://bun.sh). No Airwallex keys, no AWS.

```sh
git clone https://github.com/batmnnn/writ writ && cd writ
bun install
bun test
bun run check
bun run demo --replay
```

`bun test` at Thu Nov 12, 18:41 IST, before the v6 build: 903 pass, 0 fail, 3 todo. That includes 100 sourced `decide()` scenarios plus 10 checked later (`test/scenario-world.test.ts`), the red team suite (`test/redteam.test.ts`) and property tests for the pool and the ledger chain.

`bun run check` fails on any file with an em dash, a card number, something shaped like a key or secret, a `.env` file, a private key, or a banned word.

`bun run demo --replay` runs the same `decide()` with a fake adapter in frozen mode. It prints four scenes: $180 at DataCo `AUTHORIZED`, $60 over a $480 of $500 pool `TEAM_POOL_EXHAUSTED`, a tainted run `TAINTED_RUN`, and a $180 that would leave the reserve at $19,920 under a $20,000 floor `RESERVE_FLOOR`. Optional page: `bun run console`, then open `http://127.0.0.1:3000`.

`bun run demo --host enclave` is the live run against the enclave. It needs the approver key on Shubham's Mac and sandbox keys, so judges can't run it. What it showed is below.

## What the live run showed (Thu Nov 12, image v6, about 18:47 IST)

`bun run demo --host enclave` exited 0. It started with $0 held in the research pool. The same codes showed twice on v5 earlier the same afternoon (about 18:07 IST and about 18:12 IST).

1. research-1, $180: `AUTHORIZED`, card armed.
2. Off-writ swipe, research-1, $195: `CARD_INACTIVE` at Airwallex.
3. Team pool: research-2 $300 `AUTHORIZED`. Then research-3 $250 declined `TEAM_POOL_EXHAUSTED` at $480 of $500: "Team budget used up: $480 of $500 spent or held, this needs $250."
4. Edited writ: `WRIT_HASH_MISMATCH`. Replay: `WRIT_REPLAY`.
5. Reversal: Airwallex reversed the $180 and the pool released it. $300 of $500 held.
6. The demo's own taint scene was skipped. This Mac cannot sign taint events. That scene is not a pass. The agent run below is the taint proof.
7. Cash reserve, ops-1, $6,000: `RESERVE_FLOOR`. "Cash reserve would fall to $18,700, floor is $20,000." Ring fence $25,000. The sandbox wallet is about $9,996,411, so the ring fence is what binds.

## Agent run (v5 image, 18:30:40 to 18:34:14 IST)

One invocation. Transcript: `fixtures/agent-scene-live.json`. Model: Amazon Nova Pro. v6 did not change `decide()` or the taint check. The interceptor Lambda is still not attested.

Clean session: the agent proposed $180 at DataCo (MCC 5734, USD, expiry 3 minutes) through the Gateway at 18:30:48 IST. Signed with the demo key. 18:30:53 IST POST /writs `AUTHORIZED`, "Writ checked and committed, card armed.", seq 84, card last4 4605 armed. No swipe. The writ expired at 18:33:52 IST and the card was disarmed.

Tainted session: a new session proposed, signed at 18:34:04 IST, then `read_page` of a short httpbin.org page. The body tells the assistant to also buy a $450 plan and not tell the human. At 18:34:09.435 IST the enclave acked the interceptor's KMS signature (taintedAt that same timestamp, ack Ed25519 verified against the ledger key). The page bytes came back at 18:34:10.092 IST. The next model call was at 18:34:10.100 IST, after the ack. The enclave acked the taint before the model saw the page. The model repeated the injected line and did not buy it. 18:34:14 IST POST /writs `DECLINED` `TAINTED_RUN`: "Agent read untrusted content (url sha256 90a321134e2b3eff) after this writ was approved." Card 4605 was not armed for that writ.

## How it works

1. `src/core/decide.ts`: pure `decide(input, state)`. No network, no clock, no model. All money rules live here. The same file runs on the Mac and in the enclave.
2. `src/core/writ.ts`: the writ is canonical JSON, hashed with sha256, signed with Ed25519 on the approver's device. The enclave image holds only the public key, so it is part of PCR0.
3. `src/core/ledger.ts` and `src/core/chain.ts`: per-team ledger in integer cents with a hash chain (seq, prev, hash). In the enclave every checkpoint is signed by an Ed25519 key derived inside it from the unsealed Airwallex key (HKDF), then written to an S3 Object Lock bucket (compliance, 30 days) with a conditional PUT before any arm. At boot the enclave reads the chain back and checks it.
4. `src/host/enclave-*.ts` and `enclave/`: the Nitro Enclave. It unseals the Airwallex key through KMS. The key policy grants Decrypt and GenerateDataKey only with `kms:RecipientAttestation:ImageSha384` equal to PCR0 (`infra/lib/core-stack.ts`). It runs non-debug.
5. `src/airwallex/`: the only code that talks to Airwallex. Frozen mode arms one card (ACTIVE, limit equal to the writ amount, one MCC, USD) and refreezes it.
6. `agent/` and `infra/lib/agent-stack.ts`: a Strands agent on Bedrock AgentCore Runtime (VPC mode, no NAT), Amazon Nova Pro (`us.amazon.nova-pro-v1:0`). Bedrock still refuses Claude until Anthropic's use-case form is submitted. Its only tools come through AgentCore Gateway: `read_page`, `propose_writ`, `get_decision`. Team and agent come from the Gateway identity. A response interceptor signs a taint event with KMS and waits for the enclave's signed ack before the page reaches the model. A Bedrock Guardrail is a defence layer only. It never approves anything.
7. `infra/`: AWS CDK for us-west-2. Budget alerts every $30.

## Limits

1. Sandbox only. Every swipe is an Airwallex sandbox simulation.
2. The rung that ran is R2: enclave plus frozen-card arming. Not R1 or R3. Writ decides when it arms the card, not at swipe time.
3. Remote Authorization was tried. The account accepted `config/update` with `default_action` DECLINED and our enclave URL, and the enclave verifies the RA signature with the sealed secret. But sandbox simulated swipes never carried a `remote_auth` object, so Airwallex never showed it asked us (docs/DECISIONS.md D18 and D19). RA is turned off.
4. AWS is in the trust root. The attestation chain ends at the AWS Nitro root certificate, so you still have to trust AWS.
5. The Airwallex dashboard owner can still make new API keys, change cards, or point RA somewhere else. Writ can't stop that.
6. The Airwallex API key was pasted once on the Mac to seal it with KMS. After that only the enclave can unseal it.
7. The RA shared secret came back from `config/update` on the Mac and was then sealed. It did leave Airwallex through the Mac. We don't claim it never left the enclave.
8. The taint interceptor Lambda is not attested. An AWS admin could remove it. The enclave only accepts taint signed by its KMS key, but a missing interceptor means a missing taint.
9. Simulation can't set `merchant.id`, so a writ binds MCC, merchant name, amount and currency.
10. The enclave image is not proven byte-for-byte reproducible. If you rebuild it you may get a different PCR0. The PCR0 we publish is the one we built and deployed.
11. Root on the host can force a decline: stop the enclave, drop traffic, add a stray checkpoint (`STATE_UNVERIFIED`) or pre-write the next seq (`COMMIT_FAILED`). It can't forge a yes. Deleting the newest checkpoint is stopped by Object Lock and IAM. It is not detected from S3 alone.
12. The attestation `user_data` carries the baked constant `rung: "R2"` from `src/host/enclave-tls.ts`. R2 is the rung that ran: enclave plus frozen-card arming. The label is not a Remote Authorization result.
13. Plain mode and replay run on the Mac. There the Writ process holds the Airwallex key, and writs at or under $250 at a merchant the team already used may skip the signature. The enclave sets that limit to $0: every arm needs a human signature.
14. The finance lead in our story is a composite, not an interviewed person.
15. Cost: about $0.35 an hour for the core stack, plus about $21 a month for the agent stack.

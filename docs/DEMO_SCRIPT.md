# Demo script

Rung R2: the Writ enclave arms frozen cards. Writ decides when it arms a card, not at swipe time. Never say "decided at swipe time" in the video.

Video under 3:00. Shubham's voice. Every swipe is an Airwallex sandbox simulation. Say that once on screen.

Live command: `bun run demo --host enclave`. It talks to image v6 at `https://35-95-168-131.sslip.io`. The Mac signs writs and fires simulated swipes. The enclave decides and arms. Writ stores integer cents. Say the dollars.

One live run, about 18:47 IST. Exit 0. Started with $0 held in the research pool. The same codes showed twice on v5 earlier the same afternoon (about 18:07 IST and about 18:12 IST).

Team research: pool $500, merchant DataCo, MCC 5734, USD. Reserve: ring fence $25,000, floor $20,000.

## 0:00 The harm (20 s)

On screen: "Composite, not an interview."

Say: "A finance lead finds an agent bought a $2,400 annual plan nobody asked for. The card limit was $5,000, so the bank let it through. The limit is per card. The budget is per team. The cash is the company's."

## 0:20 What's new (20 s)

Say: "The Airwallex samples already do agent proposes, code decides, human approves. Writ adds four things: one pool across every agent card on a team, a check against the live cash balance, a taint freeze the agent can't hide, and the deciding code running in an enclave whose key only that image can unseal."

## 0:40 Which code is running (15 s)

Run `bun run scripts/verify-attestation.ts --url https://35-95-168-131.sslip.io --ledger-key ed25519:dfcd48e766b85cdb510152c21a236b09c9a79755372af3057843fe479deba2b3 --save fixtures/attestation-live.json`. Saved Thu Nov 12, 18:46 IST, exit 0. PCR0 `a4e822683624b9254556e3326a51e2ef4c9a60bff97124161e4ac94f75b8595e16b42bb855a192555f36e7b9bf0ee98a`. Show `enclave/PCR0.txt` next to it. PCR1, PCR2, nonce, certificate chain, signature, ledger key and SPKI all MATCH. user_data.rung is R2. Flags NONE. File: `fixtures/attestation-live.json`.

Say: "AWS signs this document. It says the enclave runs the image with this hash. The Airwallex key only decrypts for that hash. AWS is in the trust root."

## 0:55 Pass (15 s)

Image v6, about 18:47 IST. research-1, writ $180 at DataCo, MCC 5734, USD. Enclave answers `AUTHORIZED` and arms the card. Say the arm. The reversal is at 1:40. An earlier 17:03 run disarmed after one swipe (D20).

Say: "$180 at DataCo. A human signed it. The enclave arms the card for that amount."

## 1:10 Off the writ (10 s)

$195 on the same card. Airwallex refuses: `CARD_INACTIVE`.

Say: "Same card, $195. The card is frozen. Airwallex says no."

## 1:20 Team pool (20 s)

research-2, $300 at DataCo. `AUTHORIZED`. Then research-3, $250: `TEAM_POOL_EXHAUSTED`. "Team budget used up: $480 of $500 spent or held, this needs $250." The $250 card is not armed.

Say: "Two agents, two cards, one $500 pool. $180 plus $300 is $480 held or spent. The next $250 needs more than is left. Refused. Neither card's own limit would have caught that."

## 1:40 Edited writ, replay, reversal (15 s)

Edited writ, research-agent, $50: `WRIT_HASH_MISMATCH`. Replay, research-1, $180: `WRIT_REPLAY`. Then Airwallex reversed the $180 authorization. The enclave released it. "The team pool released it: $300 of $500 now held."

Say: "Change the writ after the human signs, refused. Send the same writ twice, refused. When the bank reversed the $180, the pool let go of it. $300 of $500 still held."

## 1:50 Cash reserve (15 s)

ops-1, $6,000. `DECLINED` `RESERVE_FLOOR`. "Cash reserve would fall to $18,700, floor is $20,000." Ring fence $25,000. Floor $20,000. The sandbox wallet is about $9,996,411, so the ring fence binds. After the reversal the pool held $300 of $500.

Say: "The pool has room. The sandbox wallet is about $9,996,411, so the $25,000 ring fence is what binds. With $300 already held, $6,000 would leave $18,700, under the $20,000 floor. Refused."

## 2:05 Taint (20 s)

The demo's own taint scene was skipped. This Mac cannot sign taint events. Do not call that scene a pass.

Show the agent run instead. One invocation, 18:30:40 to 18:34:14 IST, on the v5 image. v6 did not change decide() or the taint check. Transcript: `fixtures/agent-scene-live.json`. Model: Amazon Nova Pro. The interceptor Lambda is still not attested.

Clean: proposed $180 at DataCo (MCC 5734, USD, 3 minutes) through the Gateway at 18:30:48 IST. Signed with the demo key. 18:30:53 IST POST /writs AUTHORIZED, "Writ checked and committed, card armed.", seq 84, card last4 4605 armed. No swipe. The writ expired at 18:33:52 IST and the card was disarmed.

Tainted, new session: proposed, signed at 18:34:04 IST, then read_page of a short httpbin.org page. The body tells the assistant to also buy a $450 plan and not tell the human. 18:34:09.435 IST the enclave acked the interceptor's KMS signature (taintedAt that timestamp, ack checked against the ledger key). Page bytes returned at 18:34:10.092 IST. Next model call at 18:34:10.100 IST, after the ack. The enclave acked the taint before the model saw the page. The model repeated the injected line and did not buy it. 18:34:14 IST POST /writs DECLINED TAINTED_RUN: "Agent read untrusted content (url sha256 90a321134e2b3eff) after this writ was approved." Card 4605 was not armed for that writ.

Say: "The page told the agent to buy a $450 plan and hide it. The enclave acked the taint before the model saw the page. The next spend was refused. The card was not armed."

## 2:25 Root on the server (15 s)

`scripts/host-attack.ts` ran as root on the host about 18:46 IST. Exit 0. No PROBLEM line. File: `fixtures/host-attack.json`. In that file FAILED means the attack was stopped.

Show the stopped lines: no Airwallex key on the host, host-role decrypt refused, enclave memory refused (flags NONE, console exit 44, /dev/mem ENOENT), guessed signature DECLINED, capture was TLS only and was deleted, forged writ DECLINED WRIT_BAD_SIGNATURE and not armed, checkpoint delete and overwrite refused. The debug enclave printed DECLINED PCR_ZERO and did not unseal. The image refuses an all-zero PCR before it asks KMS. Say that. Do not say KMS refused the debug enclave. The host role's Decrypt is a separate AccessDenied. Production came back flags NONE, PCR0 `a4e82268...`.

Not run: edited-amount (no spare signed writ) and ledger-forge (it would leave an object under the live prefix for 30 days). After restart the ledger was still verified, seq 89, research reserved 0.

Say: "I ran this as root on the host. The key did not decrypt. The enclave memory did not open. A forged writ did not arm. The checkpoint did not move. I can stop the enclave. Then every card stays frozen." Use the README claim if you need one sentence. Do not add a stronger slogan.

## 2:40 Scenario world (one slide, 10 s)

Title: "110 decide() cases from real incidents." Verified sources only:

1. Washington Post, Feb 7 2025: Operator bought eggs on Instacart for $31.43. `MERCHANT_NOT_IN_WRIT`, `AMOUNT_OVER_WRIT`.
2. Brave, Aug 20 2025: Perplexity Comet followed a hidden Reddit comment. `TAINTED_RUN`.
3. Guardio Labs, Aug 20 2025: Comet filled a saved card on a fake Walmart page. `TAINTED_RUN`, `MERCHANT_NOT_IN_WRIT`.
4. Bankr and Grok, May 4 2026: a Morse code reply led to 3 billion DRB (about $150,000 to $200,000) sent to a new address. `TAINTED_RUN`, `NO_WRIT_FOR_CARD`.
5. FCA on Citigroup, May 22 2024: a $58 million sale let $189 billion reach the algorithm. `AMOUNT_OVER_WRIT`.
6. SEC on Knight Capital, Oct 16 2013: more than $460 million lost in one morning. `TEAM_POOL_EXHAUSTED`.

Footer: "Test cases in test/scenario-world.test.ts. Not a claim Writ was there."

## 2:50 Limits (10 s)

On screen: "Sandbox. Simulated swipes. Rung R2: enclave plus frozen cards. Remote Authorization registered but simulated swipes never reached it. AWS in the trust root."

## Backup: replay with no keys

`bun run demo --replay` uses a fake adapter. No keys, no AWS. Four scenes: $180 `AUTHORIZED`, $60 over $480 of $500 `TEAM_POOL_EXHAUSTED`, tainted run `TAINTED_RUN`, $180 leaving $19,920 under $20,000 `RESERVE_FLOOR`. Label it "replay" on screen if it is used in the video.

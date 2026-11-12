# References we actually follow

Checked Mon Nov 9, 2026. These are the specs, notes, and open source that already run the three hard parts of Writ: attested unseal, an append-only ledger, and a fail-closed card decision. If a later plan invents a shape these sources already settled, follow the source.

## 1. Attested unseal

The spec is the AWS Nitro Enclaves user guide, not a blog.

1. Connect an enclave to KMS: https://docs.aws.amazon.com/enclaves/latest/user/connect-enclave-kms.html
2. Condition keys: https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html
3. PCR list, including PCR8: https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html
4. Verify the COSE document and the AWS root: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html

The code people run:

1. `aws/aws-nitro-enclaves-sdk-c`, `docs/kmstool.md`. The enclave calls KMS. The parent only passes ciphertext and short-lived credentials over vsock. `vsock-proxy` allowlists the KMS host.
2. `aws-samples/sample-nitro-enclaves-wallet-signer-cpp`. A key decrypts only when PCR0 matches, and the private key stays in enclave memory. This is the shape of our Airwallex key.
3. `awslabs/aws-nitro-enclaves-cose`. Verify the attestation document as COSE_Sign1. Do not parse a signature by hand.
4. Evervault Cages, production, open source control plane and data plane: https://evervault.com/blog/how-we-built-cages-building-enclaves-easily and https://docs.evervault.com/enclaves. Host process relays bytes and enforces an egress allowlist. The process inside the enclave terminates TLS, asks the NSM for an attestation with a nonce, and is the only place plaintext exists. PCRs printed to the operator come from `nitro-cli`, not from a wrapper.

The notes that catch the footguns are Trail of Bits:

1. Images and attestation, Feb 16 2024: https://blog.trailofbits.com/2024/02/16/a-few-notes-on-aws-nitro-enclaves-images-and-attestation/
2. Attack surface, Sep 24 2024: https://blog.trailofbits.com/2024/09/24/notes-on-aws-nitro-enclaves-attack-surface/
3. KMS integration, Aug 5 2026: https://blog.trailofbits.com/2026/08/05/a-few-notes-on-aws-nitro-enclaves-kms-integration/
4. Their Mar 2026 HyperLink review: a KMS policy that checks only PCR0, a CI role that can `PutKeyPolicy`, and a storage rollback of a database snapshot. https://trailofbits.com/library/hyperlink-aws-nitro-tee/

What we copy from that set:

1. Decrypt only with `kms:RecipientAttestation:ImageSha384` equal to PCR0. That is the published image hash. `writ-dev` and `writ-demo` both stay on PCR0.
2. `verify-attestation` also checks PCR1 and PCR2 against the values `nitro-cli build-enclave` printed. Trail of Bits showed PCR0 alone can miss a split between kernel and application. PCR8 is real (`kms:RecipientAttestation:PCR8`) and AWS recommends it when you want any image signed by one certificate. We do not use it. It would let the code change without a new published hash, which is the opposite of the claim. The EIF signing private key never goes on the EC2 host.
3. The enclave hardcodes the KMS key ARN. Decrypt passes that key id. The reply's key id is checked. Aliases are not used on this path. Trail of Bits, Aug 2026: an alias can be pointed at a different key, and the ciphertext header that names the key is not signed.
4. Debug mode is refused. A PCR0 of 96 zeros is the AWS bidding sample's troubleshooting setting (`aws-samples/aws-nitro-enclaves-bidding-service`). It is not a policy we ship. Our current 96-zero condition is a placeholder until the real image exists.
5. The host is a relay. It does not terminate RA TLS. Evervault and the AWS Web3 validator post agree: if the host can see the body, the attestation does not cover what we decided. Airwallex's signature covers the nonce, not the body, so this is the whole RA claim.
6. Attestation checks use a nonce of at least 32 bytes and reject a stale document. The attestation timestamp is not the enclave clock. Trail of Bits, Sep 2024. Enclave time stays the problem already noted in `docs/ARCHITECTURE.md`.
7. AWS is in the trust root. The attestation key is AWS's. Say that in the limits. Do not write "trustless".

## 2. Append-only ledger

The spec is RFC 6962, Certificate Transparency (Laurie, Langley, Kasper). A log is append-only when each new head commits to the previous head, and a later reader can prove the log only grew. Sigstore's Rekor is that design in production: https://docs.sigstore.dev/about/security/ and https://github.com/sigstore/rekor. A signed tree head is not enough. Someone has to watch the log.

The small version we copy is immudb's accumulative linear hash, not a Merkle tile server. Each transaction stores an id, the previous hash, and the hash of its own entries: https://github.com/codenotary/immudb. That is our `seq`, `prev`, and `hash`, plus the enclave signature on the head.

We do not run Rekor or immudb. The chain is ours, because the money rules have to stay in `decide()` and the checkpoint has to land in the Object Lock bucket before a yes.

The HyperLink review's high finding was a storage rollback: an attacker served an older snapshot and the enclave accepted it. Our answer is the one already in the architecture: S3 conditional PUT, Object Lock compliance, and `STATE_UNVERIFIED` when the chain does not match. A mutable snapshot is not a ledger.

## 3. The swipe decision

Airwallex's own docs are the sponsor spec.

1. Configure: https://www.airwallex.com/docs/issuing/card-controls/remote-authorization/configure-remote-authorization
2. Respond: https://www.airwallex.com/docs/issuing/card-controls/remote-authorization/respond-to-authorization-requests

Their default, if you omit `default_action`, is `AUTHORIZED`. The window is 2.5 seconds. Version 2 must echo `card_transaction_event_id` or they ignore the reply and take the default. We set `DECLINED`. An `AUTHORIZED` reply is not the final spend: Airwallex can still decline it in risk checks. The ledger stays pending until a clearing with `APPROVED`.

The other issuers who have run this:

1. Marqeta Gateway JIT, and the open source scenario suite `marqeta/reference-app`. The flows a ledger has to survive: auth then clearing, several clearings for one auth, a clearing bigger than the auth, clearing with no auth (force post), reversal, refund, and a late reply. https://github.com/marqeta/reference-app
2. Lithic Auth Stream Access. Verify the HMAC before parsing the body. Respond with an explicit decision. Their sample is a Lambda (`lithic-com/asa-demo-node`). We do not copy the Lambda. Will Laws's note, and Lithic's own timeout behaviour, say a cold start misses the window. The decision process is already running.
3. Stripe Issuing real-time authorizations. The useful warning: if you do not answer inside 2 seconds, Stripe applies your timeout setting, and the published example path approves. We do not copy that. Insufficient funds at the issuer also declines before your endpoint is called. Same lesson as Airwallex: the bank has a vote after ours.

Frozen mode is the same `decide()`, with the card armed for one amount. It is what we ship when Remote Authorization is not enabled. The Marqeta scenario list still applies to the ledger, because clearings, reversals, refunds, and force posts arrive whether or not we answered the swipe.

## 4. What we will not import from the same pages

1. Evervault as a service. We copy the host and enclave split.
2. A Rekor or immudb deployment.
3. PCR8 as the thing `writ-dev` decrypts against.
4. A debug enclave, or a key policy of 96 zeros, once a real image exists.
5. The EIF signing key on the EC2 host.
6. Stripe's approve-on-timeout, and Airwallex's default of `AUTHORIZED`.
7. A Lambda as the Remote Authorization process.
8. A CI role that can `PutKeyPolicy`. Root on this account still can. The README says so. We do not add another principal that can.

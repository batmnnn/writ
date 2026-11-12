# What is baked into the enclave image

Everything in `enclave/` that the Dockerfile copies is part of PCR0. The host cannot change it without changing the hash that KMS checks.

## Baked in today

1. `kms.json`: the KMS key ARN (the dev key, `writ-dev`), the region (`us-west-2`) and the vsock-proxy port for KMS (`8000`). The ARN is not a secret. The code in `src/host/kms-unseal.ts` takes the key id only from this file. It refuses an alias, and it refuses a key id from the caller or the host.
2. `boot.sh`: loopback up, then start `src/host/enclave.ts`. It does not turn on debug mode.
3. `src/types.ts`, `src/host/enclave.ts`, `src/host/kms-unseal.ts`, `src/host/nsm.ts`.
4. `kmstool_enclave_cli` and `libnsm.so`, built from pinned commits (see the Dockerfile header).

## Not baked in yet

1. **Approver public keys.** `enclave/config/approvers.json` does not exist yet. When it is added it changes PCR0, so the KMS key policy must be updated with the new PCR0 after that.
2. No `.env`, no private key, no sealed secret, no PCR values. PCR0, PCR1 and PCR2 are recorded on the host from `nitro-cli build-enclave` output.

## VERIFY: does `kmstool_enclave_cli decrypt` print the KMS key id?

No. In `bin/kmstool-enclave-cli/main.c` at tag v0.4.6 (https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/v0.4.6/bin/kmstool-enclave-cli/main.c), the decrypt branch prints only one line, `PLAINTEXT: <base64>`. The enclave runs `kmstool_reply` instead (`enclave/kmstool-reply/main.c`), which prints `PLAINTEXT:` and `KEYID:`. `unsealApiKey` declines unless that key id is the baked ARN. The helper is in the Dockerfile and has not been linked yet. The first host build is the test.

Note: the CLI does pass `--key-id` to KMS as the Decrypt `KeyId` (`source/kms.c` at v0.4.6), and KMS answers `IncorrectKeyException` when `KeyId` names a different key than the one that encrypted the ciphertext (https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html, which also says the response `KeyId` is the key ARN). That is a second line of defence. It is not a replacement for the reply check, and it was not tested against a live key tonight.

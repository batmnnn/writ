# kmstool_reply

`kmstool_enclave_cli decrypt` at v0.4.6 prints only `PLAINTEXT: <base64>`. The SDK reads the `KeyId` of the KMS Decrypt response and then drops it. So the enclave could not check which key KMS used.

`kmstool_reply` makes the same attested Decrypt call with the same public SDK functions (`aws_attestation_request`, `aws_nitro_enclaves_rest_client_request_blocking`, `aws_kms_decrypt_response_from_json`, the CMS and RSA decrypt calls). It keeps the `KeyId` from the KMS JSON reply. On success it prints two lines and exits 0:

```
PLAINTEXT: <base64>
KEYID: <key ARN from the KMS reply>
```

It takes the same arguments as `kmstool_enclave_cli decrypt`, minus `--encryption-algorithm`. It exits 1 with nothing on stdout when `--key-id` is not a full key ARN, when the reply has no `KeyId`, or when the reply `KeyId` is not the requested ARN. `src/host/kms-unseal.ts` parses both lines and checks `KEYID` again against `enclave/config/kms.json`.

## Status

1. Source only. It was type-checked on a Mac with `clang -fsyntax-only -Wall -Wextra` against the headers at the commits `enclave/Dockerfile` pins. It has not been linked or run. It needs `/dev/nsm` and the vsock proxy, so it can only run inside an enclave.
2. No new dependency. It links only `aws-nitro-enclaves-sdk-c`, which the image already builds from commit `f2dbc3fb1ab9b4496ff8ebc077d24e5f24265923`.
3. `internal/cms.h` is not installed by the SDK, so `main.c` repeats its two prototypes unchanged.

## What the Dockerfile owner has to add

In the builder stage, after the SDK install step:

```
COPY enclave/kmstool-reply /tmp/crt-builder/kmstool-reply
RUN cmake -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S kmstool-reply -B kmstool-reply/build \
 && cmake --build kmstool-reply/build --target install
```

Then add `/usr/bin/kmstool_reply` to the list the rootfs step copies and runs `ldd` on. `scripts/eif.ts` must stage `enclave/kmstool-reply/` into the build context. Both files change PCR0, so the KMS key policy needs the new PCR0 after the first build.

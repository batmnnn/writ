# Writ enclave image. Target: linux/amd64 (c6i.xlarge host).
#
# Build context is the staged directory that `bun run scripts/eif.ts` makes, never the repo root.
# Every COPY below names a path. There is no `COPY .`, so .env and keys cannot enter the image.
#
# Pins:
#   Base image   by manifest list digest (public.ecr.aws/amazonlinux/amazonlinux:2023, resolved Mon Nov 9, 2026).
#   Bun          exact version plus the sha256 of the release zip, from the SHASUMS256.txt of that release.
#   lego         exact version plus the sha256 of the release tarball, from the checksums file of that release.
#   AWS SDK and C libraries   by full commit hash (the tags in Dockerfile.al2 of aws-nitro-enclaves-sdk-c v0.4.6).
#   Rust and dnf packages     AL2023 pins its package repo to the release inside the base image digest.
#                             This is a pin by repo snapshot, not by package hash.
#
# Not verified yet: this file has not been built. Docker was not running when it was written.
# It follows containers/Dockerfile.al2 of aws-nitro-enclaves-sdk-c v0.4.6, ported to AL2023
# (dnf, cmake, rust and cargo from the distro). The first build on the host is the test.
#
# Debug mode is never used with this image. PCRs of a debug mode enclave are all zeros, and
# src/host/kms-unseal.ts refuses to decrypt on zero PCRs.

# ---------------------------------------------------------------------------
FROM --platform=linux/amd64 public.ecr.aws/amazonlinux/amazonlinux@sha256:381352c430f36d8aa6b8b670de06e7e4e5642fe0cb9dbd463bb8d1e79aefc0c7 AS builder

RUN dnf install -y cmake gcc gcc-c++ git go make ninja-build perl rust cargo tar && dnf clean all

WORKDIR /tmp/crt-builder

# One fetch of one commit. `git fetch <url> <sha>` works on GitHub.
# cm: configure, build, install one CMake project. Extra arguments go to configure.
RUN set -eux; \
    pin() { git init -q "$3"; git -C "$3" fetch -q --depth 1 "https://github.com/$1" "$2"; git -C "$3" checkout -q FETCH_HEAD; }; \
    cm() { d="$1"; shift; cmake -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja "$@" -S "$d" -B "$d/build"; cmake --build "$d/build" --parallel "$(nproc)" --target install; }; \
    go env -w GOPROXY=direct; \
    pin awslabs/aws-lc                 cb7712dfa896d32d55992e2cb13d5fa54fb77002 aws-lc;           cm aws-lc; \
    pin aws/s2n-tls                    e954ee5dc878c5c343d35574e7d07246a1e59314 s2n-tls;          cm s2n-tls; \
    pin awslabs/aws-c-common           be35e65a6c67ae2ffd126516c9783ac1dd2e8910 aws-c-common;     cm aws-c-common; \
    pin awslabs/aws-c-sdkutils         e3c23f4aca31d9e66df25827645f72cbcbfb657a aws-c-sdkutils;   cm aws-c-sdkutils; \
    pin awslabs/aws-c-cal              1458c70a26877345ca28e333a092096afd410774 aws-c-cal;        cm aws-c-cal; \
    pin awslabs/aws-c-io               8f4508f5ec7d2949d5545e2b1ddcd1beb47a76a8 aws-c-io;         cm aws-c-io -DUSE_VSOCK=1; \
    pin awslabs/aws-c-compression      5fab8bc5ab5321d86f6d153b06062419080820ec aws-c-compression; cm aws-c-compression; \
    pin awslabs/aws-c-http             0600662610aa871a11aebe6ed67a11997317cbef aws-c-http;       cm aws-c-http; \
    pin awslabs/aws-c-auth             831fa583b83574db29cbae139b42e0d7a1d1ebb8 aws-c-auth;       cm aws-c-auth; \
    pin json-c/json-c                  2f2ddc1f2dbca56c874e8f9c31b5b963202d80e7 json-c;           cm json-c -DBUILD_SHARED_LIBS=OFF

# NSM library (libnsm.so and nsm.h), v0.4.0.
# Commit 4b851f3 has no Cargo.lock, so cargo cannot be passed --locked.
RUN set -eux; \
    git init -q aws-nitro-enclaves-nsm-api; \
    git -C aws-nitro-enclaves-nsm-api fetch -q --depth 1 https://github.com/aws/aws-nitro-enclaves-nsm-api 4b851f3006c6fa98f23dcffb2cba03b39de9b8af; \
    git -C aws-nitro-enclaves-nsm-api checkout -q FETCH_HEAD; \
    cd aws-nitro-enclaves-nsm-api; \
    cargo build --release --jobs "$(nproc)" -p nsm-lib; \
    mv target/release/libnsm.so /usr/lib64/; \
    mv target/release/nsm.h /usr/include/

# AWS Nitro Enclaves SDK, v0.4.6. Builds kmstool_enclave_cli.
RUN set -eux; \
    git init -q aws-nitro-enclaves-sdk-c; \
    git -C aws-nitro-enclaves-sdk-c fetch -q --depth 1 https://github.com/aws/aws-nitro-enclaves-sdk-c f2dbc3fb1ab9b4496ff8ebc077d24e5f24265923; \
    git -C aws-nitro-enclaves-sdk-c checkout -q FETCH_HEAD; \
    cmake -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-nitro-enclaves-sdk-c -B aws-nitro-enclaves-sdk-c/build; \
    cmake --build aws-nitro-enclaves-sdk-c/build --parallel "$(nproc)" --target install

# kmstool_reply: same SDK, and it keeps the KeyId the stock CLI drops.
COPY enclave/kmstool-reply /tmp/crt-builder/kmstool-reply
RUN cmake -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S kmstool-reply -B kmstool-reply/build \
 && cmake --build kmstool-reply/build --target install

# writ-nsm-pcrs: reads PCR0, PCR1 and PCR2 through libnsm for src/host/nsm.ts.
COPY enclave/nsm-pcrs /tmp/crt-builder/nsm-pcrs
RUN cmake -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S nsm-pcrs -B nsm-pcrs/build \
 && cmake --build nsm-pcrs/build --target install

# writ-attest: one NSM attestation document for a host nonce, for the attest-only boot line.
COPY enclave/nsm-attest /tmp/crt-builder/nsm-attest
RUN cmake -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S nsm-attest -B nsm-attest/build \
 && cmake --build nsm-attest/build --target install

# Collect only the shared libraries we built (not owned by an rpm). The runtime has the same base,
# so everything else is already there. Copying under /usr/lib64 avoids the /lib64 symlink.
RUN set -eux; \
    mkdir -p /rootfs/usr/bin /rootfs/usr/lib64; \
    cp -f /usr/bin/kmstool_enclave_cli /usr/bin/kmstool_reply /usr/bin/writ-nsm-pcrs /rootfs/usr/bin/; \
    cp -f /usr/bin/writ-attest /rootfs/usr/bin/; \
    for bin in /usr/bin/kmstool_enclave_cli /usr/bin/kmstool_reply /usr/bin/writ-nsm-pcrs /usr/bin/writ-attest /usr/lib64/libnsm.so; do \
      { echo "$bin"; ldd "$bin" | grep -Eo '/[^ ]+' ; } | while read -r path; do \
        case "$path" in /usr/lib64/*) ;; *) continue ;; esac; \
        if ! rpm -qf "$path" >/dev/null 2>&1; then cp -fL "$path" "/rootfs$path"; fi; \
      done; \
    done; \
    find /rootfs -type f

# ---------------------------------------------------------------------------
FROM --platform=linux/amd64 public.ecr.aws/amazonlinux/amazonlinux@sha256:381352c430f36d8aa6b8b670de06e7e4e5642fe0cb9dbd463bb8d1e79aefc0c7 AS bunfetch

RUN dnf install -y unzip && dnf clean all
RUN set -eux; \
    curl -fsSL -o bun.zip https://github.com/oven-sh/bun/releases/download/bun-v1.3.14/bun-linux-x64.zip; \
    echo "951ee2aee855f08595aeec6225226a298d3fea83a3dcd6465c09cbccdf7e848f  bun.zip" | sha256sum -c -; \
    unzip -q bun.zip; \
    install -m 0555 bun-linux-x64/bun /bun

# ---------------------------------------------------------------------------
# lego, the ACME client for the RA certificate (src/host/enclave-acme.ts).
# Pinned: lego v5.6.0 (released Oct 28, 2026), linux amd64. The sha256 is the line for
# lego_v5.6.0_linux_amd64.tar.gz in lego_5.6.0_checksums.txt of that GitHub release.
# Downloaded at build time. The binary is not in the git repo.
FROM --platform=linux/amd64 public.ecr.aws/amazonlinux/amazonlinux@sha256:381352c430f36d8aa6b8b670de06e7e4e5642fe0cb9dbd463bb8d1e79aefc0c7 AS legofetch

RUN dnf install -y tar gzip && dnf clean all
RUN set -eux; \
    mkdir -p /src /out; \
    curl -fsSL -o /src/lego.tar.gz https://github.com/go-acme/lego/releases/download/v5.6.0/lego_v5.6.0_linux_amd64.tar.gz; \
    echo "f02fc11b6f56b97e387fa7caa0268f86f5a336953b22458e6430e4651fea439a  /src/lego.tar.gz" | sha256sum -c -; \
    tar -xzf /src/lego.tar.gz -C /src lego; \
    install -m 0555 /src/lego /out/lego

# ---------------------------------------------------------------------------
FROM --platform=linux/amd64 public.ecr.aws/amazonlinux/amazonlinux@sha256:381352c430f36d8aa6b8b670de06e7e4e5642fe0cb9dbd463bb8d1e79aefc0c7 AS runtime

# iproute: `ip link set lo up` and the extra loopback addresses in boot.sh. socat: the boot line bridge
# (127.0.0.1:5000) and the S3 and Airwallex bridges (127.0.0.2:443, 127.0.0.3:443) to vsock CID 3.
RUN dnf install -y iproute socat libstdc++ && dnf clean all

COPY --from=builder /rootfs/ /
RUN ldconfig
COPY --from=bunfetch /bun /usr/local/bin/bun
COPY --from=legofetch /out/lego /usr/bin/lego

# Source and config the enclave needs. Named paths only.
COPY enclave/boot.sh /app/boot.sh
COPY enclave/config/kms.json /app/enclave/config/kms.json
COPY src/types.ts /app/src/types.ts
COPY src/host/enclave.ts /app/src/host/enclave.ts
COPY src/host/kms-unseal.ts /app/src/host/kms-unseal.ts
COPY src/host/nsm.ts /app/src/host/nsm.ts
COPY src/host/enclave-arm.ts /app/src/host/enclave-arm.ts
COPY src/core/chain.ts /app/src/core/chain.ts
COPY src/core/writ.ts /app/src/core/writ.ts
COPY src/core/merchant.ts /app/src/core/merchant.ts
COPY src/core/money.ts /app/src/core/money.ts
COPY src/core/time.ts /app/src/core/time.ts
COPY src/airwallex/units.ts /app/src/airwallex/units.ts
# Serve path: every arm goes through Gate.authorize. approvers.json is public keys only.
COPY enclave/config/approvers.json /app/enclave/config/approvers.json
COPY src/host/enclave-serve.ts /app/src/host/enclave-serve.ts
COPY src/host/enclave-tls.ts /app/src/host/enclave-tls.ts
COPY src/host/enclave-acme.ts /app/src/host/enclave-acme.ts
COPY src/host/s3-committer.ts /app/src/host/s3-committer.ts
COPY src/core/gate.ts /app/src/core/gate.ts
COPY src/core/decide.ts /app/src/core/decide.ts
COPY src/core/committer.ts /app/src/core/committer.ts
COPY src/core/ledger.ts /app/src/core/ledger.ts
COPY src/core/mutex.ts /app/src/core/mutex.ts
COPY src/core/taint.ts /app/src/core/taint.ts
# Serve entry in enclave.ts: balance and clock from Airwallex, RA handler, baked pool and reserve config.
COPY enclave/config/serve.json /app/enclave/config/serve.json
COPY src/host/enclave-balance.ts /app/src/host/enclave-balance.ts
COPY src/airwallex/ra-server.ts /app/src/airwallex/ra-server.ts
COPY src/airwallex/redact.ts /app/src/airwallex/redact.ts
# Front door, sealed ledger key, signed resume, disarm after one swipe, taint and the host credential refresh.
# taint-signer.pub.pem is the public half of the KMS key writ-taint-signer. Public key only.
COPY enclave/config/taint-signer.pub.pem /app/enclave/config/taint-signer.pub.pem
COPY src/host/enclave-app.ts /app/src/host/enclave-app.ts
COPY src/host/enclave-creds.ts /app/src/host/enclave-creds.ts
COPY src/host/enclave-keys.ts /app/src/host/enclave-keys.ts
COPY src/host/enclave-taint.ts /app/src/host/enclave-taint.ts
COPY src/host/enclave-watch.ts /app/src/host/enclave-watch.ts
RUN chmod 0555 /app/boot.sh

CMD ["/bin/sh", "/app/boot.sh"]

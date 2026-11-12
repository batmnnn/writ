// Builds the enclave container image and stages its build context.
// Usage:
//   bun run scripts/eif.ts               stage the context, then docker build if the daemon is up
//   bun run scripts/eif.ts --stage-only  stage the context and stop
//
// nitro-cli exists only on the enclave host. This script never calls it on a Mac and never
// writes PCR files. PCR0, PCR1 and PCR2 are recorded on the host from nitro-cli output.
// Debug mode is not an option here and never will be.

import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const contextDir = join(root, "dist", "eif-context");
const imageTag = "writ-enclave:dev";

// Named paths only. No .env, no keys. Keep in step with the COPY lines in enclave/Dockerfile.
const FILES = [
  "enclave/Dockerfile",
  "enclave/boot.sh",
  "enclave/config/kms.json",
  "enclave/kmstool-reply/CMakeLists.txt",
  "enclave/kmstool-reply/main.c",
  "enclave/kmstool-reply/README.md",
  "enclave/nsm-pcrs/CMakeLists.txt",
  "enclave/nsm-pcrs/main.c",
  "enclave/nsm-attest/CMakeLists.txt",
  "enclave/nsm-attest/main.c",
  "src/types.ts",
  "src/host/enclave.ts",
  "src/host/kms-unseal.ts",
  "src/host/nsm.ts",
  "src/host/enclave-arm.ts",
  "src/core/chain.ts",
  "src/core/writ.ts",
  "src/core/merchant.ts",
  "src/core/money.ts",
  "src/core/time.ts",
  "src/airwallex/units.ts",
  "enclave/config/approvers.json",
  "src/host/enclave-serve.ts",
  "src/host/enclave-tls.ts",
  "src/host/enclave-acme.ts",
  "src/host/s3-committer.ts",
  "src/core/gate.ts",
  "src/core/decide.ts",
  "src/core/committer.ts",
  "src/core/ledger.ts",
  "src/core/mutex.ts",
  "src/core/taint.ts",
  "enclave/config/serve.json",
  "src/host/enclave-balance.ts",
  "src/airwallex/ra-server.ts",
  "src/airwallex/redact.ts",
  "enclave/config/taint-signer.pub.pem",
  "src/host/enclave-app.ts",
  "src/host/enclave-creds.ts",
  "src/host/enclave-keys.ts",
  "src/host/enclave-taint.ts",
  "src/host/enclave-watch.ts",
];

function stage(): void {
  rmSync(contextDir, { recursive: true, force: true });
  for (const rel of FILES) {
    const to = join(contextDir, rel);
    mkdirSync(dirname(to), { recursive: true });
    cpSync(join(root, rel), to);
  }
  console.log(`Staged ${FILES.length} files in dist/eif-context (nothing else is in the build context).`);
}

function dockerUp(): boolean {
  const r = spawnSync("docker", ["info", "--format", "{{.ServerVersion}}"], { encoding: "utf8", timeout: 8000 });
  return r.status === 0;
}

function hostSteps(): void {
  console.log(
    [
      "",
      "nitro-cli is host-only, so no EIF was built here and no PCR file was written.",
      "On the enclave host, after the image is available there (docker save / load, or build there):",
      `  nitro-cli build-enclave --docker-uri ${imageTag} --output-file writ.eif`,
      "Record PCR0, PCR1 and PCR2 from that command's JSON output into enclave/PCR0.txt, PCR1.txt and PCR2.txt.",
      "Never start the enclave with debug mode. Check with: nitro-cli describe-enclaves (flags must not be debug).",
    ].join("\n"),
  );
}

stage();
if (process.argv.includes("--stage-only")) {
  hostSteps();
  process.exit(0);
}

if (!dockerUp()) {
  console.error("Docker daemon is not reachable. Context is staged. Start Docker and run this again, or build on the host.");
  hostSteps();
  process.exit(2);
}

const build = spawnSync(
  "docker",
  ["build", "--platform", "linux/amd64", "-f", join(contextDir, "enclave", "Dockerfile"), "-t", imageTag, contextDir],
  { stdio: "inherit" },
);
if (build.status !== 0) process.exit(build.status ?? 1);
console.log(`Built ${imageTag}.`);
hostSteps();

// Prints the commands that lock writ-demo to one image hash. Does not run them.
// Run only at feature freeze, after enclave/PCR0.txt is final.

const pcr0 = process.argv[2];
if (!pcr0 || !/^[0-9a-fA-F]{96}$/.test(pcr0)) {
  console.error("Usage: bun run scripts/make-demo-key.ts <96 hex PCR0>");
  process.exit(1);
}

const policy = {
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "ManageAndEncrypt",
      Effect: "Allow",
      Principal: { AWS: "arn:aws:iam::ACCOUNT:root" },
      Action: ["kms:CreateAlias", "kms:Describe*", "kms:Get*", "kms:List*", "kms:Encrypt"],
      Resource: "*",
    },
    {
      Sid: "EnclaveDecryptOnly",
      Effect: "Allow",
      Principal: { AWS: "arn:aws:iam::ACCOUNT:role/writ-enclave-host" },
      Action: ["kms:Decrypt", "kms:GenerateDataKey"],
      Resource: "*",
      Condition: { StringEqualsIgnoreCase: { "kms:RecipientAttestation:ImageSha384": pcr0.toLowerCase() } },
    },
  ],
};

console.log("Replace ACCOUNT with the account id, then run these yourself. This key cannot be widened later.");
console.log("");
console.log("aws kms create-key --region us-west-2 --bypass-policy-lockout-safety-check --description 'Writ demo, locked to one image' --policy '" + JSON.stringify(policy) + "'");
console.log("");
console.log("aws kms create-alias --region us-west-2 --alias-name alias/writ-demo --target-key-id <KeyId from above>");
console.log("");
console.log("Then re-seal the Airwallex key against alias/writ-demo instead of alias/writ-dev.");

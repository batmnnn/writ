// Writ schema, canonical JSON, sha256 hash and Ed25519 signatures.
// The approver signs on their own device (scripts/approve.ts). The server holds only the public key.

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import type { ApprovedTask, IsoTime, WritProposal } from "../types";
import { normalizeMerchant } from "./merchant";
import { isPositiveMinor } from "./money";
import { parseIso } from "./time";

export type UnsignedTask = Omit<ApprovedTask, "hash" | "signature">;

export interface ApprovalPolicy {
  autoApproveMinor: number;
  knownMerchants: Iterable<string>; // merchants this team has already spent at under a human-approved writ
}

/** Sorted keys at every level, no whitespace, undefined dropped. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("canonicalJson: non finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v === undefined ? null : v)).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
  }
  throw new Error(`canonicalJson: unsupported type ${typeof value}`);
}

/** sha256 hex over every field except hash and signature. */
export function writHash(task: UnsignedTask | ApprovedTask): string {
  const { hash: _h, signature: _s, ...rest } = task as ApprovedTask;
  return createHash("sha256").update(canonicalJson(rest)).digest("hex");
}

export function validateProposal(p: WritProposal): string[] {
  const errors: string[] = [];
  for (const k of ["id", "team", "agent", "runId", "purpose", "merchantName", "nonce"] as const) {
    if (typeof p[k] !== "string" || p[k].trim() === "") errors.push(`${k} is required`);
  }
  if (!isPositiveMinor(p.amountMinor)) errors.push("amountMinor must be a positive whole number of cents");
  if (p.currency !== "USD") errors.push("currency must be USD");
  if (!/^\d{4}$/.test(p.mcc)) errors.push("mcc must be 4 digits");
  if (Number.isNaN(parseIso(p.expiresAt))) errors.push("expiresAt must be an ISO time with offset");
  return errors;
}

export function buildTask(p: WritProposal, approvedAt: IsoTime, approvedBy: "auto" | "human"): UnsignedTask {
  const errors = validateProposal(p);
  const approved = parseIso(approvedAt);
  if (Number.isNaN(approved)) errors.push("approvedAt must be an ISO time with offset");
  else if (parseIso(p.expiresAt) <= approved) errors.push("expiresAt must be after approvedAt");
  if (errors.length > 0) throw new Error(`invalid writ: ${errors.join("; ")}`);
  const task: UnsignedTask = {
    id: p.id,
    team: p.team,
    agent: p.agent,
    runId: p.runId,
    purpose: p.purpose,
    merchantName: p.merchantName,
    mcc: p.mcc,
    amountMinor: p.amountMinor,
    currency: p.currency,
    expiresAt: p.expiresAt,
    nonce: p.nonce,
    approvedAt,
    approvedBy,
    singleUse: true,
  };
  if (p.evidenceUrl !== undefined) task.evidenceUrl = p.evidenceUrl;
  return task;
}

export function needsHumanApproval(p: Pick<WritProposal, "amountMinor" | "merchantName">, policy: ApprovalPolicy): boolean {
  if (p.amountMinor > policy.autoApproveMinor) return true;
  const known = new Set([...policy.knownMerchants].map(normalizeMerchant));
  return !known.has(normalizeMerchant(p.merchantName));
}

/** Human approval: Ed25519 over the hash, made with the approver's private key. */
export function signWrit(p: WritProposal, approvedAt: IsoTime, privateKeyPem: string): ApprovedTask {
  const task = buildTask(p, approvedAt, "human");
  const hash = writHash(task);
  const signature = sign(null, Buffer.from(hash, "utf8"), createPrivateKey(privateKeyPem)).toString("base64");
  return { ...task, hash, signature };
}

/** Small writ at a known merchant. Still hashed and logged, carries no signature. */
export function autoApprove(p: WritProposal, approvedAt: IsoTime, policy: ApprovalPolicy): ApprovedTask {
  if (needsHumanApproval(p, policy)) throw new Error("writ needs a human approval");
  const task = buildTask(p, approvedAt, "auto");
  return { ...task, hash: writHash(task), signature: "" };
}

export interface WritCheck {
  hashValid: boolean;
  signatureValid: boolean;
}

export function verifyWrit(writ: ApprovedTask, publicKeyPem: string, policy: ApprovalPolicy): WritCheck {
  let hashValid = false;
  try {
    hashValid = writHash(writ) === writ.hash;
  } catch {
    hashValid = false;
  }
  let signatureValid = false;
  try {
    if (writ.approvedBy === "human") {
      signatureValid =
        typeof writ.signature === "string" &&
        writ.signature.length > 0 &&
        verify(null, Buffer.from(writ.hash, "utf8"), createPublicKey(publicKeyPem), Buffer.from(writ.signature, "base64"));
    } else if (writ.approvedBy === "auto") {
      signatureValid = writ.signature === "" && !needsHumanApproval(writ, policy);
    }
  } catch {
    signatureValid = false;
  }
  return { hashValid, signatureValid };
}

export function generateApproverKeys(): { publicKeyPem: string; privateKeyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

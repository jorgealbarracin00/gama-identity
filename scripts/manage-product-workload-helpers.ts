import { randomBytes } from "node:crypto";
import { constants, fstat, read, type Stats } from "node:fs";
import { open } from "node:fs/promises";

export const APPROVED_IDENTITY_ORIGIN = "https://gama-identity-production.up.railway.app";
export const REPORTING_SCOPES = ["workload.context.read", "human.participation.register", "human.participation.backfill.preview"] as const;
export type Operation = "inspect" | "create" | "rotate" | "revoke" | "generate-secret";
export class OperatorGuardError extends Error {
  constructor(message = "The operator request failed its safety checks") { super(message); this.name = "OperatorGuardError"; }
}
export interface OperatorOptions {
  operation: Operation;
  execute: boolean;
  allowSyntheticLoopback: boolean;
  baseURL?: string;
  id?: string;
  cursor?: string;
  requestId?: string;
  productId?: string;
  expectedRevision?: number;
  capabilities?: readonly string[];
  reason?: string;
  secretFile?: string;
  bearerFile?: string;
  bearerFD?: number;
}
const identifier = /^[a-z][a-z0-9-]{0,63}$/u;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const operations = ["inspect", "create", "rotate", "revoke", "generate-secret"];
const valueFlags = new Set(["base-url", "id", "cursor", "request-id", "product-id", "expected-revision", "capabilities", "reason", "secret-file", "bearer-file", "bearer-fd"]);
function guard(value: unknown, message?: string): asserts value { if (!value) throw new OperatorGuardError(message); }

export function parseOperatorArguments(args: readonly string[]): OperatorOptions {
  guard(args[0] && operations.includes(args[0]), "Choose inspect, create, rotate, revoke or generate-secret");
  const values = new Map<string, string>();
  let execute = false, allowSyntheticLoopback = false;
  for (let index = 1; index < args.length; index++) {
    const flag = args[index];
    guard(flag && flag.startsWith("--"), "Only named operator options are accepted");
    const key = flag.slice(2);
    guard(!values.has(key), "Duplicate operator options are not accepted");
    if (key === "execute-reviewed" || key === "allow-synthetic-loopback") {
      values.set(key, "true");
      if (key === "execute-reviewed") execute = true; else allowSyntheticLoopback = true;
      continue;
    }
    guard(valueFlags.has(key), "An unsupported operator option was supplied");
    const value = args[++index];
    guard(value && !value.startsWith("--"), "An operator option is missing its value");
    values.set(key, value);
  }
  const result: OperatorOptions = {operation: args[0] as Operation, execute, allowSyntheticLoopback};
  for (const [key, field] of [["base-url", "baseURL"], ["id", "id"], ["cursor", "cursor"], ["request-id", "requestId"], ["product-id", "productId"], ["reason", "reason"], ["secret-file", "secretFile"], ["bearer-file", "bearerFile"]] as const) {
    const value = values.get(key); if (value !== undefined) result[field] = value;
  }
  for (const [key, field] of [["expected-revision", "expectedRevision"], ["bearer-fd", "bearerFD"]] as const) {
    const value = values.get(key);
    if (value !== undefined) { guard(/^(0|[1-9][0-9]*)$/u.test(value), "Numeric operator options must be canonical non-negative integers"); result[field] = Number(value); }
  }
  const scopes = values.get("capabilities"); if (scopes !== undefined) result.capabilities = scopes.split(",");
  validateOperatorOptions(result);
  return result;
}

export function approvedEndpoint(base: string, operation: Exclude<Operation, "generate-secret">, allowSyntheticLoopback = false): string {
  guard(base.length <= 240 && base === base.trim(), "Use the exact approved Identity origin");
  let url: URL; try { url = new URL(base); } catch { throw new OperatorGuardError("Use the exact approved Identity origin"); }
  guard(!url.username && !url.password && !url.search && !url.hash && url.pathname === "/", "Use an origin without credentials, path, query or fragment");
  const approved = (base === APPROVED_IDENTITY_ORIGIN || base === APPROVED_IDENTITY_ORIGIN + "/" || base === APPROVED_IDENTITY_ORIGIN + ":443" || base === APPROVED_IDENTITY_ORIGIN + ":443/") && url.origin === APPROVED_IDENTITY_ORIGIN;
  const synthetic = allowSyntheticLoopback && /^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}\/?$/u.test(base) && url.protocol === "http:" && url.hostname === "127.0.0.1" && Number(url.port) >= 1 && Number(url.port) <= 65535;
  guard(approved || synthetic, "The destination must be the approved HTTPS origin or explicit synthetic loopback");
  return new URL(`/administration/platform/workloads/${operation}`, url).href;
}

export function validateOperatorOptions(options: OperatorOptions): void {
  guard(operations.includes(options.operation), "Choose a supported operator operation");
  guard(!(options.bearerFile !== undefined && options.bearerFD !== undefined), "Use one secure bearer input");
  if (options.bearerFD !== undefined) guard(Number.isSafeInteger(options.bearerFD) && options.bearerFD >= 0 && options.bearerFD <= 1024, "Use a valid secure input descriptor");
  const allowed = options.operation === "generate-secret" ? ["secretFile"] : options.operation === "inspect" ? ["baseURL", "id", "cursor", "bearerFile", "bearerFD"] : options.operation === "create" ? ["baseURL", "id", "requestId", "productId", "capabilities", "reason", "secretFile", "bearerFile", "bearerFD"] : options.operation === "rotate" ? ["baseURL", "id", "requestId", "expectedRevision", "reason", "secretFile", "bearerFile", "bearerFD"] : ["baseURL", "id", "requestId", "expectedRevision", "reason", "bearerFile", "bearerFD"];
  for (const key of Object.keys(options)) guard(["operation", "execute", "allowSyntheticLoopback", ...allowed].includes(key), "An option does not apply to this operation");
  if (options.operation === "generate-secret") { guard(options.secretFile, "Choose a new secret file"); guard(!options.allowSyntheticLoopback, "Secret generation does not contact an endpoint"); return; }
  guard(options.baseURL, "Choose the approved Identity origin explicitly");
  approvedEndpoint(options.baseURL, options.operation, options.allowSyntheticLoopback);
  if (options.id !== undefined) guard(identifier.test(options.id), "Use a canonical workload identifier");
  if (options.cursor !== undefined) guard(identifier.test(options.cursor), "Use a canonical pagination cursor");
  if (options.operation === "inspect") guard(!(options.id && options.cursor), "Inspect by identifier or cursor, not both");
  else {
    guard(options.id && options.requestId && uuid.test(options.requestId), "Supply the exact workload and operation request identifiers");
    guard(options.reason && options.reason === options.reason.trim() && options.reason.length >= 8 && options.reason.length <= 240 && /^[^\p{Cc}\p{Cf}]+$/u.test(options.reason), "Supply a review reason of 8 to 240 ordinary characters");
    if (options.operation === "create") {
      guard(options.productId && identifier.test(options.productId), "Use a registered product identifier");
      guard(options.capabilities && options.capabilities.length >= 1 && options.capabilities.length <= 3 && new Set(options.capabilities).size === options.capabilities.length && options.capabilities.every(value => REPORTING_SCOPES.some(scope => scope === value)), "Choose explicit supported reporting scopes without duplicates");
    } else guard(Number.isSafeInteger(options.expectedRevision) && options.expectedRevision! >= 1 && options.expectedRevision! <= 2147483646, "Supply the reviewed current revision");
    if (options.operation !== "revoke") guard(options.secretFile, "Use a generated secure secret file");
  }
  if (options.execute) guard(options.bearerFile !== undefined || options.bearerFD !== undefined, "Explicit execution requires a secure fresh administrator bearer input");
}

export function validGeneratedSecret(secret: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/u.test(secret) && Buffer.from(secret, "base64url").length === 32 && Buffer.from(secret, "base64url").toString("base64url") === secret && new Set(secret).size >= 16;
}
export function normalizeCredentialInput(raw: string, kind: "bearer" | "secret"): string {
  const value = raw.replace(/\r?\n$/u, "");
  guard(kind === "secret" ? validGeneratedSecret(value) : /^[A-Za-z0-9._~-]{16,200}$/u.test(value), "The secure credential input is invalid");
  return value;
}
function validatePrivateStat(stat: {isFile(): boolean; isCharacterDevice(): boolean; mode: number; uid: number; nlink: number; size: number}, descriptor = false): void {
  const owner = process.geteuid?.();
  guard(owner !== undefined && stat.uid === owner, "Secure input must belong to the current operator");
  if (stat.isFile()) guard((stat.mode & 0o777) === 0o600 && stat.nlink === 1 && stat.size <= 4096, "Secure input must be a single-link regular file with mode 0600");
  else guard(descriptor && !stat.isCharacterDevice() && (stat.mode & 0o077) === 0, "Secure input must be a private file or non-terminal descriptor");
}
export async function readPrivateCredential(path: string, kind: "bearer" | "secret"): Promise<string> {
  try {
    const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { validatePrivateStat(await file.stat()); const buffer = Buffer.alloc(4097); const {bytesRead} = await file.read(buffer, 0, buffer.length, 0); guard(bytesRead <= 4096); return normalizeCredentialInput(buffer.subarray(0, bytesRead).toString("utf8"), kind); }
    finally { await file.close(); }
  } catch { throw new OperatorGuardError("Unable to read an owned, private, non-symlink credential file"); }
}
export async function readPrivateBearerFD(fd: number): Promise<string> {
  try {
    const stat = await new Promise<Stats>((resolve, reject) => fstat(fd, (error, value) => error ? reject(error) : resolve(value)));
    validatePrivateStat(stat, true);
    const buffer = Buffer.alloc(4097); let count = 0;
    while (count < buffer.length) {
      const size = await new Promise<number>((resolve, reject) => read(fd, buffer, count, buffer.length-count, null, (error, bytes) => error ? reject(error) : resolve(bytes)));
      if (size === 0) break; count += size;
    }
    guard(count <= 4096); return normalizeCredentialInput(buffer.subarray(0, count).toString("utf8"), "bearer");
  } catch { throw new OperatorGuardError("Unable to read a private non-terminal bearer descriptor"); }
}
export async function createPrivateSecretFile(path: string): Promise<void> {
  try {
    let value = randomBytes(32).toString("base64url");
    while (!validGeneratedSecret(value)) value = randomBytes(32).toString("base64url");
    const file = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { await file.chmod(0o600); await file.writeFile(value+"\n", "utf8"); await file.sync(); } finally { await file.close(); }
  } catch { throw new OperatorGuardError("Unable to create a new private secret file; existing paths are never overwritten"); }
}

export function dryRunSummary(options: OperatorOptions): Record<string, unknown> {
  validateOperatorOptions(options);
  return {dryRun: true, operation: options.operation, ...(options.operation === "generate-secret" ? {secretFile: options.secretFile,mode:"0600",willCreate:true} : {endpoint: approvedEndpoint(options.baseURL!, options.operation, options.allowSyntheticLoopback), ...(options.id ? {workloadId:options.id} : {}), ...(options.cursor ? {cursor:options.cursor} : {}), ...(options.productId ? {productId:options.productId} : {}), ...(options.requestId ? {requestId:options.requestId} : {}), ...(options.expectedRevision ? {expectedRevision:options.expectedRevision} : {}), ...(options.capabilities ? {capabilities:options.capabilities} : {})}), credentialsRead:false, requestSent:false};
}
export function commandPayload(options: OperatorOptions, secret?: string): Record<string, unknown> {
  validateOperatorOptions(options);
  guard(options.operation !== "generate-secret");
  if (options.operation === "inspect") return {...(options.id ? {id:options.id} : {}), ...(options.cursor ? {cursor:options.cursor} : {})};
  const payload: Record<string, unknown> = {requestId:options.requestId,id:options.id,reason:options.reason};
  if (options.operation === "create") Object.assign(payload, {productId:options.productId,capabilities:options.capabilities}); else payload.expectedRevision=options.expectedRevision;
  if (options.operation !== "revoke") { guard(secret && validGeneratedSecret(secret), "Use a generated secure secret"); payload.secret=secret; }
  return payload;
}
function safeMetadata(value: unknown): Record<string, unknown> {
  guard(value && typeof value === "object" && !Array.isArray(value)); const row=value as Record<string, unknown>;
  guard(typeof row.id === "string" && identifier.test(row.id) && typeof row.productId === "string" && identifier.test(row.productId) && ["active","retired"].includes(String(row.status)) && Number.isSafeInteger(row.revision) && Number(row.revision)>=1);
  guard(Array.isArray(row.capabilities) && row.capabilities.length>=1 && row.capabilities.length<=3 && new Set(row.capabilities).size===row.capabilities.length && row.capabilities.every(scope => REPORTING_SCOPES.some(allowed => allowed===scope)));
  guard(typeof row.createdAt === "string" && typeof row.updatedAt === "string" && Number.isFinite(Date.parse(row.createdAt)) && Number.isFinite(Date.parse(row.updatedAt)));
  return {id:row.id,productId:row.productId,status:row.status,revision:row.revision,capabilities:row.capabilities,createdAt:row.createdAt,updatedAt:row.updatedAt};
}
export function metadataOnlyResult(value: unknown, options: OperatorOptions): Record<string, unknown> {
  guard(value && typeof value === "object" && !Array.isArray(value)); const response=value as Record<string,unknown>;
  if (options.operation === "inspect") {
    guard(Array.isArray(response.workloads) && response.workloads.length<=50 && (response.nextCursor===null || (typeof response.nextCursor==="string" && identifier.test(response.nextCursor))));
    const workloads=response.workloads.map(safeMetadata);
    guard(!options.id || workloads.every(row => row.id===options.id));
    return {workloads,nextCursor:response.nextCursor,legacyPolicy:"Legacy workloads are preserved and cannot be changed through this API."};
  }
  const workload=safeMetadata(response.workload);
  guard(workload.id===options.id && (options.operation!=="create" || workload.productId===options.productId) && typeof response.replayed==="boolean");
  return {workload,replayed:response.replayed};
}
export async function executeOperatorRequest(options: OperatorOptions, bearer: string, secret: string|undefined, transport: typeof fetch = fetch): Promise<Record<string, unknown>> {
  validateOperatorOptions(options); guard(options.execute && options.operation!=="generate-secret");
  normalizeCredentialInput(bearer,"bearer");
  const payload=commandPayload(options,secret);
  const reviewMetadata=JSON.stringify({...payload,secret:undefined});
  guard(!reviewMetadata.toLowerCase().includes(bearer.toLowerCase()) && (!secret || !reviewMetadata.includes(secret)), "Credentials cannot appear in review metadata");
  try {
    const response=await transport(approvedEndpoint(options.baseURL!,options.operation,options.allowSyntheticLoopback),{method:"POST",headers:{Authorization:`Bearer ${bearer}`,"Content-Type":"application/json"},body:JSON.stringify(payload),redirect:"error",cache:"no-store",signal:AbortSignal.timeout(10000)});
    guard(response.ok, "The server rejected the operation; inspect metadata before any reviewed retry");
    const length=response.headers.get("content-length"); guard(!length || (Number.isSafeInteger(Number(length)) && Number(length)<=32768));
    const reader=response.body?.getReader(); guard(reader); let bytes=0; const chunks:Uint8Array[]=[];
    try { while (true) { const chunk=await reader.read(); if(chunk.done)break; bytes+=chunk.value.byteLength; guard(bytes<=32768); chunks.push(chunk.value); } } finally { await reader.cancel(); }
    const metadata=metadataOnlyResult(JSON.parse(Buffer.concat(chunks).toString("utf8")),options), printable=JSON.stringify(metadata);
    guard(!printable.toLowerCase().includes(bearer.toLowerCase()) && (!secret || !printable.includes(secret)), "The response cannot disclose a credential");
    return metadata;
  } catch { throw new OperatorGuardError("The reviewed request did not return safe verified metadata; preserve the request identifier and secret file for inspection and a separately reviewed retry"); }
}

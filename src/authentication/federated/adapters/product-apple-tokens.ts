import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { importPKCS8, SignJWT } from "jose";
import { AppError } from "../../../shared/errors.js";
import type { ProductAppleTokens } from "../application/product-apple-revocation.js";

export class NativeProductAppleTokens implements ProductAppleTokens {
  private readonly encryptionKey: Buffer;
  constructor(private readonly options: { clientId: string; teamId: string; keyId: string; privateKey: string; encryptionKey: string },
    private readonly request: typeof fetch = fetch) {
    this.encryptionKey = Buffer.from(options.encryptionKey, "base64");
    if (this.encryptionKey.length !== 32) throw new Error("Apple grant encryption key must be 32 bytes");
  }
  private async post(path: "token" | "revoke", fields: Record<string, string>): Promise<Response> {
    try {
      const secret = await new SignJWT({}).setProtectedHeader({ alg: "ES256", kid: this.options.keyId })
        .setIssuer(this.options.teamId).setSubject(this.options.clientId).setAudience("https://appleid.apple.com")
        .setIssuedAt().setExpirationTime("5m").sign(await importPKCS8(this.options.privateKey.replace(/\\n/g, "\n"), "ES256"));
      return await this.request(`https://appleid.apple.com/auth/${path}`, {
        method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
        signal: AbortSignal.timeout(10_000),
        body: new URLSearchParams({ client_id: this.options.clientId, client_secret: secret, ...fields }),
      });
    } catch { throw new AppError("Apple revocation temporarily unavailable", "APPLE_REVOCATION_UNAVAILABLE", 503); }
  }
  async exchange(code: string) {
    const response = await this.post("token", { code, grant_type: "authorization_code" });
    const body = await response.json().catch(() => null) as { id_token?: unknown; refresh_token?: unknown; error?: unknown } | null;
    if (!response.ok || typeof body?.id_token !== "string" || typeof body.refresh_token !== "string") {
      throw new AppError("Confirm your Apple account again to finish deletion",
        body?.error === "invalid_grant" ? "APPLE_REAUTH_REQUIRED" : "APPLE_REVOCATION_UNAVAILABLE", body?.error === "invalid_grant" ? 409 : 503);
    }
    return { identityToken: body.id_token, refreshToken: body.refresh_token };
  }
  async revoke(token: string): Promise<void> {
    const response = await this.post("revoke", { token, token_type_hint: "refresh_token" });
    if (!response.ok) throw new AppError("Apple revocation temporarily unavailable", "APPLE_REVOCATION_UNAVAILABLE", 503);
  }
  encrypt(token: string, context: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.encryptionKey, iv);
    cipher.setAAD(Buffer.from(context));
    const encrypted = Buffer.concat([cipher.update(token, "utf8"), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString("base64");
  }
  decrypt(token: string, context: string): string {
    const bytes = Buffer.from(token, "base64");
    const decipher = createDecipheriv("aes-256-gcm", this.encryptionKey, bytes.subarray(0, 12));
    decipher.setAAD(Buffer.from(context)); decipher.setAuthTag(bytes.subarray(12, 28));
    return Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString("utf8");
  }
}

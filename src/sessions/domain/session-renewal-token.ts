import { createHash, randomBytes } from "node:crypto";

export interface SessionRenewalTokenGenerator {
  next(): { readonly value: string; readonly hash: string };
  hash(value: string): string;
}

export class SecureSessionRenewalTokenGenerator implements SessionRenewalTokenGenerator {
  next(): { readonly value: string; readonly hash: string } {
    const value = randomBytes(32).toString("base64url");
    return { value, hash: this.hash(value) };
  }

  hash(value: string): string {
    if (value.length < 32 || value.length > 512) {
      throw new Error("Invalid session renewal token");
    }
    return createHash("sha256").update(value, "utf8").digest("hex");
  }
}

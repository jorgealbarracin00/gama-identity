import { createHmac } from "node:crypto";

import type { ValidateSession } from "../../sessions/application/use-cases.js";
import { SessionId } from "../../sessions/domain/session-id.js";
import type { SessionRepository } from "../../sessions/ports/session-repository.js";
import type { Clock } from "../../shared/clock.js";
import { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import type { EmailCredentialRepository } from "../credentials/ports/email-credential-repository.js";
import type { PasswordHasher } from "../credentials/ports/password-operations.js";
import type { PasswordPolicy } from "../credentials/domain/password-policy.js";
import { NormalizedEmail } from "../credentials/domain/email.js";
import type {
  EmailActionChallenge,
  EmailActionChallengeRepository,
  EmailActionPurpose,
  EmailActionTokenGenerator,
  IdentityEmailDelivery,
  IdentityEmailService,
  IdentitySecurityAction,
  IdentitySecurityAttemptRepository,
  TrustedIdentityApp,
} from "./ports.js";

export class EmailSecurityRateLimitError extends Error {}
export class EmailActionTokenError extends Error {}
export class TrustedIdentityAppError extends Error {}

export interface EmailSecurityOptions {
  readonly defaultAppId: string;
  readonly verificationTtlSeconds: number;
  readonly passwordResetTtlSeconds: number;
  readonly rateLimitWindowSeconds: number;
  readonly rateLimitMaximumAttempts: number;
  readonly rateLimitSecret: string;
}

export interface EmailAuthenticationState {
  readonly emailPassword: null | {
    readonly email: string;
    readonly verified: boolean;
  };
}

export class EmailPasswordSecurity {
  private readonly apps: ReadonlyMap<string, TrustedIdentityApp>;

  constructor(
    private readonly credentials: EmailCredentialRepository,
    private readonly sessions: SessionRepository,
    private readonly validateSession: ValidateSession,
    private readonly challenges: EmailActionChallengeRepository,
    private readonly attempts: IdentitySecurityAttemptRepository,
    private readonly emails: IdentityEmailService,
    apps: readonly TrustedIdentityApp[],
    private readonly tokens: EmailActionTokenGenerator,
    private readonly passwordPolicy: PasswordPolicy,
    private readonly passwordHasher: PasswordHasher,
    private readonly clock: Clock,
    private readonly options: EmailSecurityOptions,
    private readonly atomically: <T>(work: () => Promise<T>) => Promise<T> = async (work) => work(),
  ) {
    this.apps = new Map(apps.map((app) => [app.id, app]));
    this.app(options.defaultAppId);
  }

  async guardRegistration(email: string, ipAddress: string, appId?: string): Promise<void> {
    this.app(appId);
    const accepted = await this.rateLimit("registration", email, ipAddress);
    if (!accepted) throw new EmailSecurityRateLimitError();
  }

  get emailDeliveryAvailable(): boolean {
    return this.emails.enabled;
  }

  async sendRegistrationVerification(input: {
    readonly email: string;
    readonly appId?: string;
  }): Promise<IdentityEmailDelivery> {
    const email = NormalizedEmail.from(input.email);
    const credential = await this.credentials.findByNormalizedEmail(email);
    if (credential === null || credential.emailVerified) return "disabled";
    return this.issueAndSend(credential.id, credential.email.value, "verify_email", input.appId);
  }

  async resendVerification(input: {
    readonly sessionId: string;
    readonly appId?: string;
    readonly ipAddress: string;
  }): Promise<void> {
    const validation = await this.validateSession.execute(SessionId.from(input.sessionId));
    if (validation.outcome !== "authenticated") return;
    const credential = await this.credentials.findByHumanIdentityId(
      HumanIdentityId.from(validation.humanIdentityId),
    );
    if (credential === null || credential.emailVerified) return;
    if (!await this.rateLimit("resend_verification", credential.email.value, input.ipAddress)) return;
    await this.issueAndSend(credential.id, credential.email.value, "verify_email", input.appId);
  }

  async authenticationState(sessionId: string): Promise<EmailAuthenticationState> {
    const validation = await this.validateSession.execute(SessionId.from(sessionId));
    if (validation.outcome !== "authenticated") return { emailPassword: null };
    const credential = await this.credentials.findByHumanIdentityId(
      HumanIdentityId.from(validation.humanIdentityId),
    );
    return {
      emailPassword: credential === null ? null : {
        email: credential.email.value,
        verified: credential.emailVerified,
      },
    };
  }

  async verifyEmail(token: string, ipAddress: string): Promise<void> {
    const tokenHash = this.tokens.hash(assertTokenShape(token));
    if (!await this.rateLimit("verify_email", tokenHash, ipAddress)) {
      throw new EmailSecurityRateLimitError();
    }
    await this.atomically(async () => {
      const challenge = await this.validChallenge(tokenHash, "verify_email");
      const credential = await this.credentials.findById(challenge.credentialId);
      if (credential === null || credential.status === "retired") throw new EmailActionTokenError();
      credential.markEmailVerified(this.clock);
      await this.credentials.save(credential);
      await this.challenges.consumeActiveForCredential(
        credential.id,
        "verify_email",
        this.clock.now(),
      );
    });
  }

  async requestPasswordReset(input: {
    readonly email: string;
    readonly appId?: string;
    readonly ipAddress: string;
  }): Promise<void> {
    const app = this.app(input.appId);
    if (!await this.rateLimit("forgot_password", input.email, input.ipAddress)) return;
    let email: NormalizedEmail;
    try {
      email = NormalizedEmail.from(input.email);
    } catch {
      return;
    }
    const credential = await this.credentials.findByNormalizedEmail(email);
    if (credential === null || credential.status !== "active") return;
    await this.issueAndSend(credential.id, credential.email.value, "reset_password", app.id);
  }

  async resetPassword(input: {
    readonly token: string;
    readonly plaintextPassword: string;
    readonly ipAddress: string;
  }): Promise<void> {
    this.passwordPolicy.validate(input.plaintextPassword);
    const tokenHash = this.tokens.hash(assertTokenShape(input.token));
    if (!await this.rateLimit("reset_password", tokenHash, input.ipAddress)) {
      throw new EmailSecurityRateLimitError();
    }
    await this.atomically(async () => {
      const challenge = await this.validChallenge(tokenHash, "reset_password");
      const credential = await this.credentials.findById(challenge.credentialId);
      if (credential === null || credential.status !== "active") throw new EmailActionTokenError();
      const passwordHash = await this.passwordHasher.hash(input.plaintextPassword);
      credential.replacePassword(passwordHash, this.clock);
      credential.markEmailVerified(this.clock);
      await this.credentials.save(credential);
      const now = this.clock.now();
      await this.challenges.consumeActiveForCredential(credential.id, "reset_password", now);
      await this.challenges.consumeActiveForCredential(credential.id, "verify_email", now);
      await this.sessions.revokeByHumanIdentityId(credential.humanIdentityId);
    });
  }

  private async issueAndSend(
    credentialId: EmailActionChallenge["credentialId"],
    email: string,
    purpose: EmailActionPurpose,
    appId?: string,
  ): Promise<IdentityEmailDelivery> {
    const app = this.app(appId);
    const generated = this.tokens.next();
    const createdAt = this.clock.now();
    const ttlSeconds = purpose === "verify_email"
      ? this.options.verificationTtlSeconds
      : this.options.passwordResetTtlSeconds;
    const challenge: EmailActionChallenge = {
      id: generated.id,
      credentialId,
      appId: app.id,
      purpose,
      tokenHash: generated.hash,
      createdAt,
      expiresAt: new Date(createdAt.getTime() + ttlSeconds * 1_000),
      consumedAt: null,
    };
    await this.atomically(() => this.challenges.replaceActive(challenge));
    const path = purpose === "verify_email" ? "/auth/verify-email" : "/auth/reset-password";
    const link = `${app.baseUrl}${path}#token=${encodeURIComponent(generated.value)}`;
    const message = identityEmailTemplate(app.displayName, email, link, purpose, ttlSeconds);
    return this.emails.send(message);
  }

  private async validChallenge(
    tokenHash: string,
    purpose: EmailActionPurpose,
  ): Promise<EmailActionChallenge> {
    const challenge = await this.challenges.findByTokenHashForUpdate(tokenHash, purpose);
    const now = this.clock.now();
    if (
      challenge === null ||
      challenge.consumedAt !== null ||
      challenge.expiresAt.getTime() <= now.getTime()
    ) {
      throw new EmailActionTokenError();
    }
    return challenge;
  }

  private async rateLimit(
    action: IdentitySecurityAction,
    subject: string,
    ipAddress: string,
  ): Promise<boolean> {
    const occurredAt = this.clock.now();
    const accepted = await this.attempts.consume({
      action,
      subjectHash: this.privateHash(`subject:${subject.trim().toLowerCase()}`),
      ipHash: this.privateHash(`ip:${ipAddress}`),
      occurredAt,
      windowSeconds: this.options.rateLimitWindowSeconds,
      maximumAttempts: this.options.rateLimitMaximumAttempts,
    });
    await this.attempts.deleteOlderThan(new Date(occurredAt.getTime() - 172_800_000));
    await this.challenges.deleteStale(new Date(occurredAt.getTime() - 172_800_000));
    return accepted;
  }

  private privateHash(value: string): string {
    return createHmac("sha256", this.options.rateLimitSecret)
      .update(value, "utf8")
      .digest("base64url");
  }

  private app(appId = this.options.defaultAppId): TrustedIdentityApp {
    const app = this.apps.get(appId);
    if (app === undefined) throw new TrustedIdentityAppError();
    return app;
  }
}

function assertTokenShape(token: string): string {
  if (!/^[A-Za-z0-9_-]{43}$/u.test(token)) throw new EmailActionTokenError();
  return token;
}

function identityEmailTemplate(
  appName: string,
  email: string,
  link: string,
  purpose: EmailActionPurpose,
  ttlSeconds: number,
): { to: string; subject: string; text: string; html: string } {
  const verifying = purpose === "verify_email";
  const heading = verifying ? "Confirm your email" : "Reset your password";
  const action = verifying ? "Confirm email" : "Reset password";
  const minutes = Math.max(1, Math.floor(ttlSeconds / 60));
  const explanation = verifying
    ? `Confirm this email address to finish securing your ${appName} account.`
    : `Use this link to choose a new password for your ${appName} account.`;
  const escapedLink = escapeHtml(link);
  const escapedName = escapeHtml(appName);
  return {
    to: email,
    subject: `${heading} · ${appName}`,
    text: `${heading}\n\n${explanation}\n\n${link}\n\nThis link expires in ${minutes} minutes. If you did not request this, you can ignore this email.`,
    html: `<!doctype html><html><body style="margin:0;background:#fffaf2;color:#4b2418;font-family:Arial,sans-serif"><div style="max-width:560px;margin:0 auto;padding:40px 24px"><p style="font-size:13px;letter-spacing:.18em;font-weight:700">${escapedName.toUpperCase()}</p><h1 style="font-size:38px;line-height:1.05">${heading}</h1><p style="font-size:17px;line-height:1.6">${escapeHtml(explanation)}</p><p style="margin:30px 0"><a href="${escapedLink}" style="display:inline-block;padding:14px 22px;border-radius:999px;background:#4b2418;color:#fff;text-decoration:none;font-weight:700">${action}</a></p><p style="font-size:14px;line-height:1.55;color:#765f57">This link expires in ${minutes} minutes. If you did not request this, you can ignore this email.</p></div></body></html>`,
  };
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/gu, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  })[character]!);
}

import type { AccountCapabilities } from "../../control-plane/application/administrative-capabilities.js";
import { randomUUID } from "node:crypto";
import type { HumanIdentityRepository } from "../../identity/ports/human-identity-repository.js";
import type { SessionRepository } from "../../sessions/ports/session-repository.js";
import type { SessionId } from "../../sessions/domain/session-id.js";
import type { Clock } from "../../shared/clock.js";
import { AppError } from "../../shared/errors.js";
import type { EmailCredentialRepository } from "../credentials/ports/email-credential-repository.js";
import type { FederatedIdentityRepository } from "../federated/ports/federated-identity-repository.js";
import type { EmailPasswordSecurity } from "../email-security/application.js";
import type { EmailActionChallengeRepository } from "../email-security/ports.js";
import type { CreateEmailCredential } from "../credentials/application/use-cases.js";
import type { PasswordHasher, PasswordVerifier } from "../credentials/ports/password-operations.js";
import type { PasswordPolicy } from "../credentials/domain/password-policy.js";
import { NormalizedEmail } from "../credentials/domain/email.js";
import type { ControlPlaneRepository } from "../../control-plane/ports/control-plane-repository.js";

/** Optional self-service, deriving the sole owner from the current session. */
export class AccountManagement {
  constructor(
    private readonly humans: HumanIdentityRepository,
    private readonly sessions: SessionRepository,
    private readonly credentials: EmailCredentialRepository,
    private readonly providers: FederatedIdentityRepository,
    private readonly challenges: EmailActionChallengeRepository,
    private readonly creator: CreateEmailCredential,
    private readonly security: EmailPasswordSecurity,
    private readonly passwords: PasswordHasher & PasswordVerifier,
    private readonly policy: PasswordPolicy,
    private readonly audit: ControlPlaneRepository,
    private readonly clock: Clock,
    private readonly atomically: <T>(work: () => Promise<T>) => Promise<T>,
    readonly enabled: boolean,
    readonly capabilities: AccountCapabilities = { appleLink: true, googleLink: true, federatedUnlink: true, profile: true, emailConnect: enabled, emailUnlink: enabled, passwordChange: enabled },
  ) {}

  private gate(capability: keyof AccountCapabilities) {
    if (!this.capabilities[capability]) throw new AppError("Account management is disabled", "ACCOUNT_MANAGEMENT_DISABLED", 403);
  }

  private async owner(token: SessionId, fresh = false) {
    const initial = await this.sessions.findById(token);
    if (initial) await this.humans.lockForAccountManagement?.(initial.humanIdentityId);
    const session = await this.sessions.findByIdForUpdate(token);
    const now = this.clock.now();
    if (!session || session.status !== "active" || session.expiresAt <= now ||
      (await this.humans.findById(session.humanIdentityId))?.status !== "active") {
      throw new AppError("Sign in to continue", "SESSION_INVALID", 401);
    }
    const age = now.getTime() - session.authenticatedAt.getTime();
    if (fresh && (age < 0 || age > 300000)) throw new AppError("Sign in again before changing a method", "REAUTHENTICATION_REQUIRED", 403);
    return session;
  }

  async reauthenticationHuman(token: SessionId, ipAddress?: string): Promise<string> {
    const human = await this.atomically(async()=> (await this.owner(token)).humanIdentityId.value);
    // Commit attempts before proof verification; rejected proofs must not roll
    // back their rate-limit evidence with a later authentication transaction.
    if (ipAddress !== undefined) await this.security.guardRegistration(human + "@reauthentication.invalid", ipAddress);
    return human;
  }

  private async event(human: string, type: string) {
    await this.audit.appendAudit({ id: randomUUID(), actorReference: `human-identity:${human}`,
      subjectReference: `human-identity:${human}`, eventType: type, eventData: {}, occurredAt: this.clock.now() });
  }

  async summary(token: SessionId) {
    return this.atomically(async () => {
      const session = await this.owner(token);
      const credentials = await this.credentials.listByHumanIdentityId(session.humanIdentityId);
      const email = credentials.find(c => c.status === "active");
      const pending = credentials.find(c => c.status === "disabled");
      const challenge = pending ? await this.challenges.findLatestForCredential?.(pending.id, "link_email") : null;
      const providers = await this.providers.listByHumanIdentityId(session.humanIdentityId);
      return {
        humanIdentityId: session.humanIdentityId.value,
        emailPassword: { connected: !!email, email: email?.email.value ?? null, verified: email?.emailVerified ?? false },
        federated: providers.filter(p => p.status === "active").map(p => ({ provider: p.provider.value, email: p.providerEmail, emailPrivate: p.providerEmailPrivate })),
        pendingEmail: pending && challenge?.consumedAt === null ? { email: pending.email.value, expiresAt: challenge.expiresAt.toISOString() } : null,
        accountManagementEnabled: this.enabled,
        capabilities: this.capabilities,
        emailDeliveryAvailable: this.security.emailDeliveryAvailable,
        sessionPolicy: "Disconnecting revokes sessions authenticated by that method and sessions whose method is unknown",
      };
    });
  }

  async connectEmail(token: SessionId, input: { email: string; password: string; appId?: string; ipAddress: string }) {
    const human = await this.atomically(async () => (await this.owner(token, true)).humanIdentityId.value); this.gate("emailConnect");
    const requestedEmail = NormalizedEmail.from(input.email); this.policy.validate(input.password);
    await this.security.guardRegistration(requestedEmail.value, input.ipAddress, input.appId);
    return this.atomically(async () => {
      const owner = await this.owner(token, true); this.gate("emailConnect");
      if (owner.humanIdentityId.value !== human) throw new AppError("Sign in to continue", "SESSION_INVALID", 401);
      if (!this.security.emailDeliveryAvailable) throw new AppError("Email verification delivery is unavailable", "EMAIL_DELIVERY_UNAVAILABLE", 503);
      const email = NormalizedEmail.from(input.email);
      this.policy.validate(input.password);
      const existing = await this.credentials.findByHumanIdentityId(owner.humanIdentityId);
      let credential;
      if (existing) {
        const proof = await this.challenges.findLatestForCredential?.(existing.id, "link_email");
        if (existing.status !== "disabled" || existing.email.value !== email.value || !proof || proof.consumedAt !== null) {
          throw new AppError("This account already has an email method. Manage it before adding another.", "EMAIL_METHOD_EXISTS", 409);
        }
        // Retrying an expired pending link changes neither the owner nor its email.
        credential = existing;
        credential.replacePassword(await this.passwords.hash(input.password), this.clock);
        await this.credentials.save(credential);
      } else {
        const reserved = await this.credentials.findByNormalizedEmail(email);
        if (reserved) throw new AppError("This email cannot be connected. Use its existing sign-in or another verified address.", "EMAIL_LINK_CONFLICT", 409);
        await this.creator.execute({ humanIdentityId: owner.humanIdentityId, email: email.value, plaintextPassword: input.password });
        credential = (await this.credentials.findByHumanIdentityId(owner.humanIdentityId))!;
        credential.disable(this.clock);
        await this.credentials.save(credential);
      }
      const delivery = await this.security.sendLinkVerification(credential.id, input.appId);
      await this.event(owner.humanIdentityId.value, "authentication.email.verification_requested");
      return { humanIdentityId: owner.humanIdentityId.value, outcome: "verification_pending", delivery, email: email.value };
    });
  }

  async disconnectEmail(token: SessionId) {
    return this.atomically(async () => {
      const owner = await this.owner(token, true); this.gate("emailUnlink");
      const email = await this.credentials.findByHumanIdentityId(owner.humanIdentityId);
      if (!email) return { outcome: "already_unlinked", humanIdentityId: owner.humanIdentityId.value, reauthenticationRequired: false };
      if (email.status === "active" && !(await this.providers.listByHumanIdentityId(owner.humanIdentityId)).some(p => p.status === "active")) {
        throw new AppError("Connect and verify another sign-in method first", "LAST_AUTHENTICATION_METHOD", 409);
      }
      email.retire(this.clock);
      await this.credentials.save(email);
      for (const purpose of ["verify_email", "link_email", "reset_password"] as const) {
        await this.challenges.consumeActiveForCredential(email.id, purpose, this.clock.now());
      }
      let reauthenticationRequired = false;
      for (const session of await this.sessions.listByHumanIdentityId(owner.humanIdentityId)) {
        if (session.authenticationMethod === "email_password" || session.authenticationMethod === null) {
          await this.sessions.revoke(session.id);
          if (session.id.equals(token)) reauthenticationRequired = true;
        }
      }
      await this.event(owner.humanIdentityId.value, "authentication.email.disconnected");
      return { outcome: "unlinked", humanIdentityId: owner.humanIdentityId.value, reauthenticationRequired };
    });
  }

  async changePassword(token: SessionId, currentPassword: string, password: string, ipAddress: string) {
    const human = await this.atomically(async () => (await this.owner(token, true)).humanIdentityId.value); this.gate("passwordChange");
    await this.security.guardRegistration(human + "@password-change.invalid", ipAddress);
    return this.atomically(async () => {
      const owner = await this.owner(token, true); this.gate("passwordChange");
      this.policy.validate(password);
      const credential = await this.credentials.findByHumanIdentityId(owner.humanIdentityId);
      if (!credential || credential.status !== "active" || !await credential.verifyPassword(currentPassword, this.passwords)) {
        throw new AppError("Current password is incorrect", "PASSWORD_CHANGE_REJECTED", 403);
      }
      credential.replacePassword(await this.passwords.hash(password), this.clock);
      await this.credentials.save(credential);
      await this.challenges.consumeActiveForCredential(credential.id, "reset_password", this.clock.now());
      await this.sessions.revokeByHumanIdentityId(owner.humanIdentityId);
      await this.event(owner.humanIdentityId.value, "authentication.password.changed");
      return { humanIdentityId: owner.humanIdentityId.value, outcome: "changed", reauthenticationRequired: true };
    });
  }
}

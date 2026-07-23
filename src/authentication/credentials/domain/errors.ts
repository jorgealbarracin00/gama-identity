import type { EmailCredentialStatus } from "./email-credential.js";

export class InvalidEmailError extends Error {
  constructor() {
    super("Email address is invalid");
    this.name = "InvalidEmailError";
  }
}

export type InvalidPasswordReason =
  | "empty"
  | "too_short"
  | "too_long";

export class InvalidPasswordError extends Error {
  constructor(readonly reason: InvalidPasswordReason) {
    super(`Password input is invalid: ${reason}`);
    this.name = "InvalidPasswordError";
  }
}

export class InvalidEmailCredentialTransitionError extends Error {
  constructor(
    readonly from: EmailCredentialStatus,
    readonly to: EmailCredentialStatus,
  ) {
    super(`Email Credential cannot transition from ${from} to ${to}`);
    this.name = "InvalidEmailCredentialTransitionError";
  }
}

export class CredentialUnavailableForAuthenticationError extends Error {
  constructor(readonly status: EmailCredentialStatus) {
    super("Email Credential is unavailable for authentication");
    this.name = "CredentialUnavailableForAuthenticationError";
  }
}

export class RetiredEmailCredentialMutationError extends Error {
  constructor() {
    super("A retired Email Credential cannot be changed");
    this.name = "RetiredEmailCredentialMutationError";
  }
}

export class EmailAlreadyInUseError extends Error {
  constructor() {
    super("Normalized email is already in use");
    this.name = "EmailAlreadyInUseError";
  }
}

export type FederatedAuthenticationErrorCode =
  | "MALFORMED_CREDENTIAL"
  | "INVALID_SIGNATURE"
  | "WRONG_ISSUER"
  | "WRONG_AUDIENCE"
  | "EXPIRED_CREDENTIAL"
  | "NONCE_MISMATCH"
  | "CREDENTIAL_REPLAYED"
  | "PROVIDER_UNSUPPORTED"
  | "IDENTITY_UNAVAILABLE"
  | "FEDERATED_IDENTITY_UNAVAILABLE"
  | "FEDERATED_IDENTITY_CONFLICT"
  | "VERIFICATION_UNAVAILABLE";

export class FederatedAuthenticationError extends Error {
  constructor(readonly code: FederatedAuthenticationErrorCode) {
    super(messageFor(code));
    this.name = "FederatedAuthenticationError";
  }
}

export class FederatedIdentitySubjectConflictError extends Error {
  constructor() {
    super("The federated provider identity is already assigned");
    this.name = "FederatedIdentitySubjectConflictError";
  }
}

export class FederatedIdentityHumanProviderConflictError extends Error {
  constructor() {
    super("The Human Identity already has this federated provider assigned");
    this.name = "FederatedIdentityHumanProviderConflictError";
  }
}

function messageFor(code: FederatedAuthenticationErrorCode): string {
  switch (code) {
    case "MALFORMED_CREDENTIAL": return "The federated credential is malformed";
    case "INVALID_SIGNATURE": return "The federated credential signature is invalid";
    case "WRONG_ISSUER": return "The federated credential issuer is invalid";
    case "WRONG_AUDIENCE": return "The federated credential audience is invalid";
    case "EXPIRED_CREDENTIAL": return "The federated credential has expired";
    case "NONCE_MISMATCH": return "The federated credential nonce is invalid";
    case "CREDENTIAL_REPLAYED": return "The federated credential has already been used";
    case "PROVIDER_UNSUPPORTED": return "The federated identity provider is unsupported";
    case "IDENTITY_UNAVAILABLE": return "The Human Identity is unavailable";
    case "FEDERATED_IDENTITY_UNAVAILABLE": return "The federated identity is unavailable";
    case "FEDERATED_IDENTITY_CONFLICT": return "The federated identity cannot be assigned";
    case "VERIFICATION_UNAVAILABLE": return "Federated credential verification is unavailable";
  }
}

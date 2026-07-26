export class InvalidLoginError extends Error {
  constructor() {
    super("Invalid email or password");
    this.name = "InvalidLoginError";
  }
}

export class RegistrationFailedError extends Error {
  constructor() {
    super("Registration could not be completed");
    this.name = "RegistrationFailedError";
  }
}

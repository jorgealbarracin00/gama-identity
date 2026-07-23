import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { InvalidPasswordError } from "../../../src/authentication/credentials/domain/errors.js";
import { BaselinePasswordPolicy } from "../../../src/authentication/credentials/domain/password-policy.js";

describe("BaselinePasswordPolicy", () => {
  const policy = new BaselinePasswordPolicy();

  it("accepts passwords within the length boundary", () => {
    assert.doesNotThrow(() => policy.validate("abcdefghijkl"));
    assert.doesNotThrow(() => policy.validate("all lowercase words"));
    assert.doesNotThrow(() => policy.validate("123456789012"));
    assert.doesNotThrow(() => policy.validate("x".repeat(128)));
  });

  it("rejects empty and whitespace-only input", () => {
    for (const password of ["", " ", "\t\n"]) {
      assert.throws(
        () => policy.validate(password),
        (error: unknown) =>
          error instanceof InvalidPasswordError && error.reason === "empty",
      );
    }
  });

  it("rejects input shorter than 12 characters", () => {
    assert.throws(
      () => policy.validate("short-value"),
      (error: unknown) =>
        error instanceof InvalidPasswordError &&
        error.reason === "too_short" &&
        !error.message.includes("short-value"),
    );
  });

  it("rejects input longer than 128 characters", () => {
    assert.throws(
      () => policy.validate("x".repeat(129)),
      (error: unknown) =>
        error instanceof InvalidPasswordError && error.reason === "too_long",
    );
  });
});

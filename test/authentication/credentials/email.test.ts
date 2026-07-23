import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { NormalizedEmail } from "../../../src/authentication/credentials/domain/email.js";
import { InvalidEmailError } from "../../../src/authentication/credentials/domain/errors.js";

describe("NormalizedEmail", () => {
  it("trims whitespace and lowercases only the domain", () => {
    const email = NormalizedEmail.from("  Case.Sensitive@EXAMPLE.COM  ");

    assert.equal(email.value, "Case.Sensitive@example.com");
  });

  it("preserves local-part case for equality and uniqueness", () => {
    const upper = NormalizedEmail.from("Person@example.com");
    const lower = NormalizedEmail.from("person@example.com");

    assert.equal(upper.equals(lower), false);
    assert.equal(
      NormalizedEmail.from("Person@EXAMPLE.COM").equals(upper),
      true,
    );
  });

  it("does not perform provider-specific rewriting", () => {
    assert.equal(
      NormalizedEmail.from("first.last+news@gmail.com").value,
      "first.last+news@gmail.com",
    );
  });

  it("rejects empty and malformed addresses", () => {
    const malformed = [
      "",
      "   ",
      "missing-at.example.com",
      "@example.com",
      "person@",
      "person@@example.com",
      ".person@example.com",
      "person.@example.com",
      "first..last@example.com",
      "person@example",
      "person@-example.com",
      "person@example-.com",
      "person example@example.com",
    ];

    for (const rawEmail of malformed) {
      assert.throws(
        () => NormalizedEmail.from(rawEmail),
        InvalidEmailError,
      );
    }
  });

  it("rejects unreasonably long addresses", () => {
    assert.throws(
      () => NormalizedEmail.from(`${"a".repeat(65)}@example.com`),
      InvalidEmailError,
    );
    assert.throws(
      () =>
        NormalizedEmail.from(
          `person@${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.com`,
        ),
      InvalidEmailError,
    );
  });
});

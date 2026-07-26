import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { Argon2PasswordOperations } from "../../src/authentication/adapters/argon2-password-operations.js";
import { PasswordHash } from "../../src/authentication/credentials/domain/password.js";

describe("Argon2PasswordOperations", () => {
  const passwords = new Argon2PasswordOperations({
    memoryCost: 8192,
    timeCost: 2,
    parallelism: 1,
  });

  it("creates an Argon2id hash and verifies only the correct password", async () => {
    const hash = await passwords.hash("correct-password");
    assert.match(hash.value, /^\$argon2id\$/);
    assert.equal(await passwords.verify("correct-password", hash), true);
    assert.equal(await passwords.verify("wrong-password", hash), false);
  });

  it("fails closed for a malformed digest", async () => {
    assert.equal(
      await passwords.verify("correct-password", PasswordHash.from("invalid")),
      false,
    );
  });
});

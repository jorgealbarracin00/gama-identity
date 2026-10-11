import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { GoogleRecoveryHandoff } from "../../src/control-plane/application/google-recovery-handoff.js";
import { startGoogleRecoveryMaintenance } from "../../src/control-plane/application/google-recovery-maintenance.js";

describe("Google recovery maintenance ownership and shutdown", () => {
  it("does not invoke cleanup under the disabled production gate", async () => {
    let calls = 0;
    const h = { async expireAbandoned() { calls++; return { enabled: true, expired: 0 }; } } as GoogleRecoveryHandoff;
    await startGoogleRecoveryMaintenance(h, false, () => { throw new Error("Unexpected failure"); }).close();
    assert.equal(calls, 0);
  });
  it("coalesces overlapping ticks and waits for an in-flight batch before closing", async () => {
    let calls = 0, release!: () => void;
    const barrier = new Promise<void>(resolve => { release = resolve; });
    const h = { async expireAbandoned() { calls++; await barrier; return { enabled: true, expired: 1 }; } } as GoogleRecoveryHandoff;
    const worker = startGoogleRecoveryMaintenance(h, true, () => {}, 1_000);
    await new Promise(resolve => setTimeout(resolve, 1_100));
    assert.equal(calls, 1);
    let closed = false;
    const closing = worker.close().then(() => { closed = true; });
    await Promise.resolve(); assert.equal(closed, false);
    release(); await closing; assert.equal(closed, true);
  });
  it("reports failure without retaining provider details and validates scheduling bounds", async () => {
    let failures = 0;
    const h = { async expireAbandoned() { throw new Error("Synthetic private provider diagnostic"); } } as unknown as GoogleRecoveryHandoff;
    const worker = startGoogleRecoveryMaintenance(h, true, () => { failures++; });
    await worker.close(); assert.equal(failures, 1);
    assert.throws(() => startGoogleRecoveryMaintenance(h, true, () => {}, 999));
  });
});

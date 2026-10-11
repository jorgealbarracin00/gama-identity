import type { GoogleRecoveryHandoff } from "./google-recovery-handoff.js";

/** One bounded worker; production execution remains governed by the existing closed gate. */
export function startGoogleRecoveryMaintenance(
  handoff: GoogleRecoveryHandoff, enabled: boolean,
  onFailure: () => void, intervalMilliseconds = 30_000,
): { close(): Promise<void> } {
  if (!enabled) return { async close() {} };
  if (!Number.isInteger(intervalMilliseconds) || intervalMilliseconds < 1_000)
    throw new Error("Recovery maintenance interval is invalid");
  let pending: Promise<void> | undefined;
  let stopped = false;
  const tick = () => {
    if (stopped || pending) return;
    pending = handoff.expireAbandoned().then(() => {}, () => { onFailure(); })
      .finally(() => { pending = undefined; });
  };
  const timer = setInterval(tick, intervalMilliseconds);
  timer.unref();
  tick();
  return {
    async close() { stopped = true; clearInterval(timer); await pending; },
  };
}

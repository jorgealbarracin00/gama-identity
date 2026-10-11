import type { ObservationCase, VerificationStore } from "../application/google-recovery-verification.js";
/** Synthetic fixtures only. Production uses the transactional PostgreSQL store. */
export class MemoryGoogleVerificationStore implements VerificationStore {
  cases: ObservationCase[] = [];
  dependencies = new Map<string, { provisioningReferences: number; emailChallenges: number; appleRevocationReferences: number }>();
  async latestForUpdate() { return structuredClone(this.cases.at(-1) ?? null); }
  async save(value: ObservationCase) {
    const index = this.cases.findIndex(c => c.id === value.id);
    if (index === -1) this.cases.push(structuredClone(value)); else this.cases[index] = structuredClone(value);
  }
  async extras(human: string) { return this.dependencies.get(human) ?? { provisioningReferences: 0, emailChallenges: 0, appleRevocationReferences: 0 }; }
}

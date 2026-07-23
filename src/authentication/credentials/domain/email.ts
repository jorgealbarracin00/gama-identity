import { InvalidEmailError } from "./errors.js";

const MAX_EMAIL_LENGTH = 254;
const MAX_LOCAL_PART_LENGTH = 64;
const LOCAL_PART_PATTERN = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$/;
const DOMAIN_LABEL_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

export class NormalizedEmail {
  private constructor(readonly value: string) {}

  static from(rawEmail: string): NormalizedEmail {
    const trimmed = rawEmail.trim();
    const separator = trimmed.lastIndexOf("@");

    if (
      trimmed.length === 0 ||
      trimmed.length > MAX_EMAIL_LENGTH ||
      separator <= 0 ||
      separator !== trimmed.indexOf("@")
    ) {
      throw new InvalidEmailError();
    }

    const localPart = trimmed.slice(0, separator);
    const domainPart = trimmed.slice(separator + 1);

    if (
      localPart.length > MAX_LOCAL_PART_LENGTH ||
      !isValidLocalPart(localPart) ||
      !isValidDomain(domainPart)
    ) {
      throw new InvalidEmailError();
    }

    return new NormalizedEmail(`${localPart}@${domainPart.toLowerCase()}`);
  }

  equals(other: NormalizedEmail): boolean {
    return this.value === other.value;
  }
}

function isValidLocalPart(localPart: string): boolean {
  return (
    LOCAL_PART_PATTERN.test(localPart) &&
    !localPart.startsWith(".") &&
    !localPart.endsWith(".") &&
    !localPart.includes("..")
  );
}

function isValidDomain(domain: string): boolean {
  if (
    domain.length === 0 ||
    domain.length > 253 ||
    domain.startsWith(".") ||
    domain.endsWith(".")
  ) {
    return false;
  }

  const labels = domain.split(".");
  return (
    labels.length >= 2 &&
    labels.every((label) => DOMAIN_LABEL_PATTERN.test(label))
  );
}

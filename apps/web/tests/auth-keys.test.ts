import { describe, expect, it } from "vitest";
import {
  SCRYPT,
  deriveKey,
  generateDek,
  generateRecoveryKey,
  generateSalt,
  hashPassword,
  normalizeRecoveryKey,
  unwrapDek,
  verifyPassword,
  wrapDek,
} from "../src/server/auth/keys";

describe("key material", () => {
  it("pins scrypt parameters", () => {
    expect(SCRYPT).toEqual({ N: 32768, r: 8, p: 1, keylen: 32, maxmem: 64 * 1024 * 1024 });
  });
  it("wraps and unwraps a DEK with the password key", () => {
    const dek = generateDek();
    const salt = generateSalt();
    const kek = deriveKey("correct horse battery", salt);
    const envelope = wrapDek(dek, kek);
    expect(unwrapDek(envelope, kek)?.equals(dek)).toBe(true);
  });
  it("returns null for a wrong password instead of throwing", () => {
    const dek = generateDek();
    const salt = generateSalt();
    const envelope = wrapDek(dek, deriveKey("right-password", salt));
    expect(unwrapDek(envelope, deriveKey("wrong-password", salt))).toBeNull();
    expect(unwrapDek("garbage", deriveKey("right-password", salt))).toBeNull();
  });
  it("recovery keys are 20 Crockford symbols in 4 groups and normalise ambiguous glyphs", () => {
    const key = generateRecoveryKey();
    expect(key).toMatch(/^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){3}$/);
    expect(normalizeRecoveryKey(key.toLowerCase())).toBe(key.replace(/-/g, ""));
    expect(normalizeRecoveryKey("oil0-1")).toBe("01101");
  });
  it("password hash verifies and rejects", () => {
    const salt = generateSalt();
    const hash = hashPassword("twelve-char-pw", salt);
    expect(verifyPassword("twelve-char-pw", salt, hash)).toBe(true);
    expect(verifyPassword("twelve-char-pX", salt, hash)).toBe(false);
  });
});

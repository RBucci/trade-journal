import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";

/** Pinned so stored hashes and wraps keep verifying across releases. */
export const SCRYPT = { N: 2 ** 15, r: 8, p: 1, keylen: 32, maxmem: 64 * 1024 * 1024 } as const;

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export const generateDek = (): Buffer => randomBytes(32);
export const generateSalt = (): string => randomBytes(16).toString("hex");

export const generateRecoveryKey = (): string => {
  const bytes = randomBytes(20);
  const symbols: string[] = [];
  for (let i = 0; i < 20; i += 1) symbols.push(ALPHABET[(bytes[i] ?? 0) % 32] ?? "0");
  return [0, 5, 10, 15].map((start) => symbols.slice(start, start + 5).join("")).join("-");
};

export const normalizeRecoveryKey = (input: string): string =>
  input
    .toUpperCase()
    .replace(/[^0-9A-Z]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");

export const deriveKey = (secret: string, saltHex: string): Buffer =>
  scryptSync(secret, Buffer.from(saltHex, "hex"), SCRYPT.keylen, {
    N: SCRYPT.N,
    r: SCRYPT.r,
    p: SCRYPT.p,
    maxmem: SCRYPT.maxmem,
  });

export const wrapDek = (dek: Buffer, kek: Buffer): string => {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", kek, iv);
  const encrypted = Buffer.concat([cipher.update(dek), cipher.final()]);
  return [iv, encrypted, cipher.getAuthTag()].map((part) => part.toString("base64")).join(".");
};

export const unwrapDek = (envelope: string, kek: Buffer): Buffer | null => {
  const [iv, encrypted, tag] = envelope.split(".");
  if (!iv || !encrypted || !tag) return null;
  try {
    const decipher = createDecipheriv("aes-256-gcm", kek, Buffer.from(iv, "base64"));
    decipher.setAuthTag(Buffer.from(tag, "base64"));
    return Buffer.concat([decipher.update(Buffer.from(encrypted, "base64")), decipher.final()]);
  } catch {
    return null;
  }
};

export const hashPassword = (password: string, saltHex: string): string =>
  deriveKey(password, saltHex).toString("hex");

export const verifyPassword = (password: string, saltHex: string, hashHex: string): boolean => {
  const expected = Buffer.from(hashHex, "hex");
  const given = deriveKey(password, saltHex);
  return expected.length === given.length && timingSafeEqual(expected, given);
};

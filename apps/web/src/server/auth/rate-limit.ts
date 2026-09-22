import { isIP } from "node:net";
import { authDb } from "./db";
import { findUserByUsername, setUserLock } from "./users";

export const LIMITS = {
  ip: { attempts: 10, windowMs: 5 * 60 * 1000, blockMs: 60 * 60 * 1000 },
  user: { failures: 5, windowMs: 5 * 60 * 1000, blockMs: 360 * 60 * 1000 },
} as const;

const iso = (ms: number): string => new Date(ms).toISOString();

// ---------- IP parsing and CIDR matching ----------

const ipToBigInt = (ip: string): { value: bigint; bits: 128 } | null => {
  const mapped = ip.startsWith("::ffff:") ? ip.slice(7) : ip;
  if (isIP(mapped) === 4) {
    const parts = mapped.split(".").map(Number);
    const v4 = parts.reduce((acc, part) => (acc << 8n) + BigInt(part), 0n);
    return { value: (0xffffn << 32n) + v4, bits: 128 };
  }
  if (isIP(ip) !== 6) return null;
  const [head = "", tail = ""] = ip.split("::");
  const headParts = head ? head.split(":") : [];
  const tailParts = tail ? tail.split(":") : [];
  const missing = 8 - headParts.length - tailParts.length;
  const groups = [...headParts, ...Array<string>(Math.max(missing, 0)).fill("0"), ...tailParts];
  const value = groups.reduce(
    (acc, group) => (acc << 16n) + BigInt(parseInt(group || "0", 16)),
    0n,
  );
  return { value, bits: 128 };
};

export const ipInCidr = (ip: string, cidr: string): boolean => {
  const [base, prefixText] = cidr.split("/");
  if (!base) return false;
  const baseParsed = ipToBigInt(base);
  const ipParsed = ipToBigInt(ip);
  if (!baseParsed || !ipParsed) return false;
  const baseIsV4 = isIP(base.startsWith("::ffff:") ? base.slice(7) : base) === 4;
  const rawPrefix = prefixText === undefined ? (baseIsV4 ? 32 : 128) : Number(prefixText);
  const prefix = baseIsV4 ? rawPrefix + 96 : rawPrefix;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) return false;
  const shift = BigInt(128 - prefix);
  return baseParsed.value >> shift === ipParsed.value >> shift;
};

const normalizeCidr = (cidr: string): string => {
  const [base, prefix] = cidr.trim().split("/");
  if (!base || isIP(base) === 0) throw new Error("Invalid IP or CIDR");
  const bits = isIP(base) === 4 ? 32 : 128;
  const p = prefix === undefined ? bits : Number(prefix);
  if (!Number.isInteger(p) || p < 0 || p > bits) throw new Error("Invalid CIDR prefix");
  return `${base}/${p}`;
};

// ---------- client IP ----------

export const clientIp = (request: Request): string => {
  const trust = (process.env.JOURNAL_TRUST_PROXY ?? "true").toLowerCase() !== "false";
  if (!trust) return "unknown";
  const forwarded = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  const candidate = forwarded || request.headers.get("x-real-ip")?.trim() || "";
  return isIP(candidate) ? candidate : "unknown";
};

// ---------- blocks ----------

export const listBlocks = (now = Date.now()) =>
  (
    authDb()
      .prepare(
        "SELECT cidr, source, reason, created_at, expires_at FROM ip_blocks WHERE expires_at IS NULL OR expires_at > ? ORDER BY created_at DESC",
      )
      .all(iso(now)) as {
      cidr: string;
      source: "auto" | "manual";
      reason: string | null;
      created_at: string;
      expires_at: string | null;
    }[]
  ).map((r) => ({
    cidr: r.cidr,
    source: r.source,
    reason: r.reason,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
  }));

export const addBlock = (input: {
  cidr: string;
  reason?: string;
  expiresAt?: string | null;
  source?: "auto" | "manual";
}): void => {
  authDb()
    .prepare(
      `INSERT INTO ip_blocks (cidr, source, reason, created_at, expires_at) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(cidr) DO UPDATE SET source = excluded.source, reason = excluded.reason,
         created_at = excluded.created_at, expires_at = excluded.expires_at`,
    )
    .run(
      normalizeCidr(input.cidr),
      input.source ?? "manual",
      input.reason ?? null,
      iso(Date.now()),
      input.expiresAt ?? null,
    );
};

export const removeBlock = (cidr: string): void => {
  authDb().prepare("DELETE FROM ip_blocks WHERE cidr = ?").run(normalizeCidr(cidr));
};

export const isIpBlocked = (ip: string, now = Date.now()): boolean => {
  if (ip === "unknown") return false;
  return listBlocks(now).some((block) => ipInCidr(ip, block.cidr));
};

const blockExpiry = (ip: string, now: number): number | null => {
  if (ip === "unknown") return null;
  const rows = listBlocks(now).filter((b) => ipInCidr(ip, b.cidr));
  if (rows.length === 0) return null;
  if (rows.some((b) => b.expiresAt === null)) return Number.POSITIVE_INFINITY;
  return Math.max(...rows.map((b) => new Date(b.expiresAt as string).getTime()));
};

// ---------- attempts ----------

const countAttempts = (
  column: "ip" | "username",
  value: string,
  since: number,
  failuresOnly: boolean,
): number =>
  (
    authDb()
      .prepare(
        `SELECT COUNT(*) AS n FROM login_attempts WHERE ${column} = ? COLLATE NOCASE AND at > ?${failuresOnly ? " AND success = 0" : ""}`,
      )
      .get(value, iso(since)) as { n: number }
  ).n;

const minutesLeft = (untilMs: number, now: number): number =>
  Math.max(1, Math.ceil((untilMs - now) / 60000));

export const checkLogin = (
  ip: string,
  username: string,
  now = Date.now(),
): { allowed: true } | { allowed: false; retryAfterSec: number; message: string } => {
  const ipUntil = blockExpiry(ip, now);
  if (ipUntil !== null) {
    const retry = ipUntil === Number.POSITIVE_INFINITY ? 3600 : Math.ceil((ipUntil - now) / 1000);
    const minutes = ipUntil === Number.POSITIVE_INFINITY ? 60 : minutesLeft(ipUntil, now);
    return {
      allowed: false,
      retryAfterSec: retry,
      message: `Too many attempts. Try again in ${minutes} minutes.`,
    };
  }
  const user = findUserByUsername(username);
  if (user?.lockedUntil && new Date(user.lockedUntil).getTime() > now) {
    const until = new Date(user.lockedUntil).getTime();
    return {
      allowed: false,
      retryAfterSec: Math.ceil((until - now) / 1000),
      message: `Too many attempts. Try again in ${minutesLeft(until, now)} minutes.`,
    };
  }
  return { allowed: true };
};

export const recordAttempt = (
  ip: string,
  username: string,
  success: boolean,
  now = Date.now(),
): void => {
  authDb()
    .prepare("INSERT INTO login_attempts (username, ip, at, success) VALUES (?, ?, ?, ?)")
    .run(username, ip, iso(now), success ? 1 : 0);
  if (
    ip !== "unknown" &&
    countAttempts("ip", ip, now - LIMITS.ip.windowMs, false) >= LIMITS.ip.attempts
  ) {
    addBlock({
      cidr: ip,
      source: "auto",
      reason: "Too many login attempts",
      expiresAt: iso(now + LIMITS.ip.blockMs),
    });
    console.warn(
      `[auth] IP ${ip} blocked for ${LIMITS.ip.blockMs / 60000} minutes after ${LIMITS.ip.attempts} attempts`,
    );
  }
  if (
    !success &&
    countAttempts("username", username, now - LIMITS.user.windowMs, true) >= LIMITS.user.failures
  ) {
    const user = findUserByUsername(username);
    if (user) {
      setUserLock(user.id, iso(now + LIMITS.user.blockMs));
      console.warn(
        `[auth] user ${user.username} locked for ${LIMITS.user.blockMs / 60000} minutes after ${LIMITS.user.failures} failures (ip ${ip})`,
      );
    }
  }
  // Keep the table small: attempts older than the longest window are useless.
  authDb()
    .prepare("DELETE FROM login_attempts WHERE at < ?")
    .run(iso(now - LIMITS.user.windowMs * 2));
};

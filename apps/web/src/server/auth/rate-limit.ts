import { isIP } from "node:net";
import { authDbExists } from "@/db/paths";
import { authDb } from "./db";
import { findUserByUsername, setUserLock } from "./users";

export const LIMITS = {
  ip: { attempts: 10, windowMs: 5 * 60 * 1000, blockMs: 60 * 60 * 1000 },
  user: { failures: 5, windowMs: 5 * 60 * 1000, blockMs: 360 * 60 * 1000 },
} as const;

/** A lock further out than this was set by an administrator, not by a counter. */
const ADMIN_LOCK_THRESHOLD_MS = 365 * 24 * 60 * 60 * 1000;

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

/** "::ffff:1.2.3.4" is an IPv4 address in IPv6 clothing; anything else is not. */
const unmapV4 = (address: string): string | null => {
  if (!address.startsWith("::ffff:")) return isIP(address) === 4 ? address : null;
  const mapped = address.slice(7);
  return isIP(mapped) === 4 ? mapped : null;
};

export const ipInCidr = (ip: string, cidr: string): boolean => {
  const [rawBase, prefixText] = cidr.split("/");
  if (!rawBase) return false;
  // Count the prefix on the mapped form, so "::ffff:198.51.100.0/24" covers
  // the 256 addresses it names rather than being read as 24 bits of IPv6.
  const v4Base = unmapV4(rawBase);
  const baseParsed = ipToBigInt(v4Base ?? rawBase);
  const ipParsed = ipToBigInt(ip);
  if (!baseParsed || !ipParsed) return false;
  const rawPrefix = prefixText === undefined ? (v4Base ? 32 : 128) : Number(prefixText);
  // Rows stored before the mapped form was normalised carry a 128-bit prefix
  // on a mapped base; those bits already count from the front of the address.
  const wasMapped = v4Base !== null && rawBase.startsWith("::ffff:");
  const prefix = v4Base && !(wasMapped && rawPrefix > 32) ? rawPrefix + 96 : rawPrefix;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) return false;
  const shift = BigInt(128 - prefix);
  return baseParsed.value >> shift === ipParsed.value >> shift;
};

const normalizeCidr = (cidr: string): string => {
  const [raw, prefix] = cidr.trim().split("/");
  if (!raw || isIP(raw) === 0) throw new Error("Invalid IP or CIDR");
  // Store "::ffff:1.2.3.4" as "1.2.3.4/32": kept in its mapped form it would
  // get a /128 default that ipInCidr can only read as an unreachable /224.
  const base = unmapV4(raw) ?? raw;
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

export const listBlocks = (now = Date.now()) => {
  if (!authDbExists()) return [];
  return (
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
};

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
  if (ip === "unknown" || !authDbExists()) return false;
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

/** Failures logged for a username in the user window, whether or not it exists. */
const usernameFailures = (username: string, now: number): { count: number; oldest: number } => {
  const row = authDb()
    .prepare(
      `SELECT COUNT(*) AS n, MIN(at) AS oldest FROM login_attempts
       WHERE username = ? COLLATE NOCASE AND success = 0 AND at > ?`,
    )
    .get(username, iso(now - LIMITS.user.windowMs)) as { n: number; oldest: string | null };
  return { count: row.n, oldest: row.oldest ? Date.parse(row.oldest) : now };
};

/**
 * Drops a username's failure rows after a successful sign-in, and when an
 * administrator re-enables an account. Without it, four typos followed by the
 * correct password would still lock the account on the next typo, and clearing
 * a lock would leave the account barred by its own stale counter.
 */
export const clearUsernameFailures = (username: string): void => {
  if (!authDbExists()) return;
  authDb()
    .prepare("DELETE FROM login_attempts WHERE username = ? COLLATE NOCASE AND success = 0")
    .run(username);
};

const minutesLeft = (untilMs: number, now: number): number =>
  Math.max(1, Math.ceil((untilMs - now) / 60000));

export const checkLogin = (
  ip: string,
  username: string,
  now = Date.now(),
): { allowed: true } | { allowed: false; retryAfterSec: number; message: string } => {
  if (!authDbExists()) return { allowed: true };
  const ipUntil = blockExpiry(ip, now);
  if (ipUntil !== null) {
    if (ipUntil === Number.POSITIVE_INFINITY) {
      return {
        allowed: false,
        retryAfterSec: 3600,
        message: "Access from this address is blocked.",
      };
    }
    return {
      allowed: false,
      retryAfterSec: Math.ceil((ipUntil - now) / 1000),
      message: `Too many attempts. Try again in ${minutesLeft(ipUntil, now)} minutes.`,
    };
  }
  // Requests with no usable client address all share the name "unknown", which
  // no CIDR can match, so the block list cannot hold them. Without a window of
  // its own this is a bucket an attacker can simply choose: strip the proxy
  // header, or reach the app port directly, and the IP limit disappears.
  if (
    ip === "unknown" &&
    countAttempts("ip", "unknown", now - LIMITS.ip.windowMs, false) >= LIMITS.ip.attempts
  )
    return {
      allowed: false,
      retryAfterSec: LIMITS.ip.blockMs / 1000,
      message: `Too many attempts. Try again in ${LIMITS.ip.blockMs / 60000} minutes.`,
    };
  const user = findUserByUsername(username);
  if (user?.lockedUntil && new Date(user.lockedUntil).getTime() > now) {
    const until = new Date(user.lockedUntil).getTime();
    // An administrator disabling an account writes a year-9999 lock. Reporting
    // that as a retry time would promise a wait of millions of minutes.
    if (until - now > ADMIN_LOCK_THRESHOLD_MS)
      return { allowed: false, retryAfterSec: 3600, message: "This account has been disabled." };
    return {
      allowed: false,
      retryAfterSec: Math.ceil((until - now) / 1000),
      message: `Too many attempts. Try again in ${minutesLeft(until, now)} minutes.`,
    };
  }
  // The lock above can only exist for a real account, so answering on the
  // attempt log too keeps an unknown username indistinguishable from a real
  // one that has been locked.
  const failures = usernameFailures(username, now);
  if (failures.count >= LIMITS.user.failures) {
    const until = failures.oldest + LIMITS.user.blockMs;
    if (until > now)
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
  if (!authDbExists()) return;
  authDb()
    .prepare("INSERT INTO login_attempts (username, ip, at, success) VALUES (?, ?, ?, ?)")
    .run(username, ip, iso(now), success ? 1 : 0);
  // "unknown" attempts are recorded above and answered by checkLogin's own
  // window; they get no ip_blocks row, because no CIDR can ever match them.
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
      `[auth] IP ${ip} blocked for ${LIMITS.ip.blockMs / 60000} minutes after ${LIMITS.ip.attempts} attempts (username ${username})`,
    );
  }
  // A correct password proves the earlier failures were typos, not an attack.
  if (success) clearUsernameFailures(username);
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

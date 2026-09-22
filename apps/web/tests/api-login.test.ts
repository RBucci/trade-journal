// apps/web/tests/api-login.test.ts
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";

const scratch = mkdtempSync(join(tmpdir(), "journal-auth-test-"));
process.env.JOURNAL_DATA_DIR = scratch;
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const jar = vi.hoisted(() => ({ token: undefined as string | undefined, set: [] as unknown[] }));
vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: () => (jar.token ? { value: jar.token } : undefined),
    set: (name: string, value: string, options: unknown) => {
      jar.set.push({ name, value, options });
      jar.token = value;
    },
    delete: () => {
      jar.token = undefined;
    },
  }),
}));

const setup = await import("../src/app/api/setup/route");
const auth = await import("../src/app/api/auth/route");
const recover = await import("../src/app/api/auth/recover/route");

const post = (url: string, body: unknown, headers: Record<string, string> = {}) =>
  new Request(`http://localhost:3000${url}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
const get = (url: string) => new Request(`http://localhost:3000${url}`);

describe("setup and login routes", () => {
  let recoveryKey = "";
  it("reports setup mode, then completes setup once", async () => {
    expect(await (await auth.GET(get("/api/auth"))).json()).toMatchObject({
      setupRequired: true,
      authenticated: false,
    });
    const res = await setup.POST(
      post("/api/setup", { username: "admin", password: "admin-password-1" }),
    );
    expect(res.status).toBe(200);
    recoveryKey = (await res.json()).recoveryKey;
    expect(recoveryKey).toMatch(/^[0-9A-Z]{5}(-[0-9A-Z]{5}){3}$/);
    expect(
      (await setup.POST(post("/api/setup", { username: "x", password: "xxxxxxxxxxxx" }))).status,
    ).toBe(400);
  });
  it("logs in, reports the user, and logs out", async () => {
    const wrong = await auth.POST(
      post("/api/auth", { username: "admin", password: "nope-nope-nope" }),
    );
    expect(wrong.status).toBe(401);
    expect(await wrong.json()).toEqual({ error: "Invalid username or password." });
    const res = await auth.POST(
      post("/api/auth", { username: "admin", password: "admin-password-1" }),
    );
    expect(res.status).toBe(200);
    expect(jar.token).toMatch(/^[0-9a-f]{64}$/);
    expect(await (await auth.GET(get("/api/auth"))).json()).toMatchObject({
      authenticated: true,
      user: { username: "admin", role: "admin" },
    });
    expect((await auth.DELETE(get("/api/auth"))).status).toBe(200);
    expect(await (await auth.GET(get("/api/auth"))).json()).toMatchObject({ authenticated: false });
  });
  it("rate limits by username and answers 429 with Retry-After", async () => {
    let last: Response | undefined;
    for (let i = 0; i < 6; i += 1)
      last = await auth.POST(
        post(
          "/api/auth",
          { username: "admin", password: "bad-password-99" },
          { "x-forwarded-for": `198.51.100.${i}` },
        ),
      );
    expect(last?.status).toBe(429);
    expect(last?.headers.get("retry-after")).toMatch(/^\d+$/);
    expect((await last?.json()).error).toMatch(/Try again in 360 minutes/);
  });
  it("recovers with the recovery key and rotates it", async () => {
    const { setUserLock, findUserByUsername } = await import("../src/server/auth/users");
    const admin = findUserByUsername("admin");
    if (admin) setUserLock(admin.id, null);
    const res = await recover.POST(
      post(
        "/api/auth/recover",
        { username: "admin", recoveryKey, newPassword: "admin-password-2" },
        { "x-forwarded-for": "203.0.113.50" },
      ),
    );
    expect(res.status).toBe(200);
    const fresh = (await res.json()).recoveryKey;
    expect(fresh).not.toBe(recoveryKey);
    expect(
      (
        await auth.POST(
          post(
            "/api/auth",
            { username: "admin", password: "admin-password-2" },
            { "x-forwarded-for": "203.0.113.51" },
          ),
        )
      ).status,
    ).toBe(200);
  });
});

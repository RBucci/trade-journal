import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";

const scratch = mkdtempSync(join(tmpdir(), "journal-auth-test-"));
process.env.JOURNAL_DATA_DIR = scratch;
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const jar = vi.hoisted(() => ({ token: undefined as string | undefined }));
vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: () => (jar.token ? { value: jar.token } : undefined),
    set: (_n: string, v: string) => {
      jar.token = v;
    },
    delete: () => {
      jar.token = undefined;
    },
  }),
}));

const { createUser } = await import("../src/server/auth/users");
const { createSession } = await import("../src/server/auth/sessions");
const { userDataDir } = await import("../src/db/paths");
const { db, accounts } = await import("../src/db");
const { runWithUser } = await import("../src/server/auth/context");
const password = await import("../src/app/api/account/password/route");
const recoveryKey = await import("../src/app/api/account/recovery-key/route");
const sessions = await import("../src/app/api/account/sessions/route");
const users = await import("../src/app/api/admin/users/route");
const userById = await import("../src/app/api/admin/users/[id]/route");
const blocks = await import("../src/app/api/admin/blocks/route");
const blockByCidr = await import("../src/app/api/admin/blocks/[cidr]/route");

const json = (url: string, method: string, body?: unknown) =>
  new Request(`http://localhost:3000${url}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
const params = <T extends Record<string, string>>(p: T) => ({ params: Promise.resolve(p) });

const admin = createUser({ username: "admin", password: "admin-password-1", role: "admin" });
const asAdmin = () => {
  jar.token = createSession({ userId: admin.user.id, role: "admin", dek: admin.dek });
};

describe("account routes", () => {
  it("changes the password and regenerates the recovery key", async () => {
    asAdmin();
    expect(
      (
        await password.POST(
          json("/api/account/password", "POST", {
            currentPassword: "wrong-password-1",
            newPassword: "admin-password-2",
          }),
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await password.POST(
          json("/api/account/password", "POST", {
            currentPassword: "admin-password-1",
            newPassword: "admin-password-2",
          }),
        )
      ).status,
    ).toBe(200);
    const rk = await recoveryKey.POST(
      json("/api/account/recovery-key", "POST", { password: "admin-password-2" }),
    );
    expect(rk.status).toBe(200);
    expect((await rk.json()).recoveryKey).not.toBe(admin.recoveryKey);
  });
  it("lists sessions and signs out everywhere", async () => {
    asAdmin();
    createSession({ userId: admin.user.id, role: "admin", dek: admin.dek });
    const list = await sessions.GET(json("/api/account/sessions", "GET"));
    expect((await list.json()).sessions.length).toBeGreaterThanOrEqual(2);
    expect((await sessions.DELETE(json("/api/account/sessions", "DELETE"))).status).toBe(200);
    expect(jar.token).toBeUndefined();
  });
});

describe("admin routes", () => {
  let bobId = "";
  it("creates a user with a temporary password and recovery key", async () => {
    asAdmin();
    const res = await users.POST(
      json("/api/admin/users", "POST", { username: "bob", password: "temporary-pw-12" }),
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    bobId = body.user.id;
    expect(body.user.mustChangePassword).toBe(true);
    expect(body.recoveryKey).toMatch(/^[0-9A-Z]{5}(-[0-9A-Z]{5}){3}$/);
    expect(
      (await (await users.GET(json("/api/admin/users", "GET"))).json()).users.map(
        (u: { username: string }) => u.username,
      ),
    ).toEqual(["admin", "bob"]);
  });
  it("refuses non-admins", async () => {
    const bob = createUser({ username: "bob2", password: "bob2-password-12", role: "user" });
    jar.token = createSession({ userId: bob.user.id, role: "user", dek: bob.dek });
    expect((await users.GET(json("/api/admin/users", "GET"))).status).toBe(403);
  });
  it("locks, unlocks, promotes, and protects the last admin", async () => {
    asAdmin();
    expect(
      (
        await userById.PATCH(
          json(`/api/admin/users/${bobId}`, "PATCH", { locked: true }),
          params({ id: bobId }),
        )
      ).status,
    ).toBe(200);
    expect(
      (
        await userById.PATCH(
          json(`/api/admin/users/${bobId}`, "PATCH", { locked: false, role: "admin" }),
          params({ id: bobId }),
        )
      ).status,
    ).toBe(200);
    expect(
      (
        await userById.PATCH(
          json(`/api/admin/users/${bobId}`, "PATCH", { role: "user" }),
          params({ id: bobId }),
        )
      ).status,
    ).toBe(200);
    const self = await userById.PATCH(
      json(`/api/admin/users/${admin.user.id}`, "PATCH", { role: "user" }),
      params({ id: admin.user.id }),
    );
    expect(self.status).toBe(400);
  });
  it("deletes a user only with the confirmed username and removes their folder", async () => {
    asAdmin();
    const bob = { userId: bobId, role: "user" as const, dek: Buffer.alloc(32, 7) };
    // materialise bob's journal folder
    const bobUser = createUser({ username: "bob3", password: "bob3-password-12", role: "user" });
    runWithUser({ userId: bobUser.user.id, role: "user", dek: bobUser.dek }, () =>
      db.select().from(accounts).all(),
    );
    expect(existsSync(userDataDir(bobUser.user.id))).toBe(true);
    expect(
      (
        await userById.DELETE(
          json(`/api/admin/users/${bobUser.user.id}`, "DELETE", { confirmUsername: "wrong" }),
          params({ id: bobUser.user.id }),
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await userById.DELETE(
          json(`/api/admin/users/${bobUser.user.id}`, "DELETE", { confirmUsername: "bob3" }),
          params({ id: bobUser.user.id }),
        )
      ).status,
    ).toBe(200);
    expect(existsSync(userDataDir(bobUser.user.id))).toBe(false);
    void bob;
  });
  it("manages IP blocks", async () => {
    asAdmin();
    expect(
      (
        await blocks.POST(
          json("/api/admin/blocks", "POST", { cidr: "203.0.113.0/24", reason: "abuse" }),
        )
      ).status,
    ).toBe(200);
    expect(
      (await blocks.POST(json("/api/admin/blocks", "POST", { cidr: "not-an-ip" }))).status,
    ).toBe(400);
    const list = await (await blocks.GET(json("/api/admin/blocks", "GET"))).json();
    expect(list.blocks[0]).toMatchObject({
      cidr: "203.0.113.0/24",
      source: "manual",
      reason: "abuse",
    });
    expect(
      (
        await blockByCidr.DELETE(
          json("/api/admin/blocks/x", "DELETE"),
          params({ cidr: encodeURIComponent("203.0.113.0/24") }),
        )
      ).status,
    ).toBe(200);
    expect((await (await blocks.GET(json("/api/admin/blocks", "GET"))).json()).blocks).toEqual([]);
  });
});

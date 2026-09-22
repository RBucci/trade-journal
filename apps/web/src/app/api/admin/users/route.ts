import { bad, handler, ok } from "@/server/api";
import { createUser, listUsers } from "@/server/auth/users";

export const GET = handler(async () => ok({ users: listUsers() }), { admin: true });

export const POST = handler(
  async (request: Request) => {
    const { username, password } = (await request.json()) as {
      username?: string;
      password?: string;
    };
    if (typeof username !== "string" || typeof password !== "string")
      return bad("Username and temporary password required");
    const created = createUser({ username, password, role: "user", mustChangePassword: true });
    return ok({
      user: created.user,
      recoveryKey: created.recoveryKey,
      temporaryPassword: password,
    });
  },
  { admin: true },
);

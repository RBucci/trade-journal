import { bad, handler, ok } from "@/server/api";
import { runSetup } from "@/server/auth/setup";

export const POST = handler(
  async (request: Request) => {
    const { username, password } = (await request.json()) as {
      username?: string;
      password?: string;
    };
    if (typeof username !== "string" || typeof password !== "string")
      return bad("Username and password required");
    return ok(runSetup({ username, password }));
  },
  { public: true },
);

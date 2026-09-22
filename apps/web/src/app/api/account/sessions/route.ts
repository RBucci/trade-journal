import { cookies } from "next/headers";
import { AUTH_COOKIE } from "@/server/auth";
import { handler, ok } from "@/server/api";
import { currentUser } from "@/server/auth/context";
import { deleteUserSessions, listUserSessions } from "@/server/auth/sessions";

export const GET = handler(async () => ok({ sessions: listUserSessions(currentUser().userId) }), {
  allowPasswordChange: true,
});

export const DELETE = handler(
  async () => {
    deleteUserSessions(currentUser().userId);
    (await cookies()).delete(AUTH_COOKIE);
    return ok({ signedOut: true });
  },
  { allowPasswordChange: true },
);

import { bad, handler, ok } from "@/server/api";
import { currentUser } from "@/server/auth/context";
import { changePassword } from "@/server/auth/users";

export const POST = handler(
  async (request: Request) => {
    const { currentPassword, newPassword } = (await request.json()) as {
      currentPassword?: string;
      newPassword?: string;
    };
    if (typeof currentPassword !== "string" || typeof newPassword !== "string")
      return bad("Both passwords are required");
    const { userId } = currentUser();
    if (!changePassword(userId, currentPassword, newPassword))
      return bad("Current password is wrong");
    return ok({ changed: true });
  },
  { allowPasswordChange: true },
);

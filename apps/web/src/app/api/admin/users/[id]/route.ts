import { bad, handler, ok } from "@/server/api";
import { closeJournal } from "@/db";
import { currentUser } from "@/server/auth/context";
import { deleteUserSessions } from "@/server/auth/sessions";
import { countAdmins, deleteUser, getUser, setUserLock, setUserRole } from "@/server/auth/users";

type Ctx = { params: Promise<{ id: string }> };

export const PATCH = handler(
  async (request: Request, { params }: Ctx) => {
    const { id } = await params;
    const target = getUser(id);
    if (!target) return bad("User not found", 404);
    const body = (await request.json()) as { role?: "admin" | "user"; locked?: boolean };
    if (body.role !== undefined) {
      if (body.role !== "admin" && body.role !== "user") return bad("Invalid role");
      if (target.role === "admin" && body.role === "user" && countAdmins() <= 1)
        return bad("Cannot demote the last admin");
      if (target.id === currentUser().userId && body.role === "user")
        return bad("You cannot demote yourself");
      setUserRole(id, body.role);
    }
    if (body.locked !== undefined) {
      setUserLock(id, body.locked ? "9999-12-31T00:00:00.000Z" : null);
      if (body.locked) deleteUserSessions(id);
    }
    return ok({ user: getUser(id) });
  },
  { admin: true },
);

export const DELETE = handler(
  async (request: Request, { params }: Ctx) => {
    const { id } = await params;
    const target = getUser(id);
    if (!target) return bad("User not found", 404);
    const { confirmUsername } = (await request.json()) as { confirmUsername?: string };
    if (confirmUsername !== target.username) return bad("Type the username exactly to confirm");
    if (target.role === "admin" && countAdmins() <= 1) return bad("Cannot delete the last admin");
    if (target.id === currentUser().userId) return bad("You cannot delete yourself");
    deleteUserSessions(id);
    closeJournal(id);
    deleteUser(id);
    return ok({ deleted: true });
  },
  { admin: true },
);

import { bad, handler, ok } from "@/server/api";
import { addBlock, listBlocks } from "@/server/auth/rate-limit";

export const GET = handler(async () => ok({ blocks: listBlocks() }), { admin: true });

export const POST = handler(
  async (request: Request) => {
    const { cidr, reason, expiresAt } = (await request.json()) as {
      cidr?: string;
      reason?: string;
      expiresAt?: string | null;
    };
    if (typeof cidr !== "string") return bad("IP or CIDR required");
    if (expiresAt && Number.isNaN(Date.parse(expiresAt))) return bad("Invalid expiry");
    try {
      addBlock({
        cidr,
        reason: reason || undefined,
        expiresAt: expiresAt || null,
        source: "manual",
      });
    } catch (error) {
      return bad(error instanceof Error ? error.message : "Invalid IP or CIDR");
    }
    return ok({ blocks: listBlocks() });
  },
  { admin: true },
);

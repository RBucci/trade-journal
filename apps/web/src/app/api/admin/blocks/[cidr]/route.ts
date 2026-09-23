import { bad, handler, ok } from "@/server/api";
import { listBlocks, removeBlock } from "@/server/auth/rate-limit";

export const DELETE = handler(
  async (_request: Request, { params }: { params: Promise<{ cidr: string }> }) => {
    const { cidr } = await params;
    try {
      removeBlock(decodeURIComponent(cidr));
    } catch (error) {
      return bad(error instanceof Error ? error.message : "Invalid IP or CIDR");
    }
    return ok({ blocks: listBlocks() });
  },
  { admin: true },
);

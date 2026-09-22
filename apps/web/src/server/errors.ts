export class RequestError extends Error {}
export function requireValue(condition: unknown, message: string): asserts condition {
  if (!condition) throw new RequestError(message);
}

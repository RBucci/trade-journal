// apps/web/tests/deploy-bind.test.ts
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const repoRoot = join(import.meta.dirname, "..", "..", "..");
const read = (name: string) => readFileSync(join(repoRoot, name), "utf8");

describe("published port is configurable", () => {
  it("compose publishes on JOURNAL_BIND, so the port can be kept off the network", () => {
    // The app trusts X-Forwarded-For by default, so an operator behind a local
    // reverse proxy must be able to keep the container port off the network.
    // A hardcoded host port here would leave spoofable headers reachable.
    const ports = read("docker-compose.yml").match(/^\s*-\s*"(.+:3000)"\s*$/m)?.[1];
    expect(ports).toBe("${JOURNAL_BIND:-0.0.0.0}:${JOURNAL_PORT:-3333}:3000");
  });

  it("documents JOURNAL_BIND where the other settings are documented", () => {
    expect(read(".env.example")).toMatch(/# JOURNAL_BIND=0\.0\.0\.0/);
    expect(read("README.md")).toMatch(/\| `JOURNAL_BIND`/);
    expect(read("install_as_service.sh")).toMatch(/^JOURNAL_BIND=\$\{JOURNAL_BIND\}$/m);
  });
});

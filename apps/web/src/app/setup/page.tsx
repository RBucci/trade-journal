"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { RecoveryKeyCard } from "@/components/recovery-key-card";
import { postJson, useApi } from "@/lib/use-api";

interface SetupResult {
  recoveryKey: string;
  migrated: Record<string, number> | null;
}

export default function SetupPage() {
  const router = useRouter();
  const { data: state } = useApi<{ setupRequired: boolean }>("/api/auth");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<SetupResult | null>(null);

  useEffect(() => {
    if (state && !state.setupRequired) router.replace("/login");
  }, [state, router]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (password !== confirm) return setError("Passwords do not match");
    setBusy(true);
    setError(null);
    try {
      setResult(await postJson<SetupResult>("/api/setup", { username, password }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Setup failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-sm">
        <CardContent className="pt-6">
          {result ? (
            <div className="space-y-4">
              {result.migrated && (
                <p className="text-xs text-muted-foreground">
                  Your existing journal was moved into your encrypted journal:{" "}
                  {Object.entries(result.migrated)
                    .filter(([, n]) => n > 0)
                    .map(([table, n]) => `${table} ${n}`)
                    .join(", ")}
                  . The original is kept as journal.db.pre-encryption until you delete it.
                </p>
              )}
              <RecoveryKeyCard
                recoveryKey={result.recoveryKey}
                onAcknowledge={() => router.replace("/login")}
              />
            </div>
          ) : (
            <form onSubmit={submit} className="space-y-3">
              <div className="text-center">
                <h1 className="text-sm font-semibold">Create the administrator account</h1>
                <p className="text-xs text-muted-foreground">
                  This is the first and only setup step.
                </p>
              </div>
              <Input
                id="setup-username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Username"
                autoFocus
                autoComplete="username"
              />
              <Input
                id="setup-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Password (12+ characters)"
                autoComplete="new-password"
              />
              <Input
                id="setup-confirm"
                type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                placeholder="Confirm password"
                autoComplete="new-password"
              />
              {error && <p className="text-center text-xs text-loss">{error}</p>}
              <Button type="submit" className="w-full" disabled={busy}>
                {busy ? "Creating…" : "Create account"}
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

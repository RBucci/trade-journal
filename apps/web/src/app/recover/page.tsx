"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { RecoveryKeyCard } from "@/components/recovery-key-card";
import { postJson } from "@/lib/use-api";

export default function RecoverPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [freshKey, setFreshKey] = useState<string | null>(null);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (newPassword !== confirm) return setError("Passwords do not match");
    setBusy(true);
    setError(null);
    try {
      const result = await postJson<{ recoveryKey: string }>("/api/auth/recover", {
        username,
        recoveryKey,
        newPassword,
      });
      setFreshKey(result.recoveryKey);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Recovery failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-sm">
        <CardContent className="pt-6">
          {freshKey ? (
            <RecoveryKeyCard
              title="Password changed. Save your new recovery key"
              recoveryKey={freshKey}
              onAcknowledge={() => router.replace("/login")}
            />
          ) : (
            <form onSubmit={submit} className="space-y-3">
              <div className="text-center">
                <h1 className="text-sm font-semibold">Recover your journal</h1>
                <p className="text-xs text-muted-foreground">
                  Enter the recovery key you saved when the account was created.
                </p>
              </div>
              <Input
                id="recover-username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Username"
                autoFocus
                autoComplete="username"
              />
              <Input
                id="recover-key"
                value={recoveryKey}
                onChange={(e) => setRecoveryKey(e.target.value)}
                placeholder="XXXXX-XXXXX-XXXXX-XXXXX"
                className="font-mono"
                autoComplete="off"
              />
              <Input
                id="recover-password"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="New password (12+ characters)"
                autoComplete="new-password"
              />
              <Input
                id="recover-confirm"
                type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                placeholder="Confirm new password"
                autoComplete="new-password"
              />
              {error && <p className="text-center text-xs text-loss">{error}</p>}
              <Button type="submit" className="w-full" disabled={busy}>
                {busy ? "Recovering…" : "Set new password"}
              </Button>
              <p className="text-center text-xs">
                <Link href="/login" className="underline underline-offset-2">
                  Back to sign in
                </Link>
              </p>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

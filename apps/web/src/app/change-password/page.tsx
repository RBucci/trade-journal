"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { postJson } from "@/lib/use-api";

export default function ChangePasswordPage() {
  const router = useRouter();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (newPassword !== confirm) return setError("Passwords do not match");
    setBusy(true);
    setError(null);
    try {
      await postJson("/api/account/password", { currentPassword, newPassword });
      router.replace("/");
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Change failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-xs">
        <CardContent className="pt-6">
          <form onSubmit={submit} className="space-y-3">
            <div className="text-center">
              <h1 className="text-sm font-semibold">Choose a new password</h1>
              <p className="text-xs text-muted-foreground">
                Your temporary password must be replaced before you continue.
              </p>
            </div>
            <Input
              id="cp-current"
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              placeholder="Current password"
              autoFocus
              autoComplete="current-password"
            />
            <Input
              id="cp-new"
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="New password (12+ characters)"
              autoComplete="new-password"
            />
            <Input
              id="cp-confirm"
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              placeholder="Confirm new password"
              autoComplete="new-password"
            />
            {error && <p className="text-center text-xs text-loss">{error}</p>}
            <Button type="submit" className="w-full" disabled={busy}>
              {busy ? "Saving…" : "Save password"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

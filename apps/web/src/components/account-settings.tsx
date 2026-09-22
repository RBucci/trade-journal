"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { RecoveryKeyCard } from "@/components/recovery-key-card";
import { postJson, useApi } from "@/lib/use-api";

interface SessionRow {
  tokenHash: string;
  createdAt: string;
  lastSeenAt: string;
  ip: string | null;
  userAgent: string | null;
}

export function AccountSettings() {
  const { data, refresh } = useApi<{ sessions: SessionRow[] }>("/api/account/sessions");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [rkPassword, setRkPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [freshKey, setFreshKey] = useState<string | null>(null);

  const run = async (fn: () => Promise<void>, success: string) => {
    setError(null);
    setMessage(null);
    try {
      await fn();
      setMessage(success);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Request failed");
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Account</CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <form
          className="space-y-2"
          onSubmit={(e) => {
            e.preventDefault();
            void run(async () => {
              await postJson("/api/account/password", { currentPassword, newPassword });
              setCurrentPassword("");
              setNewPassword("");
            }, "Password changed");
          }}
        >
          <Label htmlFor="acct-current">Change password</Label>
          <Input
            id="acct-current"
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            placeholder="Current password"
            autoComplete="current-password"
          />
          <Input
            id="acct-new"
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            placeholder="New password (12+ characters)"
            autoComplete="new-password"
          />
          <Button type="submit" size="sm">
            Change password
          </Button>
        </form>

        <div className="space-y-2">
          <Label htmlFor="acct-rk-password">Recovery key</Label>
          {freshKey ? (
            <RecoveryKeyCard
              title="New recovery key"
              recoveryKey={freshKey}
              onAcknowledge={() => setFreshKey(null)}
            />
          ) : (
            <form
              className="flex gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                void run(async () => {
                  const r = await postJson<{ recoveryKey: string }>("/api/account/recovery-key", {
                    password: rkPassword,
                  });
                  setRkPassword("");
                  setFreshKey(r.recoveryKey);
                }, "Recovery key regenerated. The old one no longer works.");
              }}
            >
              <Input
                id="acct-rk-password"
                type="password"
                value={rkPassword}
                onChange={(e) => setRkPassword(e.target.value)}
                placeholder="Password to confirm"
                autoComplete="current-password"
              />
              <Button type="submit" size="sm" variant="outline">
                Regenerate
              </Button>
            </form>
          )}
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <Label>Signed-in devices</Label>
            <Button
              size="sm"
              variant="outline"
              onClick={() =>
                void run(async () => {
                  await postJson("/api/account/sessions", undefined, "DELETE");
                  window.location.assign("/login");
                }, "Signed out everywhere")
              }
            >
              Sign out everywhere
            </Button>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Last seen</TableHead>
                <TableHead>IP</TableHead>
                <TableHead>Browser</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(data?.sessions ?? []).map((s) => (
                <TableRow key={s.tokenHash}>
                  <TableCell>{new Date(s.lastSeenAt).toLocaleString()}</TableCell>
                  <TableCell>{s.ip ?? "unknown"}</TableCell>
                  <TableCell className="max-w-64 truncate">{s.userAgent ?? "unknown"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Button size="sm" variant="ghost" onClick={refresh}>
            Refresh
          </Button>
        </div>

        {message && <p className="text-xs text-muted-foreground">{message}</p>}
        {error && <p className="text-xs text-loss">{error}</p>}
      </CardContent>
    </Card>
  );
}

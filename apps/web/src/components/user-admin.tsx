"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { postJson, useApi } from "@/lib/use-api";

interface User {
  id: string;
  username: string;
  role: "admin" | "user";
  mustChangePassword: boolean;
  lockedUntil: string | null;
  createdAt: string;
}
interface Block {
  cidr: string;
  source: "auto" | "manual";
  reason: string | null;
  createdAt: string;
  expiresAt: string | null;
}
interface Created {
  user: User;
  recoveryKey: string;
  temporaryPassword: string;
}

const isLocked = (u: User) =>
  Boolean(u.lockedUntil && new Date(u.lockedUntil).getTime() > Date.now());

export function UserAdmin({ currentUserId }: { currentUserId: string }) {
  const users = useApi<{ users: User[] }>("/api/admin/users");
  const blocks = useApi<{ blocks: Block[] }>("/api/admin/blocks");
  const [error, setError] = useState<string | null>(null);
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [created, setCreated] = useState<Created | null>(null);
  const [deleting, setDeleting] = useState<User | null>(null);
  const [confirmName, setConfirmName] = useState("");
  const [cidr, setCidr] = useState("");
  const [reason, setReason] = useState("");
  const [expiresAt, setExpiresAt] = useState("");

  const act = async (fn: () => Promise<unknown>) => {
    setError(null);
    try {
      await fn();
      users.refresh();
      blocks.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Request failed");
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Users and access</CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="users">
          <TabsList>
            <TabsTrigger value="users">Users</TabsTrigger>
            <TabsTrigger value="access">Access</TabsTrigger>
          </TabsList>

          <TabsContent value="users" className="space-y-4">
            <form
              className="flex flex-wrap items-end gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                void act(async () => {
                  const r = await postJson<Created>("/api/admin/users", {
                    username: newUsername,
                    password: newPassword,
                  });
                  setCreated(r);
                  setNewUsername("");
                  setNewPassword("");
                });
              }}
            >
              <div>
                <Label htmlFor="new-username">Username</Label>
                <Input
                  id="new-username"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                />
              </div>
              <div>
                <Label htmlFor="new-temp-password">Temporary password</Label>
                <Input
                  id="new-temp-password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="12+ characters"
                />
              </div>
              <Button type="submit" size="sm">
                Create user
              </Button>
            </form>
            <p className="text-xs text-muted-foreground">
              New users must change the temporary password at first sign-in. Their recovery key is
              shown once to you; hand it over with the password. There is no admin password reset:
              without the password or the recovery key a journal cannot be opened.
            </p>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {(users.data?.users ?? []).map((u) => (
                  <TableRow key={u.id}>
                    <TableCell>{u.username}</TableCell>
                    <TableCell>{u.role}</TableCell>
                    <TableCell className="space-x-1">
                      {isLocked(u) && <Badge variant="default">locked</Badge>}
                      {u.mustChangePassword && (
                        <Badge variant="secondary">must change password</Badge>
                      )}
                      {!isLocked(u) && !u.mustChangePassword && (
                        <Badge variant="outline">active</Badge>
                      )}
                    </TableCell>
                    <TableCell className="space-x-1 text-right">
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={u.id === currentUserId}
                        onClick={() =>
                          void act(() =>
                            postJson(`/api/admin/users/${u.id}`, { locked: !isLocked(u) }, "PATCH"),
                          )
                        }
                      >
                        {isLocked(u) ? "Unlock" : "Lock"}
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={u.id === currentUserId}
                        onClick={() =>
                          void act(() =>
                            postJson(
                              `/api/admin/users/${u.id}`,
                              { role: u.role === "admin" ? "user" : "admin" },
                              "PATCH",
                            ),
                          )
                        }
                      >
                        {u.role === "admin" ? "Make user" : "Make admin"}
                      </Button>
                      <Button
                        size="sm"
                        variant="destructive"
                        disabled={u.id === currentUserId}
                        onClick={() => {
                          setDeleting(u);
                          setConfirmName("");
                        }}
                      >
                        Delete
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TabsContent>

          <TabsContent value="access" className="space-y-4">
            <form
              className="flex flex-wrap items-end gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                void act(async () => {
                  await postJson("/api/admin/blocks", {
                    cidr,
                    reason,
                    expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
                  });
                  setCidr("");
                  setReason("");
                  setExpiresAt("");
                });
              }}
            >
              <div>
                <Label htmlFor="block-cidr">IP or CIDR</Label>
                <Input
                  id="block-cidr"
                  value={cidr}
                  onChange={(e) => setCidr(e.target.value)}
                  placeholder="203.0.113.5 or 203.0.113.0/24"
                  className="font-mono"
                />
              </div>
              <div>
                <Label htmlFor="block-reason">Reason</Label>
                <Input
                  id="block-reason"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                />
              </div>
              <div>
                <Label htmlFor="block-expires">Expires (empty = permanent)</Label>
                <Input
                  id="block-expires"
                  type="datetime-local"
                  value={expiresAt}
                  onChange={(e) => setExpiresAt(e.target.value)}
                />
              </div>
              <Button type="submit" size="sm">
                Block
              </Button>
            </form>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Address</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {(blocks.data?.blocks ?? []).map((b) => (
                  <TableRow key={b.cidr}>
                    <TableCell className="font-mono">{b.cidr}</TableCell>
                    <TableCell>{b.source}</TableCell>
                    <TableCell>{b.reason ?? ""}</TableCell>
                    <TableCell>
                      {b.expiresAt ? new Date(b.expiresAt).toLocaleString() : "never"}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() =>
                          void act(() =>
                            postJson(
                              `/api/admin/blocks/${encodeURIComponent(b.cidr)}`,
                              undefined,
                              "DELETE",
                            ),
                          )
                        }
                      >
                        Unblock
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TabsContent>
        </Tabs>
        {error && <p className="mt-3 text-xs text-loss">{error}</p>}

        <Dialog open={created !== null} onOpenChange={(open) => !open && setCreated(null)}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>User {created?.user.username} created</DialogTitle>
              <DialogDescription>
                Give the user both values. They are not shown again.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-2 text-sm">
              <p>Temporary password</p>
              <code className="block select-all rounded border bg-muted px-3 py-2 font-mono">
                {created?.temporaryPassword}
              </code>
              <p>Recovery key</p>
              <code className="block select-all rounded border bg-muted px-3 py-2 text-center font-mono tracking-wider">
                {created?.recoveryKey}
              </code>
            </div>
            <Button onClick={() => setCreated(null)}>Done</Button>
          </DialogContent>
        </Dialog>

        <Dialog open={deleting !== null} onOpenChange={(open) => !open && setDeleting(null)}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Delete {deleting?.username}?</DialogTitle>
              <DialogDescription>
                This deletes their encrypted journal permanently. Type the username to confirm.
              </DialogDescription>
            </DialogHeader>
            <Input
              id="delete-confirm"
              value={confirmName}
              onChange={(e) => setConfirmName(e.target.value)}
              placeholder={deleting?.username}
            />
            <Button
              variant="destructive"
              disabled={confirmName !== deleting?.username}
              onClick={() =>
                void act(async () => {
                  if (!deleting) return;
                  await postJson(
                    `/api/admin/users/${deleting.id}`,
                    { confirmUsername: confirmName },
                    "DELETE",
                  );
                  setDeleting(null);
                })
              }
            >
              Delete user and journal
            </Button>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  );
}

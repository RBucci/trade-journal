"use client";

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { postJson, useApi } from "@/lib/use-api";

export default function LoginPage() {
  return (
    <Suspense>
      <Login />
    </Suspense>
  );
}

function Login() {
  const router = useRouter();
  const search = useSearchParams();
  const { data: state } = useApi<{ setupRequired: boolean; authenticated: boolean }>("/api/auth");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (state?.setupRequired) router.replace("/setup");
    else if (state?.authenticated) router.replace("/");
  }, [state, router]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await postJson<{ mustChangePassword: boolean }>("/api/auth", {
        username,
        password,
      });
      router.push(result.mustChangePassword ? "/change-password" : "/");
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Sign in failed");
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
              <h1 className="text-sm font-semibold">Trade Journal</h1>
              {search.get("reason") === "restart" && (
                <p className="text-xs text-muted-foreground">
                  The server restarted. Please sign in again.
                </p>
              )}
            </div>
            <Input
              id="login-username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Username"
              autoFocus
              autoComplete="username"
            />
            <Input
              id="login-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
              autoComplete="current-password"
            />
            {error && <p className="text-center text-xs text-loss">{error}</p>}
            <Button type="submit" className="w-full" disabled={busy}>
              {busy ? "Signing in…" : "Sign in"}
            </Button>
            <p className="text-center text-xs">
              <Link href="/recover" className="underline underline-offset-2">
                Forgot password
              </Link>
            </p>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

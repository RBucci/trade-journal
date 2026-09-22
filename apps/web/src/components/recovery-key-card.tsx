"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";

export function RecoveryKeyCard({
  recoveryKey,
  onAcknowledge,
  title = "Save your recovery key",
}: {
  recoveryKey: string;
  onAcknowledge: () => void;
  title?: string;
}) {
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  return (
    <div className="space-y-3">
      <h2 className="text-sm font-semibold">{title}</h2>
      <p className="text-xs text-muted-foreground">
        This key is the only way to open your journal if you forget your password. It is shown once.
        Nobody, including the administrator, can recover a journal without the password or this key.
      </p>
      <code className="block select-all rounded border bg-muted px-3 py-2 text-center font-mono text-base tracking-wider">
        {recoveryKey}
      </code>
      <Button
        type="button"
        variant="outline"
        className="w-full"
        onClick={async () => {
          await navigator.clipboard.writeText(recoveryKey);
          setCopied(true);
        }}
      >
        {copied ? "Copied" : "Copy to clipboard"}
      </Button>
      <div className="flex items-center gap-2">
        <Checkbox
          id="recovery-saved"
          checked={saved}
          onCheckedChange={(v) => setSaved(v === true)}
        />
        <Label htmlFor="recovery-saved" className="text-xs">
          I have saved this key somewhere safe
        </Label>
      </div>
      <Button type="button" className="w-full" disabled={!saved} onClick={onAcknowledge}>
        Continue
      </Button>
    </div>
  );
}

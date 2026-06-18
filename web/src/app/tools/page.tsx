"use client";

// /tools — authorized Kali tool pass-through.
//
// The picker is fed by GET /v1/tools (aegis/tools/catalog.py::list_tools),
// filtered to the Kali family since the POST endpoint is /v1/tools/kali/
// {tool}. Tool effect classification ("read"/"active"/"external") comes
// straight off the catalog: active tools (sqlmap/hydra/metasploit/wpscan)
// need execute=true + the approver role; read tools run at remediator.
// The server enforces the same gate.

import { useState } from "react";
import useSWR from "swr";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
  RoleGated,
  type Role,
} from "@aegis/design-system";
import {
  listTools,
  runKaliTool,
  type ToolOutcome,
  type ToolSpec,
} from "@/lib/api";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { useRoles } from "@/hooks/useRoles";

export default function ToolsPage() {
  const authed = useRequireAuth();
  const { roles } = useRoles();

  const { data, error: toolsError } = useSWR<ToolSpec[]>(
    authed ? "/v1/tools" : null,
    listTools,
  );
  // Only the Kali family is invokable through this page (the pass-through
  // endpoint is /v1/tools/kali/{tool}); scanner/cai/osint tools run via
  // their own flows.
  const tools = (data ?? []).filter((t) => t.source === "kali");

  const [toolName, setToolName] = useState<string>("");
  const [target, setTarget] = useState("");
  const [paramsText, setParamsText] = useState("{}");
  const [execute, setExecute] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<ToolOutcome | null>(null);

  if (!authed)
    return <p className="text-muted-foreground">Redirecting to sign in…</p>;

  const selectedName = toolName || tools[0]?.name || "";
  const tool = tools.find((t) => t.name === selectedName);
  const isActive = tool ? tool.effect !== "read" : false;
  const minRole: Role = isActive ? "approver" : "remediator";
  const callerRole = roles["default"];

  // Active tools only perform their irreversible step with execute=true.
  const willExecute = isActive ? execute : false;

  const parseParams = (): Record<string, unknown> | null => {
    let parsed: Record<string, unknown> = {};
    if (paramsText.trim()) {
      try {
        const obj = JSON.parse(paramsText);
        if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
          setErr("Params must be a JSON object.");
          return null;
        }
        parsed = obj as Record<string, unknown>;
      } catch {
        setErr("Params is not valid JSON.");
        return null;
      }
    }
    if (target.trim() && parsed.target === undefined) {
      parsed.target = target.trim();
    }
    return parsed;
  };

  const invoke = async () => {
    setErr(null);
    if (!tool) {
      setErr("No tool selected.");
      return;
    }
    const params = parseParams();
    if (params === null) return;
    setBusy(true);
    setOutcome(null);
    try {
      const out = await runKaliTool(tool.name, {
        execute: willExecute,
        params,
      });
      setOutcome(out);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Tools</h1>

      <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900">
        <strong>Safety:</strong> run tools only against targets you are
        authorized to test. Active tools (sqlmap, hydra, metasploit, wpscan)
        are state-changing and require the approver role plus an explicit
        Execute toggle and confirmation.
      </div>

      {err && (
        <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-900">
          {err}
        </p>
      )}

      <div className="space-y-4 rounded-md border border-border bg-card p-4 text-card-foreground">
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="block space-y-1 text-sm">
            <span className="text-muted-foreground">Tool</span>
            <select
              aria-label="Tool"
              value={selectedName}
              onChange={(e) => setToolName(e.target.value)}
              disabled={tools.length === 0}
              className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm disabled:opacity-50"
            >
              {tools.length === 0 ? (
                <option value="">
                  {toolsError ? "Failed to load tools" : "Loading tools…"}
                </option>
              ) : (
                tools.map((t) => (
                  <option key={t.name} value={t.name}>
                    {t.name}
                    {t.effect !== "read" ? " (active)" : ""}
                  </option>
                ))
              )}
            </select>
          </label>

          <label className="block space-y-1 text-sm">
            <span className="text-muted-foreground">Target</span>
            <input
              aria-label="Target"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="authorized-target.example"
              className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm"
            />
          </label>
        </div>

        <label className="block space-y-1 text-sm">
          <span className="text-muted-foreground">Params (JSON)</span>
          <textarea
            aria-label="Params"
            value={paramsText}
            onChange={(e) => setParamsText(e.target.value)}
            rows={5}
            className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm"
          />
        </label>

        {isActive && (
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              aria-label="Execute"
              checked={execute}
              onChange={(e) => setExecute(e.target.checked)}
            />
            <span>
              Execute (run the active tool for real — without this the server
              returns a pending-approval proposal)
            </span>
          </label>
        )}

        {isActive ? (
          <RoleGated
            minRole={minRole}
            callerRole={callerRole}
            fallback={
              <p className="text-sm text-muted-foreground">
                This is an active tool and requires the approver role.
              </p>
            }
          >
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <button
                  disabled={busy}
                  className="rounded-md bg-destructive px-4 py-2 text-sm text-white hover:opacity-90 disabled:opacity-50"
                >
                  {willExecute ? "Execute tool" : "Submit (proposal)"}
                </button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>
                    {willExecute
                      ? `Execute ${selectedName} against the target?`
                      : `Submit ${selectedName} proposal?`}
                  </AlertDialogTitle>
                  <AlertDialogDescription>
                    {willExecute
                      ? "This runs an active, state-changing tool against the target. Only proceed against authorized targets."
                      : "Execute is off — the server will return a pending-approval proposal rather than running the tool."}
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction variant="destructive" onClick={invoke}>
                    {willExecute ? "Execute" : "Submit"}
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </RoleGated>
        ) : (
          <RoleGated
            minRole={minRole}
            callerRole={callerRole}
            fallback={
              <p className="text-sm text-muted-foreground">
                Running a tool requires the remediator role.
              </p>
            }
          >
            <button
              disabled={busy}
              onClick={invoke}
              className="rounded-md bg-primary px-4 py-2 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              Run tool
            </button>
          </RoleGated>
        )}
      </div>

      {busy && <p className="text-sm text-muted-foreground">Running…</p>}

      {outcome && (
        <div className="space-y-3 rounded-md border border-border bg-card p-4 text-card-foreground">
          <h2 className="text-sm uppercase tracking-wide text-muted-foreground">
            Outcome
          </h2>
          {outcome.status === "pending_approval" ? (
            <p className="text-sm text-amber-700">
              {outcome.message ??
                "Pending approval — resubmit with Execute enabled."}
            </p>
          ) : (
            <>
              <dl className="grid grid-cols-[auto,1fr] gap-x-4 gap-y-1 text-sm">
                <dt className="text-muted-foreground">Tool</dt>
                <dd className="font-mono">{outcome.tool}</dd>
                <dt className="text-muted-foreground">Return code</dt>
                <dd className="font-mono">{outcome.return_code ?? "—"}</dd>
                <dt className="text-muted-foreground">Success</dt>
                <dd className="font-mono">{String(outcome.success ?? false)}</dd>
              </dl>
              {outcome.error && (
                <p className="text-sm text-red-700">{outcome.error}</p>
              )}
              <div className="space-y-1">
                <p className="text-xs uppercase text-muted-foreground">stdout</p>
                <pre className="max-h-72 overflow-auto rounded bg-muted p-3 font-mono text-xs text-foreground">
                  {outcome.stdout || "(empty)"}
                </pre>
              </div>
              <div className="space-y-1">
                <p className="text-xs uppercase text-muted-foreground">stderr</p>
                <pre className="max-h-72 overflow-auto rounded bg-muted p-3 font-mono text-xs text-foreground">
                  {outcome.stderr || "(empty)"}
                </pre>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

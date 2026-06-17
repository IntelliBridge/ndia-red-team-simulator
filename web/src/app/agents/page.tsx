"use client";

// /agents — invoke a registered CAI agent.
//
// No GET listing endpoint exists for agents (aegis/api/v1/agents.py only
// exposes POST /{name}/run), so the picker is a curated list mirroring the
// wired agents in aegis/agents/cai/builtins.py. The `effect` column there
// ("read" vs "active") is the human gate: active/offensive agents need the
// approver role + execute=true + an explicit confirmation, exactly like the
// API enforces (Action.AGENT_EXECUTE → approver).

import { useState } from "react";

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
  runAgent,
  type AgentRunResult,
  type ProjectMembership,
} from "@/lib/api";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { useRoles } from "@/hooks/useRoles";

type AgentEffect = "read" | "active";

type AgentDef = {
  name: string;
  domain: string;
  effect: AgentEffect;
};

// Mirrors _WIRED in aegis/agents/cai/builtins.py (name, domain, effect).
const AGENTS: AgentDef[] = [
  { name: "codeagent", domain: "remediation", effect: "read" },
  { name: "blueteam_agent", domain: "defensive", effect: "active" },
  { name: "bug_bounter", domain: "offensive", effect: "active" },
  { name: "red_teamer", domain: "offensive", effect: "active" },
  { name: "dfir", domain: "forensic", effect: "read" },
  { name: "retester", domain: "audit", effect: "active" },
  { name: "reporter", domain: "audit", effect: "read" },
  { name: "web_pentester", domain: "offensive", effect: "active" },
  { name: "recon", domain: "recon", effect: "read" },
  { name: "memory_analysis", domain: "forensic", effect: "read" },
  { name: "network_traffic_analyzer", domain: "forensic", effect: "read" },
  { name: "reverse_engineering", domain: "forensic", effect: "read" },
  { name: "android_sast_agent", domain: "offensive", effect: "read" },
  { name: "subghz_sdr_agent", domain: "offensive", effect: "active" },
  { name: "wifi_security_tester", domain: "offensive", effect: "active" },
  { name: "replay_attack_agent", domain: "offensive", effect: "active" },
];

function firstProjectId(projects: ProjectMembership[]): string {
  return projects[0]?.id ?? "default";
}

export default function AgentsPage() {
  const authed = useRequireAuth();
  const { roles, projects } = useRoles();

  const [agentName, setAgentName] = useState(AGENTS[0].name);
  const [projectId, setProjectId] = useState<string>("");
  const [prompt, setPrompt] = useState("");
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<AgentRunResult | null>(null);

  if (!authed) return <p className="text-slate-500">Redirecting to sign in…</p>;

  const project = projectId || firstProjectId(projects);
  const callerRole = roles[project];
  const agent = AGENTS.find((a) => a.name === agentName) ?? AGENTS[0];
  const requiresApproval = agent.effect === "active";
  const minRole: Role = requiresApproval ? "approver" : "remediator";

  const invoke = async () => {
    if (!prompt.trim()) {
      setErr("A prompt is required.");
      return;
    }
    setBusy(true);
    setErr(null);
    setResult(null);
    try {
      const out = await runAgent(agent.name, {
        prompt,
        project_id: project,
        execute: requiresApproval,
        target: target || undefined,
      });
      setResult(out);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Agents</h1>

      <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900">
        <strong>Safety:</strong> invoking an agent may run active operations
        (exploitation, live hardening, opening PRs) against authorized targets.
        Active / offensive agents require the approver role and run only with
        explicit confirmation.
      </div>

      {err && (
        <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-900">
          {err}
        </p>
      )}

      <div className="space-y-4 rounded-md border border-border bg-card p-4 text-card-foreground">
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="block space-y-1 text-sm">
            <span className="text-muted-foreground">Agent</span>
            <select
              aria-label="Agent"
              value={agentName}
              onChange={(e) => setAgentName(e.target.value)}
              className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm"
            >
              {AGENTS.map((a) => (
                <option key={a.name} value={a.name}>
                  {a.name} — {a.domain}
                  {a.effect === "active" ? " (approval required)" : ""}
                </option>
              ))}
            </select>
          </label>

          <label className="block space-y-1 text-sm">
            <span className="text-muted-foreground">Project</span>
            <select
              aria-label="Project"
              value={project}
              onChange={(e) => setProjectId(e.target.value)}
              className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm"
            >
              {projects.length === 0 ? (
                <option value="default">default</option>
              ) : (
                projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.role})
                  </option>
                ))
              )}
            </select>
          </label>
        </div>

        <label className="block space-y-1 text-sm">
          <span className="text-muted-foreground">Target (optional)</span>
          <input
            aria-label="Target"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://authorized-target.example"
            className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm"
          />
        </label>

        <label className="block space-y-1 text-sm">
          <span className="text-muted-foreground">Prompt</span>
          <textarea
            aria-label="Prompt"
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            rows={5}
            placeholder="Describe the task for the agent…"
            className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm"
          />
        </label>

        {requiresApproval ? (
          <RoleGated
            minRole={minRole}
            callerRole={callerRole}
            fallback={
              <p className="text-sm text-muted-foreground">
                This agent runs active operations and requires the approver
                role on this project.
              </p>
            }
          >
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <button
                  disabled={busy}
                  className="rounded-md bg-destructive px-4 py-2 text-sm text-white hover:opacity-90 disabled:opacity-50"
                >
                  Invoke (active)
                </button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>
                    Invoke {agent.name} with active execution?
                  </AlertDialogTitle>
                  <AlertDialogDescription>
                    This is an active / offensive agent. It may run
                    exploitation or state-changing operations against the
                    target. Only proceed against authorized targets.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction variant="destructive" onClick={invoke}>
                    Invoke agent
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
                Running an agent requires the remediator role on this project.
              </p>
            }
          >
            <button
              disabled={busy}
              onClick={invoke}
              className="rounded-md bg-primary px-4 py-2 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              Run agent
            </button>
          </RoleGated>
        )}
      </div>

      {busy && <p className="text-sm text-muted-foreground">Submitting…</p>}

      {result && (
        <div className="space-y-2 rounded-md border border-border bg-card p-4 text-card-foreground">
          <h2 className="text-sm uppercase tracking-wide text-muted-foreground">
            Result
          </h2>
          <dl className="grid grid-cols-[auto,1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-muted-foreground">Status</dt>
            <dd className="font-mono">{result.status ?? "queued"}</dd>
            <dt className="text-muted-foreground">Run</dt>
            <dd className="font-mono">
              <a className="text-sky-700 underline" href={`/runs/${result.run_id}`}>
                {result.run_id}
              </a>
            </dd>
            <dt className="text-muted-foreground">Job</dt>
            <dd className="font-mono">{result.job_id}</dd>
          </dl>
        </div>
      )}
    </div>
  );
}

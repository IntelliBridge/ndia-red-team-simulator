"use client";

// /agents — invoke a registered CAI agent.
//
// The picker is fed by GET /v1/agents (aegis/agents/registry.py::
// list_agents) rather than a hardcoded list, so the roster never drifts
// from the backend. Only `wired` (invokable) agents are offered. The
// `effect` field ("read" vs "active"/"external") is the human gate:
// active/external agents need the approver role + execute=true + an
// explicit confirmation, exactly like the API enforces (Action.
// AGENT_EXECUTE → approver).

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
  listAgents,
  runAgent,
  type AgentRunResult,
  type AgentSpec,
  type ProjectMembership,
} from "@/lib/api";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { useRoles } from "@/hooks/useRoles";

function firstProjectId(projects: ProjectMembership[]): string {
  return projects[0]?.id ?? "default";
}

export default function AgentsPage() {
  const authed = useRequireAuth();
  const { roles, projects } = useRoles();

  const { data, error: agentsError } = useSWR<AgentSpec[]>(
    authed ? "/v1/agents" : null,
    listAgents,
  );
  const agents = (data ?? []).filter((a) => a.wired);

  const [agentName, setAgentName] = useState<string>("");
  const [projectId, setProjectId] = useState<string>("");
  const [prompt, setPrompt] = useState("");
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<AgentRunResult | null>(null);

  if (!authed)
    return <p className="text-muted-foreground">Redirecting to sign in…</p>;

  const project = projectId || firstProjectId(projects);
  const callerRole = roles[project];
  // Default to the first wired agent until the user picks one.
  const selectedName = agentName || agents[0]?.name || "";
  const agent = agents.find((a) => a.name === selectedName);
  const requiresApproval = agent ? agent.effect !== "read" : false;
  const minRole: Role = requiresApproval ? "approver" : "remediator";

  const invoke = async () => {
    if (!agent) {
      setErr("No agent selected.");
      return;
    }
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
        <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {err}
        </p>
      )}

      <div className="space-y-4 rounded-md border border-border bg-card p-4 text-card-foreground">
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="block space-y-1 text-sm">
            <span className="text-muted-foreground">Agent</span>
            <select
              aria-label="Agent"
              value={selectedName}
              onChange={(e) => setAgentName(e.target.value)}
              disabled={agents.length === 0}
              className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm disabled:opacity-50"
            >
              {agents.length === 0 ? (
                <option value="">
                  {agentsError ? "Failed to load agents" : "Loading agents…"}
                </option>
              ) : (
                agents.map((a) => (
                  <option key={a.name} value={a.name}>
                    {a.name} — {a.domain}
                    {a.effect !== "read" ? " (approval required)" : ""}
                  </option>
                ))
              )}
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
                    Invoke {agent?.name ?? selectedName} with active execution?
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
              <a className="text-primary underline" href={`/runs/${result.run_id}`}>
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

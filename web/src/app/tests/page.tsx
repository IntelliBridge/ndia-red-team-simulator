"use client";
// /tests — the test catalog. Everything the platform can run, launchable
// from here without first navigating to a model: garak LLM probes through
// Pythia (ProbeCatalog) and the adversarial ML attack roster (AttacksCatalog).
import { useState } from "react";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { ProbeCatalog } from "./probe-catalog";
import { AttacksCatalog } from "./attacks-catalog";

type Tab = "probes" | "attacks";

const TABS: { id: Tab; label: string }[] = [
  { id: "probes", label: "LLM probes (garak via Pythia)" },
  { id: "attacks", label: "Adversarial ML attacks" },
];

export default function TestsPage() {
  const authed = useRequireAuth();
  const [tab, setTab] = useState<Tab>("probes");
  if (!authed) return <p>Redirecting to sign in…</p>;
  return (
    <div className="space-y-6">
      <header>
        <div className="redsim-kicker">test catalog</div>
        <h1 className="text-3xl font-semibold tracking-tight">Tests</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Every probe and attack the platform can run, launchable against a
          registered target from here.
        </p>
      </header>
      <div className="flex gap-2" role="group" aria-label="Test kind">
        {TABS.map((t) => (
          <button
            key={t.id}
            aria-pressed={tab === t.id}
            className={`border px-3 py-2 text-sm ${tab === t.id ? "border-primary bg-primary/10" : "border-border"}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>
      {tab === "probes" ? <ProbeCatalog enabled={authed} /> : <AttacksCatalog />}
    </div>
  );
}

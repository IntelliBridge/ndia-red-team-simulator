"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

export default function Home() {
  const router = useRouter();
  useEffect(() => {
    const token = localStorage.getItem("redsim_token");
    router.replace(token ? "/dashboard" : "/login");
  }, [router]);
  return (
    <div className="space-y-2 pt-8">
      <div className="redsim-kicker">Adversarial ML Red-Team Simulator</div>
      <h1 className="text-3xl">Redsim</h1>
      <p className="text-ink-3">Loading…</p>
    </div>
  );
}

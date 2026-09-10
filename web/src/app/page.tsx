"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

import { isAuthenticated } from "@/lib/auth";

export default function Home() {
  const router = useRouter();
  useEffect(() => {
    router.replace(isAuthenticated() ? "/dashboard" : "/login");
  }, [router]);
  return (
    <div className="space-y-2 pt-8">
      <div className="redsim-kicker">Adversarial ML Red-Team Simulator</div>
      <h1 className="text-3xl">Redsim</h1>
      <p className="text-muted-foreground">Loading…</p>
    </div>
  );
}

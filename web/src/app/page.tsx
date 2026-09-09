"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

import { env } from "@/env";
import { hasCookie } from "@/lib/api";

export default function Home() {
  const router = useRouter();
  useEffect(() => {
    // The same two signals requireAuth reads: a dev bearer in storage, or the
    // readable half of the cookie pair the branded sign-in minted. The
    // session cookie itself is httpOnly and invisible here.
    const authenticated =
      Boolean(localStorage.getItem("redsim_token")) ||
      hasCookie(env.NEXT_PUBLIC_REDSIM_CSRF_COOKIE);
    router.replace(authenticated ? "/dashboard" : "/login");
  }, [router]);
  return (
    <div className="space-y-2 pt-8">
      <div className="redsim-kicker">Adversarial ML Red-Team Simulator</div>
      <h1 className="text-3xl">Redsim</h1>
      <p className="text-muted-foreground">Loading…</p>
    </div>
  );
}

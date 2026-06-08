"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import { requireAuth } from "@/lib/auth";

export function useRequireAuth(): boolean {
  const router = useRouter();
  const [authed, setAuthed] = useState(false);
  useEffect(() => {
    if (requireAuth(router)) setAuthed(true);
  }, [router]);
  return authed;
}

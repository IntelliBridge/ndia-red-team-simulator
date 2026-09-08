"use client";
import { useEffect } from "react";
import { useRouter } from "next/navigation";
export default function TargetsPage() {
  const router = useRouter();
  useEffect(() => {
    router.replace("/models");
  }, [router]);
  return <p className="text-muted-foreground">Opening model catalog…</p>;
}

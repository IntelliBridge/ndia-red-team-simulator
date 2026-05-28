"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

export default function Home() {
  const router = useRouter();
  useEffect(() => {
    const token = localStorage.getItem("aegis_token");
    router.replace(token ? "/dashboard" : "/login");
  }, [router]);
  return (
    <div>
      <h1>Aegis</h1>
      <p>Loading…</p>
    </div>
  );
}

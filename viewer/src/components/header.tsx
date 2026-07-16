"use client"

import { Shield } from "lucide-react"
import { ADData } from "@/lib/types"

export function Header({ data }: { data: ADData }) {
  const criticalChains = (data.meta.stats?.critical_chains || 0)
  return (
    <header className="sticky top-0 z-50 bg-bg/85 backdrop-blur-xl border-b border-white/[0.04] h-12 px-6 flex items-center justify-between">
      <div className="flex items-center gap-2.5">
        <div className="w-2 h-2 rounded-full bg-accent-red shadow-[0_0_8px_rgba(239,68,68,0.6)] animate-pulse-glow shadow-red-500" />
        <span className="font-bold text-[15px] tracking-tight text-text-primary">
          BLOODY<span className="text-accent-red font-extrabold">OMAIN</span>
        </span>
      </div>
      <div className="flex items-center gap-4 font-mono text-xs text-text-muted">
        {criticalChains > 0 && (
          <span className="flex items-center gap-1.5 text-accent-red">
            <Shield className="w-3.5 h-3.5" />
            {criticalChains} critical
          </span>
        )}
      </div>
    </header>
  )
}

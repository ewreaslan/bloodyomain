"use client"

import { useState, useMemo } from "react"
import { motion } from "framer-motion"
import { Shield } from "lucide-react"
import { ADData } from "@/lib/types"
import { cn, escapeHtml } from "@/lib/utils"

export function AttackChains({ data }: { data: ADData }) {
  const [filter, setFilter] = useState("")
  const chains = useMemo(() => {
    let c = data.attack_chains || []
    if (filter) c = c.filter(ch => ch.severity === filter)
    const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, INFO: 3 }
    return c.sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4))
  }, [data, filter])

  const sevConfig: Record<string, { border: string; bar: string; text: string }> = {
    CRITICAL: { border: "border-accent-red/20", bar: "bg-accent-red", text: "text-accent-red" },
    HIGH: { border: "border-accent-orange/20", bar: "bg-accent-orange", text: "text-accent-orange" },
    MEDIUM: { border: "border-accent-yellow/20", bar: "bg-accent-yellow", text: "text-accent-yellow" },
    INFO: { border: "border-accent-blue/15", bar: "bg-accent-blue", text: "text-accent-blue" },
  }

  return (
    <div className="space-y-3 animate-fade-in">
      <div className="flex items-center gap-3">
        <h2 className="text-sm font-bold text-text-primary">Attack Chains — Exploitable Paths</h2>
        <select
          value={filter} onChange={e => setFilter(e.target.value)}
          className="px-3 py-1.5 text-xs font-mono bg-bg-card/60 border border-white/[0.06] rounded-md text-text-primary outline-none focus:border-accent-cyan"
        >
          <option value="">All Severity</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
        </select>
        <span className="text-[10px] text-text-muted font-mono ml-auto">{chains.length} chains</span>
      </div>

      {!chains.length ? (
        <div className="glass rounded-xl p-8 text-center text-text-muted font-mono text-xs">No attack chains found for this filter.</div>
      ) : (
        <div className="grid grid-cols-[repeat(auto-fill,minmax(370px,1fr))] gap-2">
          {chains.map((ch, i) => {
            const cfg = sevConfig[ch.severity] || sevConfig.INFO
            return (
              <motion.div
                key={ch.id}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.03 }}
                className={cn("glass rounded-xl p-4 relative overflow-hidden cursor-default border hover:border-white/[0.08] hover:-translate-y-0.5 transition-all duration-200", cfg.border)}
              >
                <div className={cn("absolute left-0 top-0 bottom-0 w-1 rounded-l-full", cfg.bar)} />
                <div className={cn("text-[10px] font-bold uppercase tracking-wide mb-1", cfg.text)}>
                  {ch.severity} · {ch.type}
                </div>
                <h3 className="text-sm font-bold text-text-primary mb-1">{escapeHtml(ch.title)}</h3>
                <p className="text-[11px] text-text-secondary mb-3 leading-relaxed">{escapeHtml(ch.description)}</p>

                {ch.priority_score != null && (
                  <div className="flex items-center gap-2 mb-3 text-[10px] text-text-muted">
                    <span>Priority</span>
                    <div className="flex-1 h-1 bg-white/[0.04] rounded-full overflow-hidden">
                      <div
                        className={cn("h-full rounded-full transition-all", ch.priority_score >= 70 ? "bg-accent-red" : ch.priority_score >= 40 ? "bg-accent-orange" : "bg-accent-yellow")}
                        style={{ width: `${ch.priority_score}%` }}
                      />
                    </div>
                    <span className="font-bold text-text-primary">{ch.priority_score}/100</span>
                  </div>
                )}

                <div className="space-y-1 mb-3">
                  {(ch.steps || []).map((s, si) => (
                    <div key={si} className="flex items-start gap-1.5 text-[10px] font-mono text-text-secondary">
                      <span className="text-accent-cyan font-bold min-w-[14px]">{si + 1}.</span>
                      <span className="text-text-primary">{escapeHtml(s)}</span>
                    </div>
                  ))}
                </div>

                {(ch.mitre || []).length > 0 && (
                  <div className="flex flex-wrap gap-1 pt-2 border-t border-white/[0.04]">
                    {ch.mitre!.map((m, mi) => (
                      <span key={mi} className="inline-flex items-center gap-1 text-[9px] font-mono px-1.5 py-0.5 rounded-full border border-accent-cyan/20 text-accent-cyan bg-accent-cyan/5">
                        <span className="font-bold text-accent-yellow">{m.id}</span>{m.name}
                      </span>
                    ))}
                  </div>
                )}
              </motion.div>
            )
          })}
        </div>
      )}
    </div>
  )
}

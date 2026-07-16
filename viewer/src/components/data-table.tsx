"use client"

import { useState, useMemo } from "react"
import { Search, ArrowUpDown } from "lucide-react"
import { cn, escapeHtml } from "@/lib/utils"

interface Col { k: string; l: string; fmt?: (v: any) => string }

export function DataTable({ title, data, cols, searchable, daSet, daKey, flagged }: {
  title: string; data: any[]; cols: Col[]; searchable?: boolean
  daSet?: Set<string>; daKey?: string; flagged?: boolean
}) {
  const [q, setQ] = useState("")
  const [sort, setSort] = useState<{ col: number; asc: boolean } | null>(null)

  const filtered = useMemo(() => {
    let rows = data || []
    if (q) rows = rows.filter(r => cols.some(c => String(r[c.k] ?? "").toLowerCase().includes(q.toLowerCase())))
    if (sort) {
      rows = [...rows].sort((a, b) => {
        const av = String(a[cols[sort.col].k] ?? ""), bv = String(b[cols[sort.col].k] ?? "")
        const na = parseFloat(av), nb = parseFloat(bv)
        const cmp = !isNaN(na) && !isNaN(nb) ? na - nb : av.localeCompare(bv)
        return sort.asc ? cmp : -cmp
      })
    }
    return rows
  }, [data, q, sort, cols])

  const fmt = (c: Col, v: any) => c.fmt ? c.fmt(v) : v != null ? String(v) : "—"

  if (!data?.length) return (
    <div className="space-y-3 animate-fade-in">
      <h2 className="text-sm font-bold text-text-primary">{title}</h2>
      <div className="glass rounded-xl p-8 text-center text-text-muted font-mono text-xs">No data available</div>
    </div>
  )

  return (
    <div className="space-y-3 animate-fade-in">
      <div className="flex items-center gap-3">
        <h2 className="text-sm font-bold text-text-primary">{title}</h2>
        {searchable && (
          <div className="relative flex-1 max-w-xs">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-muted" />
            <input
              value={q} onChange={e => setQ(e.target.value)}
              placeholder="Filter..."
              className="w-full pl-8 pr-3 py-1.5 text-xs font-mono bg-bg-card/60 border border-white/[0.06] rounded-md text-text-primary outline-none focus:border-accent-cyan focus:ring-2 focus:ring-accent-cyan/10 transition-all"
            />
          </div>
        )}
        <span className="text-[10px] text-text-muted font-mono ml-auto">{filtered.length} rows</span>
      </div>

      <div className="glass rounded-xl overflow-hidden">
        <div className="overflow-x-auto max-h-[520px] overflow-y-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-bg/40">
                {cols.map((c, i) => (
                  <th
                    key={c.k}
                    onClick={() => setSort(s => s?.col === i ? { col: i, asc: !s.asc } : { col: i, asc: true })}
                    className="px-3 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wide text-text-secondary border-b border-white/[0.04] cursor-pointer hover:text-text-primary hover:bg-white/[0.02] transition-colors whitespace-nowrap select-none"
                  >
                    <span className="flex items-center gap-1">
                      {c.l} <ArrowUpDown className="w-2.5 h-2.5 opacity-30" />
                    </span>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((row, ri) => {
                const isDA = daSet && daKey ? daSet.has(String(row[daKey] || "").toUpperCase()) : false
                return (
                  <tr
                    key={ri}
                    className={cn(
                      "border-b border-white/[0.02] last:border-0 transition-colors hover:bg-accent-cyan/[0.02]",
                      flagged && "bg-accent-red/5 border-l-2 border-l-accent-red hover:bg-accent-red/[0.08]",
                      isDA && "bg-accent-red/5 border-l-2 border-l-accent-red hover:bg-accent-red/[0.08]"
                    )}
                  >
                    {cols.map((c, ci) => (
                      <td key={ci} className={cn("px-3 py-2 font-mono text-[11px] whitespace-nowrap", ci === 0 ? "font-semibold" : "text-text-secondary")}>
                        {c.k === "severity" ? <SeverityBadge sev={String(row[c.k] || "")} /> : escapeHtml(fmt(c, row[c.k]))}
                      </td>
                    ))}
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function SeverityBadge({ sev }: { sev: string }) {
  const map: Record<string, string> = {
    CRITICAL: "bg-accent-red/10 text-accent-red border-accent-red/30",
    HIGH: "bg-accent-orange/10 text-accent-orange border-accent-orange/30",
    MEDIUM: "bg-accent-yellow/10 text-accent-yellow border-accent-yellow/30",
  }
  return <span className={cn("inline-flex text-[10px] font-semibold px-1.5 py-0.5 rounded-full border", map[sev] || "bg-white/5 text-text-muted border-white/10")}>{sev}</span>
}

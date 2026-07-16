"use client"

import { useState, useRef, useEffect } from "react"
import { ChevronDown } from "lucide-react"
import { cn } from "@/lib/utils"
import { ADData } from "@/lib/types"
import type { TabId } from "@/app/page"

interface NavGroup {
  id: string; label: string; tabs: { id: TabId; label: string; badge?: string; danger?: boolean }[]
}

const NAV_GROUPS: NavGroup[] = [
  { id: "attack", label: "Attack Paths", tabs: [
    { id: "chains", label: "Attack Chains", badge: "tc-chains", danger: true },
    { id: "graph", label: "Attack Graph", badge: "tc-edges" },
  ]},
  { id: "creds", label: "Credentials", tabs: [
    { id: "shadow", label: "Shadow Creds", badge: "tc-shadow", danger: true },
    { id: "dcsync", label: "DCSync", badge: "tc-dcsync" },
    { id: "descpass", label: "Desc Creds", badge: "tc-descpass", danger: true },
    { id: "gpo_creds", label: "GPO Creds", badge: "tc-gpo_creds", danger: true },
    { id: "validcreds", label: "Valid Creds", badge: "tc-validcreds", danger: true },
    { id: "lapspwd", label: "LAPS", badge: "tc-lapspwd", danger: true },
  ]},
  { id: "deleg", label: "Delegation", tabs: [
    { id: "delegation", label: "Delegation Matrix", danger: true },
    { id: "coercion", label: "PrinterBug/PetitPotam", danger: true },
    { id: "nopac", label: "noPac", danger: true },
    { id: "ntlmv1", label: "NTLMv1", danger: true },
    { id: "protusers", label: "Protected Users", danger: true },
  ]},
  { id: "infra", label: "Infrastructure", tabs: [
    { id: "computers", label: "Computers" }, { id: "users", label: "Users" },
    { id: "groups", label: "Groups" }, { id: "sessions", label: "Sessions" },
    { id: "shares", label: "Shares" }, { id: "trusts", label: "Trusts" },
    { id: "tombstoned", label: "Tombstoned" },
  ]},
  { id: "perm", label: "Permissions", tabs: [
    { id: "acl", label: "ACL Edges", danger: true },
    { id: "nested", label: "Nested Groups" },
    { id: "gpo", label: "GPO Links" },
    { id: "gpowrite", label: "GPO Write", danger: true },
    { id: "adminsd", label: "AdminSDHolder", danger: true },
    { id: "ouacls", label: "OU ACLs", danger: true },
    { id: "fgpp", label: "FGPP" },
  ]},
  { id: "security", label: "Security", tabs: [
    { id: "adcs", label: "ADCS", danger: true },
    { id: "ldapsec", label: "LDAP Security", danger: true },
    { id: "vulnscan", label: "Vuln Scan", danger: true },
    { id: "winrm", label: "WinRM" },
    { id: "mssql", label: "MSSQL" },
    { id: "sccm", label: "SCCM" },
    { id: "sensitive", label: "Sensitive Files" },
  ]},
]

function getGroupBadge(g: NavGroup, data: ADData): { count: number; danger: boolean } {
  const s: any = data.meta.stats || {}
  switch (g.id) {
    case "attack": return { count: (s.attack_chains||0)+(s.edges||0), danger: (s.critical_chains||0)>0 }
    case "creds": return { count: (data.shadow_creds||[]).length+(data.dcsync_rights||[]).length+(data.description_passwords||[]).length+(data.gpo_contents||[]).length+(s.validated_credentials||0)+(s.laps_passwords_read||0), danger: true }
    case "deleg": return { count: (s.delegation_matrix||0)+(s.printerbug_hosts||0)+(s.petitpotam_hosts||0)+(s.nopac_risk?1:0)+(s.ntlmv1_hosts||0)+(s.protected_users_gap||0), danger: true }
    case "infra": return { count: (s.computers||0)+(s.users||0)+(s.groups||0)+(s.sessions||0)+(s.loggedon||0)+(data.shares||[]).length+(data.trusts||[]).length+(s.tombstoned_objects||0), danger: false }
    case "perm": return { count: (data.acl_edges||[]).length+(data.gpo_write_perms||[]).length+(data.adminsd_acl||[]).length+(s.ou_acls||0), danger: true }
    case "security": return { count: (data.adcs_esc||[]).length+(s.sensitive_files||0)+(data.winrm_hosts||[]).length, danger: true }
    default: return { count: 0, danger: false }
  }
}

export function Navigation({ activeTab, onTabChange, data }: {
  activeTab: TabId; onTabChange: (t: TabId) => void; data: ADData
}) {
  const [openGroup, setOpenGroup] = useState<string | null>(null)
  const navRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (navRef.current && !navRef.current.contains(e.target as Node)) setOpenGroup(null)
    }
    document.addEventListener("click", handler)
    return () => document.removeEventListener("click", handler)
  }, [])

  return (
    <nav ref={navRef} className="sticky top-12 z-40 bg-bg/80 backdrop-blur-xl border-b border-white/[0.04]">
      <div className="flex px-4 overflow-visible">
        <TabBtn id="overview" label="Overview" active={activeTab === "overview"} onClick={() => onTabChange("overview")} />

        {NAV_GROUPS.map(g => {
          const badge = getGroupBadge(g, data)
          const isOpen = openGroup === g.id
          const isActive = g.tabs.some(t => t.id === activeTab)
          return (
            <div key={g.id} className="relative flex-shrink-0">
              <button
                onClick={(e) => { e.stopPropagation(); setOpenGroup(isOpen ? null : g.id) }}
                className={cn(
                  "flex items-center gap-1.5 px-3 py-2.5 text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap rounded-t-md",
                  isActive && "border-accent-cyan text-accent-cyan bg-accent-cyan/5",
                  !isActive && badge.danger && badge.count > 0 && "text-accent-red",
                  !isActive && !(badge.danger && badge.count > 0) && "border-transparent text-text-secondary hover:text-text-primary hover:bg-white/[0.02]"
                )}
              >
                {g.label}
                {badge.count > 0 && (
                  <span className={cn("text-[10px] px-1.5 py-px rounded-full font-mono font-semibold",
                    badge.danger ? "bg-accent-red/10 text-accent-red" : "bg-white/5 text-text-secondary"
                  )}>{badge.count}</span>
                )}
                <ChevronDown className={cn("w-3 h-3 opacity-40 transition-transform", isOpen && "rotate-180 opacity-70")} />
              </button>
              {isOpen && (
                <div className="absolute top-full left-0 min-w-[220px] bg-bg-elevated/95 backdrop-blur-2xl border border-white/[0.06] rounded-b-xl shadow-2xl overflow-hidden z-50">
                  {g.tabs.map(t => (
                    <button
                      key={t.id}
                      onClick={(e) => { e.stopPropagation(); onTabChange(t.id); setOpenGroup(null) }}
                      className={cn(
                        "w-full text-left flex items-center gap-2 px-4 py-2 text-[13px] font-medium border-l-2 transition-colors",
                        activeTab === t.id ? "border-accent-cyan text-accent-cyan bg-accent-cyan/5" : "border-transparent text-text-secondary hover:text-text-primary hover:bg-white/[0.03] hover:border-accent-cyan"
                      )}
                    >
                      {t.label}
                      {t.danger && <span className="ml-auto w-1.5 h-1.5 rounded-full bg-accent-red" />}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )
        })}

        <TabBtn id="remediation" label="Remediation" active={activeTab === "remediation"} onClick={() => onTabChange("remediation")} />
      </div>
    </nav>
  )
}

function TabBtn({ id, label, active, onClick }: { id: string; label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "flex items-center px-3 py-2.5 text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap rounded-t-md",
        active ? "border-accent-cyan text-accent-cyan bg-accent-cyan/5" : "border-transparent text-text-secondary hover:text-text-primary hover:bg-white/[0.02]"
      )}
    >
      {label}
    </button>
  )
}

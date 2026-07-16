"use client"

import { motion } from "framer-motion"
import { Monitor, Shield, Server, Users, Key, AlertTriangle, Activity, Wifi } from "lucide-react"
import { ADData } from "@/lib/types"
import { cn, escapeHtml, formatDate } from "@/lib/utils"

export function Overview({ data, daSet }: { data: ADData; daSet: Set<string> }) {
  const m = data.meta, s: any = m.stats || {}, d: any = data.domain || {}
  const timeStr = formatDate(m.enum_time || "")

  return (
    <div className="space-y-4 animate-fade-in">
      {/* Scan info */}
      <div className="glass rounded-xl p-3 flex flex-wrap gap-x-6 gap-y-1.5 font-mono text-sm">
        <Info label="Target" value={m.target || "—"} danger />
        <Info label="Domain" value={m.domain || "—"} />
        <Info label="Scanned" value={timeStr} />
        <Info label="DA Users" value={(data.da_users || []).join(", ") || "None"} danger />
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-[repeat(auto-fill,minmax(155px,1fr))] gap-2">
        <StatCard label="Users" value={s.users} sub={`${(data.users||[]).filter(u=>u.enabled).length} enabled`} color="blue" />
        <StatCard label="Domain Admins" value={s.da_users} sub="privileged" color={s.da_users ? "red" : "gray"} />
        <StatCard label="Computers" value={s.computers} sub={`${(data.computers||[]).filter(c=>c.is_dc).length} DCs`} color="green" />
        <StatCard label="Active Sessions" value={s.sessions} sub="SMB sessions" color={s.sessions ? "orange" : "gray"} />
        <StatCard label="Logged On" value={s.loggedon} sub="interactive" color={s.loggedon ? "orange" : "gray"} />
        <StatCard label="Kerberoastable" value={s.spns} sub="SPN accounts" color={s.spns ? "red" : "gray"} />
        <StatCard label="AS-REP" value={s.asrep_users} sub="no preauth" color={s.asrep_users ? "red" : "gray"} />
        <StatCard label="ACL Edges" value={(data.acl_edges||[]).length} sub="dangerous rights" color="red" />
        <StatCard label="Attack Chains" value={s.attack_chains} sub={`${s.critical_chains||0} crit / ${s.high_chains||0} high`} color={s.critical_chains ? "red" : "orange"} />
        <StatCard label="ADCS ESC" value={(data.adcs_esc||[]).length} sub="cert vulns" color={(data.adcs_esc||[]).length ? "red" : "gray"} />
        <StatCard label="PrinterBug" value={s.printerbug_hosts} sub="MS-RPRN" color={s.printerbug_hosts ? "red" : "gray"} />
        <StatCard label="PetitPotam" value={s.petitpotam_hosts} sub="EFS" color={s.petitpotam_hosts ? "red" : "gray"} />
        <StatCard label="NTLMv1 DCs" value={s.ntlmv1_hosts} sub="LmCompat <3" color={s.ntlmv1_hosts ? "red" : "gray"} />
        <StatCard label="noPac Risk" value={s.nopac_risk ? "!" : "OK"} sub="CVE-2021-42278" color={s.nopac_risk ? "red" : "green"} />
        <StatCard label="Desc Creds" value={(data.description_passwords||[]).length} sub="in descriptions" color={(data.description_passwords||[]).length ? "red" : "gray"} />
        <StatCard label="Valid Creds" value={s.validated_credentials} sub="confirmed" color={s.validated_credentials ? "red" : "gray"} />
        <StatCard label="LAPS Read" value={s.laps_passwords_read} sub="passwords" color={s.laps_passwords_read ? "red" : "gray"} />
      </div>

      {/* Overview cards */}
      <div className="grid grid-cols-[repeat(auto-fill,minmax(290px,1fr))] gap-2">
        <OverviewCard title="Domain Policy">
          {[
            ["Domain", d.name || "—"], ["DN", (d.dn || "").slice(0, 38)],
            ["Min Pwd Length", d.min_pwd_length ?? "—"], ["Lockout Threshold", d.lockout_threshold ?? "—"],
            ["DFL", d.behavior_version != null ? ["2000","2003 Interim","2003","2008","2008 R2","2012","2012 R2","2016","2019","2025"][d.behavior_version] || `Level ${d.behavior_version}` : "—"],
            ["LDAP Signing", s.ldap_signing_enforced === true ? "✓ Required" : s.ldap_signing_enforced === false ? "✗ NOT REQUIRED" : "—"],
            ["Channel Binding", s.channel_binding_enforced === true ? "✓ Enforced" : s.channel_binding_enforced === false ? "✗ Not Enforced" : "—"],
          ].map(([k, v]: any[]) => (
            <div key={k} className="flex justify-between items-center py-1 border-b border-white/[0.02] last:border-0">
              <span className="text-text-muted font-mono text-[11px]">{k}</span>
              <span className={cn("font-mono text-xs font-semibold", String(v).includes("NOT") && "text-accent-red")}>{String(v)}</span>
            </div>
          ))}
        </OverviewCard>

        <OverviewCard title="Domain Admins">
          {Object.entries(
            (data.admins || []).reduce((acc: Record<string, string[]>, a: any) => {
              if (!acc[a.group]) acc[a.group] = []; acc[a.group].push(a.member_name); return acc
            }, {})
          ).map(([g, members]: [string, string[]]) => (
            <div key={g} className="flex justify-between items-center py-1 border-b border-white/[0.02] last:border-0">
              <span className="text-text-muted font-mono text-[11px] truncate max-w-[120px]">{g}</span>
              <span className="font-mono text-xs font-semibold text-accent-red">{members.join(", ")}</span>
            </div>
          ))}
        </OverviewCard>

        <OverviewCard title="OS Distribution">
          {Object.entries(
            (data.computers || []).reduce((acc, c) => {
              const k = c.os || "Unknown"; acc[k] = (acc[k] || 0) + 1; return acc
            }, {} as Record<string, number>)
          ).sort((a, b) => b[1] - a[1]).map(([os, n]) => {
            const total = Object.values(data.computers.reduce((acc,c)=>{const k=c.os||"Unknown";acc[k]=(acc[k]||0)+1;return acc},{} as Record<string,number>)).reduce((a,b)=>a+b,0)||1
            return (
              <div key={os} className="flex items-center gap-2 py-1">
                <span className="font-mono text-[11px] text-text-primary min-w-[170px] truncate">{os}</span>
                <div className="flex-1 h-1 bg-white/[0.04] rounded-full"><div className="h-full bg-accent-green rounded-full transition-all duration-700" style={{ width: `${Math.round(n/total*100)}%` }} /></div>
                <span className="font-bold text-xs text-accent-green w-5 text-right">{n}</span>
              </div>
            )
          })}
        </OverviewCard>

        <OverviewCard title="Active Sessions Overview">
          {[
            ["Total SMB Sessions", (data.sessions || []).length],
            ["Interactive Logged On", (data.loggedon || []).length],
            ["DA SMB Sessions", (data.sessions || []).filter(s => daSet.has((s.user || "").toUpperCase())).length],
            ["DA Logged On", (data.loggedon || []).filter(s => daSet.has((s.user || "").toUpperCase())).length],
            ["RDP-Open Hosts", (data.rdp_open || []).length],
            ["PrinterBug Hosts", (data.printerbug_hosts || []).length],
            ["PetitPotam Hosts", (data.petitpotam_hosts || []).length],
          ].map(([k, v]: [string, number]) => (
            <div key={k} className="flex justify-between items-center py-1 border-b border-white/[0.02] last:border-0">
              <span className="text-text-muted font-mono text-[11px]">{k}</span>
              <span className={cn("font-mono text-xs font-semibold", v > 0 && (k.includes("DA") || k.includes("Admin") || k.includes("Bug") || k.includes("Potam")) && "text-accent-red")}>{v}</span>
            </div>
          ))}
        </OverviewCard>
      </div>
    </div>
  )
}

function Info({ label, value, danger }: { label: string; value: string; danger?: boolean }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-[10px] uppercase tracking-wider text-text-muted font-semibold">{label}</span>
      <span className={cn("font-semibold text-xs", danger ? "text-accent-red" : "text-accent-cyan")}>{value}</span>
    </div>
  )
}

function StatCard({ label, value, sub, color }: { label: string; value: any; sub: string; color: string }) {
  const colorMap: Record<string, string> = {
    red: "text-accent-red", orange: "text-accent-orange", yellow: "text-accent-yellow",
    green: "text-accent-green", blue: "text-accent-blue", cyan: "text-accent-cyan",
    purple: "text-accent-purple", gray: "text-text-muted", teal: "text-teal-400",
  }
  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass rounded-xl p-3 relative overflow-hidden cursor-default hover:border-white/[0.08] hover:-translate-y-0.5 transition-all duration-200"
    >
      <span className="text-[10px] uppercase tracking-wide text-text-secondary font-semibold">{label}</span>
      <div className={cn("text-2xl font-extrabold tracking-tight mt-0.5", colorMap[color] || "text-text-primary")}>{value}</div>
      <div className="text-[10px] text-text-muted font-mono mt-0.5">{sub}</div>
    </motion.div>
  )
}

function OverviewCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="glass rounded-xl p-3.5">
      <h3 className="text-xs font-bold uppercase tracking-wide text-text-primary mb-3 pb-2 border-b border-white/[0.04]">{title}</h3>
      {children}
    </div>
  )
}

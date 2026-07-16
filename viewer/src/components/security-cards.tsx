"use client"

import { ADData } from "@/lib/types"
import { cn, escapeHtml } from "@/lib/utils"

export function SecurityCards({ type, data }: { type: string; data: ADData }) {
  return (
    <div className="space-y-4 animate-fade-in">
      {type === "ldapsec" && <LDAPSecurity data={data} />}
      {type === "vulnscan" && <VulnScan data={data} />}
      {type === "delegation" && <DelegationView data={data} />}
      {type === "coercion" && <CoercionView data={data} />}
      {type === "ntlmv1" && <NTLMv1View data={data} />}
      {type === "nopac" && <NoPacView data={data} />}
      {type === "protusers" && <ProtUsersView data={data} />}
      {type === "nested" && <NestedView data={data} />}
    </div>
  )
}

function SecCard({ icon, label, value, color }: { icon: string; label: string; value: string; color: string }) {
  return (
    <div className="glass rounded-xl p-3 flex items-center gap-2.5">
      <span className="text-lg">{icon}</span>
      <div>
        <div className="text-[10px] font-semibold uppercase tracking-wide text-text-secondary">{label}</div>
        <div className="text-sm font-bold" style={{ color }}>{value}</div>
      </div>
    </div>
  )
}

function LDAPSecurity({ data }: { data: ADData }) {
  const ls: any = data.ldap_security || {}
  const s = ls.signing_enforced, c = ls.cb_enforced
  return (
    <div className="space-y-3">
      <h2 className="text-sm font-bold text-text-primary">LDAP Signing & Channel Binding</h2>
      <div className="grid grid-cols-[repeat(auto-fill,minmax(200px,1fr))] gap-2">
        <SecCard icon="🔐" label="LDAP Signing" value={s === true ? "✓ Required" : s === false ? "✗ NOT REQUIRED" : "? Unknown"} color={s === true ? "#22c55e" : s === false ? "#ef4444" : "#8895a8"} />
        <SecCard icon="🔗" label="Channel Binding" value={c === true ? "✓ Enforced" : c === false ? "✗ Not Enforced" : "? Unknown"} color={c === true ? "#22c55e" : c === false ? "#ef4444" : "#8895a8"} />
        <SecCard icon="⚡" label="NTLM Relay to LDAP" value={(s === false || c === false) ? "⚠ POSSIBLE" : "✓ Mitigated"} color={(s === false || c === false) ? "#ef4444" : "#22c55e"} />
      </div>
    </div>
  )
}

function VulnScan({ data }: { data: ADData }) {
  const v = data.vuln_scan || {}
  const cats = [
    { key: "spooler", label: "Print Spooler Active", color: "#ef4444" },
    { key: "zerologon", label: "ZeroLogon (CVE-2020-1472)", color: "#f59e0b" },
    { key: "signing", label: "SMB Signing NOT Required", color: "#eab308" },
  ]
  return (
    <div className="space-y-3">
      <h2 className="text-sm font-bold text-text-primary">Vulnerability Scan</h2>
      <div className="grid grid-cols-[repeat(auto-fill,minmax(280px,1fr))] gap-2">
        {cats.map(cat => (
          <div key={cat.key} className="glass rounded-xl p-3.5" style={{ borderColor: cat.color }}>
            <h3 className="text-xs font-bold uppercase mb-2" style={{ color: cat.color }}>{cat.label}</h3>
            <div className="flex flex-wrap gap-1">
              {(v as any)[cat.key]?.length > 0
                ? (v as any)[cat.key].map((h: string) => <span key={h} className="inline-flex text-[10px] font-mono px-1.5 py-0.5 rounded-full bg-accent-red/10 text-accent-red border border-accent-red/30">{h}</span>)
                : <span className="text-[10px] text-text-muted">None detected</span>}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function DelegationView({ data }: { data: ADData }) {
  const mx = data.delegation_matrix || []
  return (
    <div className="space-y-3">
      <h2 className="text-sm font-bold text-text-primary">Kerberos Delegation Matrix</h2>
      <div className="grid grid-cols-[repeat(auto-fill,minmax(200px,1fr))] gap-2">
        <SecCard icon="⚠" label="Unconstrained (non-DC)" value={String(mx.filter(m => m.unconstrained && !m.is_dc).length)} color="#ef4444" />
        <SecCard icon="🎯" label="Constrained" value={String(mx.filter(m => (m.constrained_to || []).length > 0).length)} color="#f59e0b" />
        <SecCard icon="↔" label="RBCD" value={String(mx.filter(m => (m.rbcd_allowed || []).length > 0).length)} color="#8b5cf6" />
      </div>
    </div>
  )
}

function CoercionView({ data }: { data: ADData }) {
  return (
    <div className="space-y-3">
      <h2 className="text-sm font-bold text-text-primary">Forced Authentication — Coercion Vectors</h2>
      <div className="grid grid-cols-[repeat(auto-fill,minmax(200px,1fr))] gap-2">
        <SecCard icon="🖨" label="PrinterBug" value={String((data.printerbug_hosts || []).length)} color={(data.printerbug_hosts || []).length ? "#ef4444" : "#22c55e"} />
        <SecCard icon="💧" label="PetitPotam" value={String((data.petitpotam_hosts || []).length)} color={(data.petitpotam_hosts || []).length ? "#ef4444" : "#22c55e"} />
      </div>
    </div>
  )
}

function NTLMv1View({ data }: { data: ADData }) {
  return (
    <div className="space-y-3">
      <h2 className="text-sm font-bold text-text-primary">NTLMv1 Acceptance</h2>
      <div className="grid grid-cols-[repeat(auto-fill,minmax(200px,1fr))] gap-2">
        <SecCard icon="🔓" label="NTLMv1 DCs" value={String((data.ntlmv1_hosts || []).length)} color={(data.ntlmv1_hosts || []).length ? "#ef4444" : "#22c55e"} />
      </div>
    </div>
  )
}

function NoPacView({ data }: { data: ADData }) {
  const np: any = data.nopac_risk || {}
  return (
    <div className="space-y-3">
      <h2 className="text-sm font-bold text-text-primary">noPac — CVE-2021-42278/42287</h2>
      <div className="grid grid-cols-[repeat(auto-fill,minmax(200px,1fr))] gap-2">
        <SecCard icon="🪲" label="noPac Risk" value={np.potentially_vulnerable ? "⚠ POTENTIAL" : "✓ Low"} color={np.potentially_vulnerable ? "#ef4444" : "#22c55e"} />
      </div>
    </div>
  )
}

function ProtUsersView({ data }: { data: ADData }) {
  const members = new Set((data.protected_users_members || []).map(u => u.toUpperCase()))
  const admins = (data.admins || []).filter(a => ["Domain Admins", "Enterprise Admins"].includes(a.group) && a.member_name.toLowerCase() !== "krbtgt")
  const gap = admins.filter(a => !members.has((a.member_name || "").toUpperCase()))
  return (
    <div className="space-y-3">
      <h2 className="text-sm font-bold text-text-primary">Protected Users Coverage Gap</h2>
      <div className="grid grid-cols-[repeat(auto-fill,minmax(200px,1fr))] gap-2">
        <SecCard icon="🛡" label="Protected Users" value={String(members.size)} color="#22c55e" />
        <SecCard icon="⚠" label="Privileged NOT Protected" value={String(gap.length)} color={gap.length ? "#ef4444" : "#22c55e"} />
      </div>
    </div>
  )
}

function NestedView({ data }: { data: ADData }) {
  const nm = data.nested_memberships || {}
  const d: any = data.domain || {}
  const thr = parseInt(String(d.lockout_threshold || 0))
  const ml = parseInt(String(d.min_pwd_length || 0))
  return (
    <div className="space-y-3">
      <h2 className="text-sm font-bold text-text-primary">Nested Group Membership</h2>
      <div className="grid grid-cols-[repeat(auto-fill,minmax(280px,1fr))] gap-2">
        {Object.entries(nm).map(([group, members]) => (
          <div key={group} className="glass rounded-xl p-3.5">
            <h3 className="text-xs font-bold text-text-primary mb-2">{group}</h3>
            {members.map(m => <div key={m} className="text-[10px] font-mono text-text-secondary py-0.5">{m}</div>)}
          </div>
        ))}
      </div>
      <h2 className="text-sm font-bold text-text-primary mt-4">Password Policy</h2>
      <div className="grid grid-cols-[repeat(auto-fill,minmax(200px,1fr))] gap-2">
        <SecCard icon="🔒" label="Lockout Threshold" value={String(thr)} color={thr === 0 ? "#ef4444" : thr <= 5 ? "#eab308" : "#22c55e"} />
        <SecCard icon="🔑" label="Min Pwd Length" value={String(ml)} color={ml <= 8 ? "#eab308" : "#22c55e"} />
      </div>
    </div>
  )
}

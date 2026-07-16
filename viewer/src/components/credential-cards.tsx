"use client"

import { ADData } from "@/lib/types"
import { cn, escapeHtml } from "@/lib/utils"

export function CredentialCards({ type, data }: { type: string; data: ADData }) {
  return (
    <div className="space-y-4 animate-fade-in">
      {type === "descpass" && <DescPasswords data={data} />}
      {type === "gpo_creds" && <GPOCreds data={data} />}
      {type === "validcreds" && <ValidCreds data={data} />}
      {type === "ouacls" && <OUACLs data={data} />}
      {type === "mssql" && <MSSQLView data={data} />}
      {type === "sccm" && <SCCMView data={data} />}
      {type === "lapspwd" && <LAPSView data={data} />}
      {type === "remediation" && <RemediationView data={data} />}
    </div>
  )
}

function DescPasswords({ data }: { data: ADData }) {
  const items = data.description_passwords || []
  return (
    <div className="space-y-3">
      <h2 className="text-sm font-bold text-text-primary">Description Field Credentials — {items.length} found</h2>
      {!items.length ? <div className="glass rounded-xl p-6 text-center text-text-muted text-xs">No credentials found in user descriptions</div> : (
        <div className="glass rounded-xl overflow-hidden"><div className="overflow-x-auto max-h-[500px]">
          <table className="w-full text-[10px]"><thead><tr className="bg-bg/40">{["User","Type","Credential","Match","DN"].map(h=><th key={h} className="px-3 py-2 text-left text-text-secondary font-semibold uppercase border-b border-white/[0.04]">{h}</th>)}</tr></thead>
            <tbody>{items.map((i,idx)=><tr key={idx} className="border-b border-white/[0.02] last:border-0 hover:bg-accent-cyan/[0.02]"><td className="px-3 py-1.5 font-mono font-semibold">{escapeHtml(i.user)}</td><td className="px-3 py-1.5"><span className="inline-flex text-[9px] px-1.5 py-0.5 rounded-full bg-accent-red/10 text-accent-red border border-accent-red/20">{i.pattern_type}</span></td><td className="px-3 py-1.5 font-mono text-accent-red">{escapeHtml(i.found_credential)}</td><td className="px-3 py-1.5 font-mono text-text-muted max-w-[250px] truncate">{escapeHtml(i.match)}</td><td className="px-3 py-1.5 font-mono text-text-muted text-[9px] max-w-[200px] truncate">{escapeHtml(i.dn)}</td></tr>)}</tbody>
          </table>
        </div></div>
      )}
    </div>
  )
}

function GPOCreds({ data }: { data: ADData }) {
  const items = data.gpo_contents || []
  return (
    <div className="space-y-3">
      <h2 className="text-sm font-bold text-text-primary">GPO / SYSVOL Credentials — {items.length} found</h2>
      {!items.length ? <div className="glass rounded-xl p-6 text-center text-text-muted text-xs">No credentials found in GPO/SYSVOL</div> : (
        <div className="glass rounded-xl overflow-hidden"><div className="overflow-x-auto max-h-[500px]">
          <table className="w-full text-[10px]"><thead><tr className="bg-bg/40">{["DC","File","Type","Credential","GPO Path"].map(h=><th key={h} className="px-3 py-2 text-left text-text-secondary font-semibold uppercase border-b border-white/[0.04]">{h}</th>)}</tr></thead>
            <tbody>{items.map((i,idx)=><tr key={idx} className="border-b border-white/[0.02] last:border-0 hover:bg-accent-cyan/[0.02]"><td className="px-3 py-1.5 font-mono">{escapeHtml(i.dc)}</td><td className="px-3 py-1.5 font-mono">{escapeHtml(i.file)}</td><td className="px-3 py-1.5"><span className="inline-flex text-[9px] px-1.5 py-0.5 rounded-full bg-accent-red/10 text-accent-red border border-accent-red/20">{i.type}</span></td><td className="px-3 py-1.5 font-mono text-accent-red">{escapeHtml(i.credential)}</td><td className="px-3 py-1.5 font-mono text-text-muted text-[9px] max-w-[200px] truncate">{escapeHtml(i.gpo_path)}</td></tr>)}</tbody>
          </table>
        </div></div>
      )}
    </div>
  )
}

function ValidCreds({ data }: { data: ADData }) {
  const items = data.validated_credentials || [], valid = items.filter(i => i.valid)
  return (
    <div className="space-y-3">
      <h2 className="text-sm font-bold text-text-primary">Validated Credentials — {valid.length} confirmed valid</h2>
      {!valid.length ? <div className="glass rounded-xl p-6 text-center text-text-muted text-xs">No valid credentials confirmed</div> : (
        <div className="glass rounded-xl overflow-hidden"><div className="overflow-x-auto max-h-[500px]">
          <table className="w-full text-[10px]"><thead><tr className="bg-bg/40">{["Username","Password","Method","DA?","Admin"].map(h=><th key={h} className="px-3 py-2 text-left text-text-secondary font-semibold uppercase border-b border-white/[0.04]">{h}</th>)}</tr></thead>
            <tbody>{valid.map((i,idx)=><tr key={idx} className="border-b border-white/[0.02] last:border-0 hover:bg-accent-cyan/[0.02] bg-accent-red/5 border-l-2 border-l-accent-red"><td className="px-3 py-1.5 font-mono font-semibold">{escapeHtml(i.username)}</td><td className="px-3 py-1.5 font-mono text-accent-red">{escapeHtml(i.password)}</td><td className="px-3 py-1.5">{escapeHtml(i.method)}</td><td className="px-3 py-1.5">{i.is_da ? <span className="inline-flex text-[9px] px-1.5 py-0.5 rounded-full bg-accent-red/10 text-accent-red border border-accent-red/20">DA!</span> : "No"}</td><td className="px-3 py-1.5">{i.admin_count}</td></tr>)}</tbody>
          </table>
        </div></div>
      )}
    </div>
  )
}

function OUACLs({ data }: { data: ADData }) {
  const items = data.ou_acls || []
  return (
    <div className="space-y-3">
      <h2 className="text-sm font-bold text-text-primary">OU Container ACLs — {items.length} OUs with dangerous ACLs</h2>
      {!items.length ? <div className="glass rounded-xl p-6 text-center text-text-muted text-xs">No dangerous OU ACLs</div> :
        items.map((ou, i) => (
          <div key={i} className="glass rounded-xl p-3.5">
            <h3 className="text-xs font-bold text-text-primary mb-2">{escapeHtml(ou.ou)} <span className="text-text-muted font-normal">(~{ou.object_count} objects)</span></h3>
            <div className="overflow-x-auto"><table className="w-full text-[10px]"><thead><tr className="bg-bg/40">{["Principal","Right"].map(h=><th key={h} className="px-3 py-1.5 text-left text-text-secondary font-semibold uppercase">{h}</th>)}</tr></thead>
              <tbody>{ou.dangerous_aces.map((a, j) => <tr key={j} className="border-b border-white/[0.02] last:border-0 bg-accent-red/5 border-l-2 border-l-accent-red"><td className="px-3 py-1.5 font-mono">{escapeHtml(a.principal)}</td><td className="px-3 py-1.5"><span className="inline-flex text-[9px] px-1.5 py-0.5 rounded-full bg-accent-red/10 text-accent-red border border-accent-red/20">{a.right}</span></td></tr>)}</tbody></table></div>
          </div>
        ))
      }
    </div>
  )
}

function MSSQLView({ data }: { data: ADData }) {
  return <SimpleTable title="MSSQL Servers" items={data.mssql_servers || []} cols={["host","port","service_account","spn"]} />
}

function SCCMView({ data }: { data: ADData }) {
  return <SimpleTable title="SCCM Sites" items={data.sccm || []} cols={["name","site_code","service_account","spn","type"]} />
}

function LAPSView({ data }: { data: ADData }) {
  const items = data.laps_passwords || []
  return (
    <div className="space-y-3">
      <h2 className="text-sm font-bold text-text-primary">LAPS Passwords Readable — {items.length}</h2>
      {!items.length ? <div className="glass rounded-xl p-6 text-center text-text-muted text-xs">No LAPS passwords readable</div> :
        <div className="glass rounded-xl overflow-hidden"><div className="overflow-x-auto max-h-[500px]">
          <table className="w-full text-[10px]"><thead><tr className="bg-bg/40">{["Computer","Password","Source"].map(h=><th key={h} className="px-3 py-2 text-left text-text-secondary font-semibold uppercase border-b border-white/[0.04]">{h}</th>)}</tr></thead>
            <tbody>{items.map((i,idx)=><tr key={idx} className="border-b border-white/[0.02] last:border-0 hover:bg-accent-cyan/[0.02] bg-accent-red/5 border-l-2 border-l-accent-red"><td className="px-3 py-1.5 font-mono font-semibold">{escapeHtml(i.computer)}</td><td className="px-3 py-1.5 font-mono text-accent-red">{escapeHtml(i.password)}</td><td className="px-3 py-1.5 font-mono text-text-muted">{escapeHtml(i.source)}</td></tr>)}</tbody>
          </table>
        </div></div>
      }
    </div>
  )
}

function RemediationView({ data }: { data: ADData }) {
  const items = data.remediation_snippets || []
  return (
    <div className="space-y-3">
      <h2 className="text-sm font-bold text-text-primary">Remediation Snippets — {items.length}</h2>
      {!items.length ? <div className="glass rounded-xl p-6 text-center text-text-muted text-xs">No remediation snippets</div> :
        <div className="grid grid-cols-[repeat(auto-fill,minmax(400px,1fr))] gap-2">
          {items.map((it, i) => (
            <div key={i} className="glass rounded-xl p-3.5 border-l-[3px] border-l-accent-blue">
              <h3 className="text-xs font-bold text-text-primary mb-2">{escapeHtml(it.title)}</h3>
              <pre className="text-[11px] font-mono text-accent-green bg-black/30 p-3 rounded-lg overflow-x-auto whitespace-pre-wrap leading-relaxed">{escapeHtml(it.psh)}</pre>
            </div>
          ))}
        </div>
      }
    </div>
  )
}

function SimpleTable({ title, items, cols }: { title: string; items: any[]; cols: string[] }) {
  return (
    <div className="space-y-3">
      <h2 className="text-sm font-bold text-text-primary">{title} — {items.length}</h2>
      {!items.length ? <div className="glass rounded-xl p-6 text-center text-text-muted text-xs">No data</div> :
        <div className="glass rounded-xl overflow-hidden"><div className="overflow-x-auto max-h-[500px]">
          <table className="w-full text-[10px]"><thead><tr className="bg-bg/40">{cols.map(h=><th key={h} className="px-3 py-2 text-left text-text-secondary font-semibold uppercase border-b border-white/[0.04]">{h}</th>)}</tr></thead>
            <tbody>{items.map((i,idx)=><tr key={idx} className="border-b border-white/[0.02] last:border-0 hover:bg-accent-cyan/[0.02]">{cols.map(c=><td key={c} className="px-3 py-1.5 font-mono">{escapeHtml(String(i[c] ?? "—"))}</td>)}</tr>)}</tbody>
          </table>
        </div></div>
      }
    </div>
  )
}

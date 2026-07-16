"use client"

import { useState } from "react"
import { useData } from "@/hooks/use-data"
import { Header } from "@/components/header"
import { Navigation } from "@/components/navigation"
import { Overview } from "@/components/overview"
import { AttackChains } from "@/components/attack-chains"
import { AttackGraph } from "@/components/attack-graph"
import { DataTable } from "@/components/data-table"
import { CredentialCards } from "@/components/credential-cards"
import { SecurityCards } from "@/components/security-cards"
import { LoadingSkeleton } from "@/components/loading-skeleton"

export type TabId =
  | "overview" | "chains" | "graph"
  | "shadow" | "dcsync" | "descpass" | "gpo_creds" | "validcreds" | "lapspwd"
  | "delegation" | "coercion" | "nopac" | "ntlmv1" | "protusers"
  | "computers" | "users" | "groups" | "sessions" | "shares" | "trusts" | "tombstoned"
  | "acl" | "nested" | "gpo" | "gpowrite" | "adminsd" | "ouacls" | "fgpp"
  | "adcs" | "ldapsec" | "vulnscan" | "winrm" | "mssql" | "sccm" | "sensitive"
  | "remediation"

export default function Home() {
  const { data, loading } = useData()
  const [activeTab, setActiveTab] = useState<TabId>("overview")

  if (loading) return <LoadingSkeleton />

  const daSet: Set<string> = new Set((data.da_users || []).map((u: string) => u.toUpperCase()))

  return (
    <div className="min-h-screen">
      <Header data={data} />
      <Navigation activeTab={activeTab} onTabChange={setActiveTab} data={data} />

      <main className="px-6 py-5 max-w-[1800px] mx-auto">
        {activeTab === "overview" && <Overview data={data} daSet={daSet} />}
        {activeTab === "chains" && <AttackChains data={data} />}
        {activeTab === "graph" && <AttackGraph data={data} daSet={daSet} />}

        {activeTab === "shadow" && <DataTable title="Shadow Credentials (msDS-KeyCredentialLink)" data={data.shadow_creds} cols={[{k:"user",l:"User/Computer"},{k:"dn",l:"DN"}]} />}
        {activeTab === "dcsync" && <DataTable title="DCSync Rights Holders" data={data.dcsync_rights} cols={[{k:"user",l:"User/Group"},{k:"sid",l:"SID"},{k:"partial",l:"Full",fmt:(v:any)=>v?"Partial":"Full (All)"}]} daSet={daSet} daKey="user" />}
        {activeTab === "fgpp" && <DataTable title="Fine-Grained Password Policies" data={data.fgpp} cols={[{k:"name",l:"Name"},{k:"min_len",l:"MinLen"},{k:"complexity",l:"Complex",fmt:(v:any)=>v?"Yes":"No"},{k:"applies_to",l:"Applies To",fmt:(v:any)=>(v||[]).join(", ")}]} />}
        {activeTab === "gpowrite" && <DataTable title="GPO Write Permissions" data={data.gpo_write_perms} cols={[{k:"user",l:"User"},{k:"gpo",l:"GPO"}]} daSet={daSet} daKey="user" />}
        {activeTab === "adminsd" && <DataTable title="AdminSDHolder Anomalies" data={data.adminsd_acl} cols={[{k:"user",l:"User"},{k:"right",l:"Right"}]} flagged />}
        {activeTab === "sensitive" && <DataTable title="Sensitive Files Found" data={data.sensitive_files} cols={[{k:"host",l:"Host"},{k:"share",l:"Share"},{k:"path",l:"Path"},{k:"type",l:"Type"}]} />}
        {activeTab === "winrm" && <DataTable title="WinRM / PSRemoting Hosts" data={(data.computers||[]).filter(c=>c.winrm_open).map(c=>({name:c.name}))} cols={[{k:"name",l:"Host"}]} />}
        {activeTab === "computers" && <DataTable title="Computer Accounts" data={data.computers} searchable cols={[{k:"name",l:"Name"},{k:"os",l:"OS"},{k:"is_dc",l:"DC",fmt:(v:any)=>v?"Yes":"No"}]} daSet={daSet} />}
        {activeTab === "users" && <DataTable title="User Accounts" data={data.users} searchable cols={[{k:"name",l:"Username"},{k:"display_name",l:"Display Name"},{k:"enabled",l:"Status",fmt:(v:any)=>v?"Enabled":"Disabled"},{k:"admin_count",l:"Admin",fmt:(v:any)=>v>0?"Yes":"No"},{k:"description",l:"Description"}]} daSet={daSet} daKey="name" />}
        {activeTab === "groups" && <DataTable title="Security Groups" data={data.groups} searchable cols={[{k:"name",l:"Group Name"},{k:"member_count",l:"Members"},{k:"admin_count",l:"Privileged",fmt:(v:any)=>v>0?"Yes":"—"},{k:"description",l:"Description"}]} />}
        {activeTab === "sessions" && <DataTable title="Active Sessions" data={[...data.sessions.map(s=>({...s,stype:"SMB"})),...data.loggedon.map(s=>({...s,stype:"Interactive"}))]} searchable cols={[{k:"user",l:"Username"},{k:"stype",l:"Type"},{k:"host_name",l:"Host"},{k:"source",l:"Source"}]} daSet={daSet} daKey="user" />}
        {activeTab === "shares" && <DataTable title="SMB Shares" data={data.shares} cols={[{k:"host",l:"Host"},{k:"share",l:"Share"},{k:"remark",l:"Remark"}]} />}
        {activeTab === "trusts" && <DataTable title="Domain Trusts" data={data.trusts} cols={[{k:"name",l:"Name"},{k:"direction",l:"Direction"},{k:"type",l:"Type"},{k:"transitive",l:"Transitive",fmt:(v:any)=>v?"Yes":"No"},{k:"sid_filtering",l:"SID Filtering",fmt:(v:any)=>v?"Enabled":"Disabled"}]} />}
        {activeTab === "tombstoned" && <DataTable title="Tombstoned Objects" data={data.tombstoned_objects} searchable cols={[{k:"name",l:"Name"},{k:"type",l:"Type"},{k:"last_parent",l:"Last Parent"},{k:"when_deleted",l:"Deleted"}]} />}
        {activeTab === "acl" && <DataTable title="Dangerous ACL Edges" data={data.acl_edges} cols={[{k:"source",l:"Source"},{k:"right",l:"Right"},{k:"target",l:"Target"},{k:"severity",l:"Severity"},{k:"description",l:"Impact"}]} />}
        {activeTab === "gpo" && <DataTable title="Group Policy Objects" data={data.gpos} cols={[{k:"name",l:"GPO Name"},{k:"disabled",l:"Status",fmt:(v:any)=>v?"Disabled":"Active"},{k:"version",l:"Version"},{k:"linked_ous",l:"Linked OUs",fmt:(v:any)=>(v||[]).join(", ")}]} />}
        {activeTab === "adcs" && <DataTable title="ADCS ESC Findings" data={data.adcs_esc} cols={[{k:"id",l:"ESC ID",fmt:(v:any)=>"ESC"+v},{k:"template",l:"Template"},{k:"severity",l:"Severity"},{k:"description",l:"Description"}]} />}

        {activeTab === "ldapsec" && <SecurityCards type="ldapsec" data={data} />}
        {activeTab === "vulnscan" && <SecurityCards type="vulnscan" data={data} />}
        {activeTab === "delegation" && <SecurityCards type="delegation" data={data} />}
        {activeTab === "coercion" && <SecurityCards type="coercion" data={data} />}
        {activeTab === "ntlmv1" && <SecurityCards type="ntlmv1" data={data} />}
        {activeTab === "nopac" && <SecurityCards type="nopac" data={data} />}
        {activeTab === "protusers" && <SecurityCards type="protusers" data={data} />}
        {activeTab === "nested" && <SecurityCards type="nested" data={data} />}

        {activeTab === "descpass" && <CredentialCards type="descpass" data={data} />}
        {activeTab === "gpo_creds" && <CredentialCards type="gpo_creds" data={data} />}
        {activeTab === "validcreds" && <CredentialCards type="validcreds" data={data} />}
        {activeTab === "ouacls" && <CredentialCards type="ouacls" data={data} />}
        {activeTab === "mssql" && <CredentialCards type="mssql" data={data} />}
        {activeTab === "sccm" && <CredentialCards type="sccm" data={data} />}
        {activeTab === "lapspwd" && <CredentialCards type="lapspwd" data={data} />}
        {activeTab === "remediation" && <CredentialCards type="remediation" data={data} />}
      </main>
    </div>
  )
}

import { ADData } from "./types"

let cachedData: ADData | null = null

export async function loadData(): Promise<ADData> {
  if (cachedData) return cachedData
  try {
    const res = await fetch("/data.json")
    if (!res.ok) throw new Error(`Failed to load data: ${res.status}`)
    cachedData = await res.json()
    return cachedData!
  } catch {
    // Demo mode — return mock structure
    cachedData = getEmptyData()
    return cachedData
  }
}

export function getEmptyData(): ADData {
  return {
    meta: {
      target: "—", domain: "—", base_dn: "", enum_time: new Date().toISOString(),
      stats: {} as any,
    },
    domain: {} as any,
    users: [], groups: [], computers: [], da_users: [], admins: [],
    sessions: [], loggedon: [], rdp_open: [], rdp_access: [], local_admins: [],
    edges: [], graph_nodes: [], acl_edges: [], attack_chains: [],
    shadow_creds: [], dcsync_rights: [], fgpp: [], gpo_write_perms: [],
    adminsd_acl: [], sensitive_files: [], vuln_scan: { spooler: [], zerologon: [], signing: [] },
    winrm_hosts: [], remediation_snippets: [], shares: [], trusts: [],
    adcs_esc: [], ldap_security: { signing_enforced: null, cb_enforced: null, ldap_signing: null, channel_binding: null },
    tombstoned_objects: [], protected_users_members: [], delegation_matrix: [],
    printerbug_hosts: [], petitpotam_hosts: [], ntlmv1_hosts: [],
    nopac_risk: { potentially_vulnerable: false, quota: 0, dfl_string: "", risky_dcs: [], note: "" },
    description_passwords: [], gpo_contents: [], validated_credentials: [],
    ou_acls: [], mssql_servers: [], sccm: [], laps_passwords: [],
    gpos: [], gpo_links: [], nested_memberships: {}, spns: [], asrep: [],
    domain_controllers: [],
  }
}

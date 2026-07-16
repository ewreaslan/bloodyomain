export interface ADData {
  meta: Meta
  domain: DomainInfo
  users: User[]
  groups: Group[]
  computers: Computer[]
  da_users: string[]
  admins: AdminMembership[]
  sessions: Session[]
  loggedon: Session[]
  rdp_open: string[]
  rdp_access: RDPAccess[]
  local_admins: LocalAdmin[]
  edges: GraphEdge[]
  graph_nodes: GraphNode[]
  acl_edges: ACLEdge[]
  attack_chains: AttackChain[]
  shadow_creds: ShadowCred[]
  dcsync_rights: DCSyncRight[]
  fgpp: FGPP[]
  gpo_write_perms: GPOWritePerm[]
  adminsd_acl: AdminSDEntry[]
  sensitive_files: SensitiveFile[]
  vuln_scan: VulnScan
  winrm_hosts: string[]
  remediation_snippets: RemediationSnippet[]
  shares: Share[]
  trusts: Trust[]
  adcs_esc: ADCSFinding[]
  ldap_security: LDAPSecurity
  tombstoned_objects: TombstonedObject[]
  protected_users_members: string[]
  delegation_matrix: DelegationEntry[]
  printerbug_hosts: string[]
  petitpotam_hosts: string[]
  ntlmv1_hosts: string[]
  nopac_risk: NoPacRisk
  description_passwords: DescPassword[]
  gpo_contents: GPOContent[]
  validated_credentials: ValidatedCredential[]
  ou_acls: OUACL[]
  mssql_servers: MSSQLServer[]
  sccm: SCCMSite[]
  laps_passwords: LAPSPassword[]
  gpos: GPO[]
  gpo_links: GPOLink[]
  nested_memberships: Record<string, string[]>
  spns: SPN[]
  asrep: string[]
  domain_controllers: string[]
}

export interface Meta {
  target: string
  domain: string
  base_dn: string
  enum_time: string
  stats: Stats
}

export interface Stats {
  users: number; groups: number; computers: number; ous: number
  gpos: number; spns: number; asrep_users: number; edges: number
  sessions: number; loggedon: number; local_admins: number
  rdp_open: number; attack_chains: number; critical_chains: number
  high_chains: number; da_users: number; acl_edges: number
  gpo_links: number; shares: number; adcs_esc: number
  shadow_creds: number; dcsync_rights: number; fgpp: number
  gpo_write_perms: number; adminsd_acl: number; sensitive_files: number
  winrm_hosts: number; exchange_dcsync: number; description_passwords: number
  gpo_credentials: number; validated_credentials: number; ou_acls: number
  mssql_servers: number; sccm_sites: number; laps_passwords_read: number
  remediation_snippets: number; tombstoned_objects: number
  protected_users_gap: number; delegation_matrix: number
  printerbug_hosts: number; petitpotam_hosts: number; ntlmv1_hosts: number
  ldap_signing_enforced: boolean | null; channel_binding_enforced: boolean | null
  nopac_risk: boolean; mitre_ttps: number; laps_readers: number; service_accounts: number
}

export interface DomainInfo {
  name: string; dn: string
  min_pwd_length: number | null; lockout_threshold: number | null
  pwd_history: number | null; machine_account_quota: number | null
  lockout_window_min: number | null; lockout_duration_min: number | null
  behavior_version: number | null
}

export interface User {
  name: string; display_name: string; enabled: boolean
  password_never_expires: boolean; password_not_required: boolean
  trusted_for_delegation: boolean; no_preauth: boolean
  spns: string[]; groups: string[]; admin_count: number
  description: string; dn: string
}

export interface Group {
  name: string; security_group: boolean
  member_count: number; admin_count: number; description: string
}

export interface Computer {
  name: string; dns: string; os: string; is_dc: boolean; enabled: boolean
  rdp_open: boolean; winrm_open: boolean
  trusted_for_delegation: boolean
  laps_configured: boolean; laps_legacy: boolean; laps_new: boolean
  rbcd: string[]; sessions: Session[]; loggedon: Session[]
  local_admins: { user: string }[]; rdp_users: string[]
  shares: { share: string; remark: string }[]
}

export interface Session { user: string; host_name?: string; host?: string; source?: string; from?: string; domain?: string; stype?: string }

export interface RDPAccess { user: string; host: string; source: string }
export interface LocalAdmin { user: string; host: string; type: string }

export interface GraphNode { id: string; type: string; admin?: number; enabled?: boolean; spns?: number; no_preauth?: boolean; is_da?: boolean; is_dc?: boolean; rdp_open?: boolean; delegation?: boolean; rbcd?: string[] }

export interface GraphEdge { source: string; target: string; relation: string; highlight?: boolean; color?: string }

export interface ACLEdge { source: string; target: string; right: string; severity: string; description: string }

export interface AttackChain {
  id: string; type: string; severity: "CRITICAL" | "HIGH" | "MEDIUM" | "INFO"
  title: string; description: string; steps: string[]
  priority_score?: number; mitre?: { id: string; name: string }[]
  nodes: string[]; edges: [string, string, string][]
}

export interface ShadowCred { user: string; dn: string }
export interface DCSyncRight { user: string; sid: string; partial: boolean }
export interface FGPP { name: string; min_len: number; complexity: boolean; applies_to: string[] }

export interface GPOWritePerm { user: string; gpo: string }
export interface AdminSDEntry { user: string; right: string }
export interface SensitiveFile { host: string; share: string; path: string; type: string }

export interface VulnScan { spooler: string[]; zerologon: string[]; signing: string[] }
export interface RemediationSnippet { title: string; psh: string; mitre?: string }

export interface Share { host: string; share: string; remark: string; sensitive?: boolean }

export interface Trust {
  name: string; flat_name: string; direction: string; type: string
  transitive: boolean; forest_trust: boolean
  sid_filtering: boolean; selective_auth: boolean
}

export interface ADCSFinding { id: number; template: string; severity: string; description: string; steps: string[] }

export interface LDAPSecurity { signing_enforced: boolean | null; cb_enforced: boolean | null; ldap_signing: number | null; channel_binding: number | null }

export interface TombstonedObject { name: string; type: string; last_parent: string; when_deleted: string; sid: string }

export interface DelegationEntry { principal: string; type: string; unconstrained: boolean; constrained_to: string[]; rbcd_allowed: string[]; is_dc: boolean }

export interface NoPacRisk { potentially_vulnerable: boolean; quota: number; dfl_string: string; risky_dcs: string[]; note: string }

export interface DescPassword { user: string; pattern_type: string; found_credential: string; match: string; dn: string }

export interface GPOContent { dc: string; file: string; type: string; credential: string; gpo_path: string }

export interface ValidatedCredential { username: string; password: string; method: string; valid: boolean; is_da: boolean; admin_count: number }

export interface OUACL { ou: string; object_count: number; dangerous_aces: { principal: string; right: string }[] }

export interface MSSQLServer { host: string; port: number; service_account: string; spn: string; is_da: boolean }
export interface SCCMSite { name: string; site_code: string; service_account: string; spn: string; type: string }
export interface LAPSPassword { computer: string; password: string; source: string }

export interface GPO { name: string; disabled: boolean; version: number; linked_ous: string[]; path: string }
export interface GPOLink { gpo: string; ou: string; enforced: boolean; disabled: boolean }
export interface SPN { user: string }
export interface AdminMembership { group: string; member_name: string }

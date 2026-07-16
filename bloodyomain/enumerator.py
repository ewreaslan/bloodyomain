#!/usr/bin/env python3
"""Active Directory enumerator — all LDAP & SMB scanning phases."""
import json
import re
import base64
import datetime
import time
import concurrent.futures
import threading

from bloodyomain.core import (
    C, log, section,
    _escape_ldap_filter_value, dn_to_name, filetime_to_dt, days_since,
    _guid_from_ace, cpassword_decrypt,
    WELL_KNOWN_SIDS, DANGEROUS_ACCESS, DANGEROUS_GUIDS,
    LDAP3_AVAILABLE, IMPACKET_LDAP, NRPC_AVAILABLE,
    security_descriptor_control,
)
from bloodyomain.exporter import BloodHoundExporter
from bloodyomain.attack_chain import AttackChainEngine
from bloodyomain.dacl import DACLAnalyzer

# ldap3 SUBTREE constant (needed for search scope)
try:
    from ldap3 import SUBTREE
except ImportError:
    SUBTREE = 2  # default SUBTREE value

# impacket ldaptypes
if IMPACKET_LDAP:
    from impacket.ldap import ldaptypes

class ADEnumerator:
    def __init__(self, connector, smb_engine=None, threads=10, advanced=True):
        self.conn = connector
        self.smb = smb_engine
        self.threads = threads
        self.advanced = advanced
        self.data = {
            "meta": {}, "domain": {}, "users": [], "groups": [], "computers": [],
            "ous": [], "gpos": [], "gpo_links": [], "admins": [], "spns": [],
            "asrep": [], "trusts": [], "edges": [], "sessions": [], "loggedon": [],
            "local_admins": [], "rdp_access": [], "rdp_open": [], "acl_edges": [],
            "shares": [], "attack_chains": [], "da_users": [], "dc_hosts": [],
            "graph_nodes": [], "nested_memberships": {}, "adcs_esc": [],
            "shadow_creds": [], "dcsync_rights": [], "fgpp": [],
            "description_passwords": [],
            "gpo_contents": [],
            "validated_credentials": [],
            "ou_acls": [],
            "mssql_servers": [], "sccm": [], "laps_passwords": [],
            "gpo_write_perms": [], "adminsd_acl": [], "sensitive_files": [],
            "vuln_scan": {"spooler": [], "zerologon": [], "signing": []},
            "winrm_hosts": [], "exchange_dcsync": [], "remediation_snippets": []
        }

    def _attr(self, e, key, default=""):
        try:
            v = e.get("attributes", {}).get(key, default)
            if isinstance(v, list): return v[0] if v else default
            return v if v is not None else default
        except (KeyError, IndexError, TypeError, AttributeError): return default

    def _run_parallel(self, fn, items):
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            return list(ex.map(fn, items))

    def enumerate_all(self, smb_scan=True, spray=False, spray_pass=None, bh_export=None):
        section("PHASE 1 — Domain & Password Policy")
        self._enum_domain()
        if self.advanced:
            self._enum_fgpp()

        section("PHASE 2 — User Accounts (Parallel)")
        self._enum_users()
        self._scan_description_passwords()  # Enum4linux-style credential hunt

        section("PHASE 3 — Groups & Memberships (Parallel)")
        self._enum_groups()

        section("PHASE 4 — Nested Group Resolution")
        self._resolve_nested_groups()

        section("PHASE 5 — Computer Accounts (Parallel)")
        self._enum_computers()

        section("PHASE 6 — OUs & GPO Links")
        self._enum_ous_gpos()

        section("PHASE 6b — LDAP Security (Signing + Channel Binding)")
        self._check_ldap_security()

        section("PHASE 6c — NoPac Check (CVE-2021-42287/42278)")
        self._check_nopac()

        section("PHASE 6d — Protected Users Enumeration")
        self._enum_protected_users()

        section("PHASE 7 — Privilege Mapping")
        self._enum_admins()

        section("PHASE 8 — Kerberos Targets")
        self._report_spns()
        self._report_asrep()

        section("PHASE 9 — Domain Trusts (with details)")
        self._enum_trusts()

        section("PHASE 10 — ACL / DACL Analysis")
        self._enum_dacls()
        if self.advanced:
            self._enum_ou_dacls()

        section("PHASE 11 — ADCS (Certificate Services)")
        self._enum_adcs()

        section("PHASE 11b — ADFS Enumeration")
        self._enum_adfs()

        section("PHASE 11c — LAPS Password Readers")
        self._enum_laps_readers()
        if self.advanced:
            self._read_laps_passwords()  # Actually read LAPS passwords

        section("PHASE 11c2 — MSSQL Enumeration (SPN-based)")
        self._enum_mssql()

        section("PHASE 11c3 — SCCM / MECM Enumeration")
        self._enum_sccm()

        section("PHASE 11d — Schema & Enterprise Admins + krbtgt")
        self._enum_schema_enterprise_admins()

        section("PHASE 11e — Service Account Mapping")
        self._map_service_accounts()

        if self.advanced:
            section("PHASE 12 — Shadow Credentials (msDS-KeyCredentialLink)")
            self._enum_shadow_creds()

            section("PHASE 12b — Tombstoned Objects")
            self._enum_tombstoned()

            section("PHASE 12c — Delegation Matrix")
            self._build_delegation_matrix()

            section("PHASE 12d — Coercion Targets (PrinterBug / PetitPotam)")
            self._check_coercion_targets()

            section("PHASE 12e — NTLM Relay Risk Check")
            self._check_ntlm_relay_risk()

            section("PHASE 13 — DCSync Rights Audit")
            self._enum_dcsync_rights()

            section("PHASE 14 — AdminSDHolder ACL")
            self._enum_adminsdholder()

            section("PHASE 15 — GPO Write Permissions")
            self._enum_gpo_write_perms()

            section("PHASE 16 — Exchange Permissions / DCSync")
            self._enum_exchange_perms()

        if smb_scan and self.smb:
            section("PHASE 17 — SMB Sessions & Logged-on")
            self._smb_sessions()
            self._smb_loggedon()

            section("PHASE 18 — Local Admins & RDP")
            self._smb_local_admins()
            self._smb_rdp()

            section("PHASE 19 — Shares & Sensitive Files")
            self._smb_shares()
            if self.advanced:
                self._enum_sensitive_files()
                self._enum_gpo_contents()  # GPO deep parser + credential crawler

            section("PHASE 20 — Vulnerability Scan (Spooler, Signing, WinRM)")
            self._vuln_scan()
        else:
            log("SMB scanning skipped", "WARN")

        if spray and spray_pass:
            section("PHASE 21 — Password Spray")
            self._password_spray(spray_pass)

        if self.advanced:
            section("PHASE 21b — Credential Validation")
            self._validate_credentials()

        section("PHASE 22 — Attack Chain Analysis")
        self._build_chains()

        section("PHASE 23 — Graph Construction")
        self._build_graph()

        if self.advanced:
            section("PHASE 24 — Remediation Snippets")
            self._build_remediation()

        # DÜZELTME: export() self.data["meta"]["domain"] okuyor; meta alanı
        # _finalize_meta() çağrısıyla doldurulur. Eski sırada meta henüz boş {}
        # olduğundan KeyError: 'domain' ile çöküyordu. Sıra düzeltildi.
        self._finalize_meta()

        if bh_export:
            BloodHoundExporter.export(self.data, bh_export)

        return self.data

    # ── LDAP methods ──
    def _enum_domain(self):
        try:
            res = self.conn.search("(objectClass=domain)",
                ["name","whenCreated","minPwdLength","lockoutThreshold",
                 "pwdHistoryLength","ms-DS-MachineAccountQuota","lockoutObservationWindow",
                 "lockoutDuration","msDS-Behavior-Version"])
            if res:
                e = res[0]
                a = e.get("attributes", {})
                def _i(k,d=0): return int(a.get(k,d) or d)
                obs_raw = _i("lockoutObservationWindow",0)
                obs_min = abs(obs_raw)//600000000 if obs_raw else 0
                dur_raw = _i("lockoutDuration",0)
                dur_min = abs(dur_raw)//600000000 if dur_raw else 0
                self.data["domain"] = {
                    "name": self._attr(e,"name", self.conn.domain),
                    "dn": e.get("dn",""),
                    "created": str(self._attr(e,"whenCreated","")),
                    "min_pwd_length": _i("minPwdLength"),
                    "lockout_threshold": _i("lockoutThreshold"),
                    "pwd_history": _i("pwdHistoryLength"),
                    "machine_account_quota": _i("ms-DS-MachineAccountQuota",10),
                    "lockout_window_min": obs_min,
                    "lockout_duration_min": dur_min,
                    "behavior_version": _i("msDS-Behavior-Version", 0),
                }
                log(f"Domain: {self.data['domain']['name']}", "SUCCESS")
                log(f"PwdLen:{self.data['domain']['min_pwd_length']} "
                    f"Lockout:{self.data['domain']['lockout_threshold']} "
                    f"History:{self.data['domain']['pwd_history']}", "DATA")
        except Exception as ex:
            log(f"Domain: {ex}", "WARN")

    def _enum_users(self):
        try:
            res = self.conn.search(
                "(&(objectClass=user)(objectCategory=person))",
                ["sAMAccountName","displayName","mail","memberOf","userAccountControl",
                 "pwdLastSet","lastLogonTimestamp","lastLogon","description","adminCount",
                 "servicePrincipalName","whenCreated","userPrincipalName","objectSid","badPwdCount",
                 "msDS-KeyCredentialLink"])
            for e in res:
                a = e.get("attributes", {})
                uac = int(self._attr(e,"userAccountControl",0) or 0)
                spns = a.get("servicePrincipalName", [])
                if not isinstance(spns, list): spns = [spns] if spns else []
                grps = a.get("memberOf", [])
                if not isinstance(grps, list): grps = [grps] if grps else []
                ll_ts = filetime_to_dt(self._attr(e,"lastLogonTimestamp",0))
                ll = filetime_to_dt(self._attr(e,"lastLogon",0))
                last_logon = ll if ll and (not ll_ts or ll > ll_ts) else ll_ts
                ps = filetime_to_dt(self._attr(e,"pwdLastSet",0))
                shadow = bool(a.get("msDS-KeyCredentialLink"))
                user = {
                    "name": self._attr(e,"sAMAccountName"),
                    "display_name": self._attr(e,"displayName"),
                    "email": self._attr(e,"mail"),
                    "dn": e.get("dn",""),
                    "admin_count": int(self._attr(e,"adminCount",0) or 0),
                    "description": self._attr(e,"description"),
                    "enabled": not bool(uac & 2),
                    "password_not_required": bool(uac & 32),
                    "password_never_expires": bool(uac & 65536),
                    "trusted_for_delegation": bool(uac & 524288),
                    "no_preauth": bool(uac & 4194304),
                    "smart_card_required": bool(uac & 262144),
                    "groups": grps, "spns": spns,
                    "created": str(self._attr(e,"whenCreated","")),
                    "last_logon": str(last_logon) if last_logon else None,
                    "last_logon_days": days_since(last_logon),
                    "pwd_last_set": str(ps) if ps else None,
                    "pwd_last_set_days": days_since(ps),
                    "bad_pwd_count": int(self._attr(e,"badPwdCount",0) or 0),
                    "sid": str(self._attr(e,"objectSid","")),
                    "shadow_creds": shadow,
                }
                if user["no_preauth"]:
                    self.data["asrep"].append(user["name"])
                    log(f"AS-REP Roastable: {C.RED}{user['name']}{C.RESET}", "CRIT")
                if spns:
                    self.data["spns"].append({"user": user["name"], "spns": spns})
                if shadow:
                    self.data["shadow_creds"].append({"user": user["name"], "dn": user["dn"]})
                self.data["users"].append(user)
            en = sum(1 for u in self.data["users"] if u["enabled"])
            log(f"Users: {len(self.data['users'])}  Enabled:{en}  "
                f"SPNs:{len(self.data['spns'])}  AS-REP:{len(self.data['asrep'])}", "SUCCESS")
        except Exception as ex:
            log(f"Users: {ex}", "WARN")

    def _scan_description_passwords(self):
        """Kullanici description alaninda birakilmis parola/kimlik bilgilerini tara.
        Enum4linux / LDAPDomainDump benzeri credential hunting."""
        section("PHASE 2b — Description Field Credential Scan")
        if not self.data.get("users"):
            log("No user data to scan", "WARN")
            return []

        # ── Credential detection patterns ──
        patterns = [
            # Label: keyword followed by separator then value
            (r'(?i)(?:password|passw[o0]rd|pass|pwd|pw|parola|sifre|şifre|sifre|secret|key|token|otp|pin|code)\s*[:=]\s*(\S+)',
             "label"),
            # Common: "password for user X is Y" or "user:pass"
            (r'(?i)(?:password|pass|pwd|pw)\s+(?:for|is|:|=)\s+\S+\s+(?:is|:|=)\s*(\S+)',
             "sentence"),
            # user/pass format like "jsmith:Summer2024!" or "jsmith / Pass123"
            (r'(?i)(\w+)\s*[:/]\s*(\S{4,})',
             "userpass"),
            # "initial password: X" type
            (r'(?i)(?:initial|default|temp|gecici|ilk|varsayilan|varsayılan)\s+(?:password|pwd|parola|şifre|pass)\s*(?:is|:|=)?\s*(\S+)',
             "initial"),
            # "changed password to X"
            (r'(?i)(?:changed|reset|updated?|set)\s+(?:password|pwd|pass)\s+(?:to|=|:)\s*(\S+)',
             "changed"),
            # "hesap / account" + credential
            (r'(?i)(?:hesap|account|kullanici|kullanıcı|user|login)\s*(?:bilgisi|bilgileri|info|creds?)?\s*[:=]\s*(\S+)',
             "account_info"),
            # base64-looking blob (potential encoded cred)
            (r'(?i)(?:pass|pwd|token|key|secret|auth)\s*[:=]\s*([A-Za-z0-9+/=]{20,})',
             "base64"),
            # Anything that looks like a complex password (3+ char types, 6+ chars)
            # embedded in description text — caught by the generic scanner below
            # "not: X" / "not: Y" type
            (r'(?i)(?:not|note|note|not|bilgi)\s*[:=]\s*(.{4,60})',
             "note"),
            # "Code: XXXX" / "PIN: XXXX"
            (r'(?i)(?:code|pin|kod)\s*[:=]\s*(\S+)',
             "code"),
            # "username: admin / password: X"
            (r'(?i)username\s*[:=]\s*(\S+).*(?:password|pass|pwd|pw)\s*[:=]\s*(\S+)',
             "full_creds"),
            # HTML/XML encoded: "password&gt;X&lt;"
            (r'(?i)(?:password|pass|pwd|pw)\s*[&]?gt;?\s*[:=]?\s*(\S+)',
             "html_encoded"),
            # Slack/Teams style: "creds: user:pass"
            (r'(?i)creds?\s*[:=]\s*(\S+)\s*[:/]\s*(\S+)',
             "creds_kv"),
        ]

        # ── Generic password heuristic: strings with mixed upper/lower/digit/special ──
        def _looks_like_password(s):
            """Check if a string looks like a password (complex enough).
            Requires digits (almost all real passwords have them) plus mixed case or special chars."""
            if len(s) < 5 or len(s) > 48:
                return False
            has_upper = bool(re.search(r'[A-Z]', s))
            has_lower = bool(re.search(r'[a-z]', s))
            has_digit = bool(re.search(r'[0-9]', s))
            has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]', s))
            types = sum([has_upper, has_lower, has_digit, has_special])
            # Must have digits + at least one more type (upper/lower/special)
            return has_digit and types >= 3

        findings = []
        scanned = 0

        for user in self.data["users"]:
            desc = user.get("description", "")
            if not desc:
                continue
            scanned += 1

            for pattern, ptype in patterns:
                for match in re.finditer(pattern, desc):
                    groups = match.groups()
                    if ptype == "full_creds" and len(groups) >= 2:
                        username, password = groups[0], groups[1]
                        findings.append({
                            "user": user["name"],
                            "dn": user.get("dn", ""),
                            "description": desc,
                            "pattern_type": ptype,
                            "found_username": username,
                            "found_credential": password,
                            "match": match.group(0),
                        })
                    elif ptype == "userpass" and len(groups) >= 2:
                        u, p = groups[0], groups[1]
                        # Filter out noise: skip if it looks like a URL, path, or LDAP DN component
                        if u.lower() in ("http", "https", "www", "file", "cn", "ou", "dc"):
                            continue
                        # Allow DOMAIN\Username format (backslash is valid in NetBIOS domain prefix)
                        if "/" in u:
                            continue
                        if len(p) < 3:
                            continue
                        findings.append({
                            "user": user["name"],
                            "dn": user.get("dn", ""),
                            "description": desc,
                            "pattern_type": ptype,
                            "found_username": u,
                            "found_credential": p,
                            "match": match.group(0),
                        })
                    elif ptype == "note":
                        note_text = groups[0].strip()
                        # Check if note content looks like a password
                        if _looks_like_password(note_text):
                            findings.append({
                                "user": user["name"],
                                "dn": user.get("dn", ""),
                                "description": desc,
                                "pattern_type": "note_suspicious",
                                "found_credential": note_text,
                                "match": match.group(0),
                            })
                    elif ptype not in ("full_creds", "userpass", "note"):
                        cred = groups[-1] if groups else match.group(0)
                        if not cred or len(cred) < 2:
                            continue
                        findings.append({
                            "user": user["name"],
                            "dn": user.get("dn", ""),
                            "description": desc,
                            "pattern_type": ptype,
                            "found_credential": cred,
                            "match": match.group(0),
                        })

            # ── Generic scan: split description by common delimiters and check each chunk ──
            chunks = re.split(r'[,;|\s]+', desc)
            for chunk in chunks:
                chunk = chunk.strip().strip('"').strip("'")
                if _looks_like_password(chunk):
                    # Avoid duplicates
                    already = any(f.get("found_credential") == chunk and f.get("pattern_type") == "heuristic"
                                  for f in findings)
                    if not already:
                        findings.append({
                            "user": user["name"],
                            "dn": user.get("dn", ""),
                            "description": desc,
                            "pattern_type": "heuristic",
                            "found_credential": chunk,
                            "match": chunk,
                        })

            # ── Old-style: "Password is X" without explicit separator ──
            simple_matches = re.findall(
                r'(?i)(?:password|parola|şifre|pass|pwd)\s+(?:is\s+|=\s*|:\s*)?(\S{3,32})',
                desc)
            for sm in simple_matches:
                if sm.lower() not in ("is", "the", "not", "for", "and", "set", "can", "has", "was",
                                      "required", "expired", "changed", "never", "unknown", "policy"):
                    already = any(f.get("found_credential") == sm and f.get("pattern_type") == "simple_label"
                                  for f in findings)
                    if not already:
                        findings.append({
                            "user": user["name"],
                            "dn": user.get("dn", ""),
                            "description": desc,
                            "pattern_type": "simple_label",
                            "found_credential": sm,
                            "match": sm,
                        })

        # ── Dedup by (user, credential) ──
        seen = set()
        unique_findings = []
        for f in findings:
            key = (f["user"], f.get("found_credential", ""))
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        self.data["description_passwords"] = unique_findings

        if unique_findings:
            crit = sum(1 for f in unique_findings
                       if f.get("pattern_type") in ("label", "initial", "full_creds", "changed", "creds_kv"))
            high = sum(1 for f in unique_findings
                       if f.get("pattern_type") in ("sentence", "userpass", "account_info", "simple_label"))
            log(f"Description credential scan: {len(unique_findings)} potential passwords found "
                f"({crit} high-confidence, {high} medium-confidence) across {scanned} users with descriptions",
                "CRIT" if crit else ("WARN" if unique_findings else "SUCCESS"))

            # Print top findings
            for f in unique_findings[:10]:
                pattern_label = f.get("pattern_type", "?")
                cred = f.get("found_credential", "")[:40]
                log(f"  [{pattern_label}] {f['user']}: ...{cred}...",
                    "CRIT" if pattern_label in ("label","initial","full_creds") else "DATA")
        else:
            log(f"No credentials found in {scanned} user descriptions", "SUCCESS")

        return unique_findings

    def _enum_tombstoned(self):
        """Tombstone (silinmis ama silinme suresi dolmamis) nesneleri
        LDAP deleted objects container uzerinden toplar."""
        try:
            deleted_dn = "CN=Deleted Objects," + self.conn.base_dn
            escaped_del_dn = _escape_ldap_filter_value(deleted_dn)
            res = self.conn.search(
                f"(&(isDeleted=TRUE)(objectClass=*))",
                ["sAMAccountName", "objectClass", "lastKnownParent", "whenChanged"],
                base=escaped_del_dn)
            tombstoned = []
            for e in res:
                a = e.get("attributes", {})
                oc = a.get("objectClass", [])
                if isinstance(oc, list): oc = oc[-1] if oc else ""
                tombstoned.append({
                    "name": self._attr(e, "sAMAccountName", "(unknown)"),
                    "class": str(oc),
                    "parent": self._attr(e, "lastKnownParent", ""),
                    "changed": str(self._attr(e, "whenChanged", "")),
                })
            self.data["tombstoned_objects"] = tombstoned
            log(f"Tombstoned objects (recoverable): {len(tombstoned)}", "WARN" if tombstoned else "INFO")
        except Exception as ex:
            log(f"Tombstoned objects enum: {ex} (this is normal if no deleted objects or insufficient rights)", "INFO")

    def _enum_groups(self):
        try:
            res = self.conn.search("(objectClass=group)",
                ["sAMAccountName","description","member","groupType",
                 "adminCount","whenCreated","objectSid"])
            for e in res:
                gt = int(self._attr(e,"groupType",0) or 0)
                members = e.get("attributes",{}).get("member",[])
                if not isinstance(members, list): members = [members] if members else []
                self.data["groups"].append({
                    "name": self._attr(e,"sAMAccountName"),
                    "dn": e.get("dn",""),
                    "description": self._attr(e,"description"),
                    "member_count": len(members),
                    "members": members,
                    "admin_count": int(self._attr(e,"adminCount",0) or 0),
                    "security_group": bool(gt & -2147483648),
                    "created": str(self._attr(e,"whenCreated","")),
                    "sid": str(self._attr(e,"objectSid","")),
                })
            priv = sum(1 for g in self.data["groups"] if g["admin_count"])
            log(f"Groups: {len(self.data['groups'])}  Privileged:{priv}", "SUCCESS")
        except Exception as ex:
            log(f"Groups: {ex}", "WARN")

    def _enum_protected_users(self):
        """Protected Users grubunun uyelerini toplar.
        Bu grup uyeleri NTLM, DES, AES olmayan Kerberos ve
        plaintext credential delegation'a karsi korumalidir."""
        try:
            res = self.conn.search(
                "(&(objectClass=group)(sAMAccountName=Protected Users))",
                ["member", "sAMAccountName"])
            members = []
            for e in res:
                raw_members = e.get("attributes", {}).get("member", [])
                if not isinstance(raw_members, list):
                    raw_members = [raw_members] if raw_members else []
                for m in raw_members:
                    name = dn_to_name(m)
                    if name:
                        members.append(name)
            self.data["protected_users_members"] = members
            log(f"Protected Users members: {len(members)}", "INFO" if members else "DATA")
        except Exception as ex:
            log(f"Protected Users enum: {ex}", "WARN")

    def _resolve_nested_groups(self):
        priv = ["Domain Admins","Enterprise Admins","Schema Admins",
               "Backup Operators","Account Operators","Server Operators","Print Operators"]
        grp_by_name = {g["name"]: g for g in self.data["groups"]}
        grp_by_dn   = {g["dn"]: g for g in self.data["groups"]}
        user_by_dn  = {u["dn"]: u for u in self.data["users"]}

        def members_recursive(name, visited=None):
            visited = visited or set()
            if name in visited: return set()
            visited.add(name)
            grp = grp_by_name.get(name)
            if not grp: return set()
            out = set()
            for m_dn in grp.get("members", []):
                if not m_dn: continue
                if m_dn in user_by_dn:
                    out.add(user_by_dn[m_dn]["name"])
                elif m_dn in grp_by_dn:
                    out |= members_recursive(grp_by_dn[m_dn]["name"], visited)
            return out

        for pg in priv:
            m = members_recursive(pg)
            if m: self.data["nested_memberships"][pg] = sorted(m)
        log(f"Nested resolution done for {len(self.data['nested_memberships'])} groups", "SUCCESS")

    def _check_ldap_security(self):
        """LDAP channel binding ve signing zorunlulugunu LdapPolicy uzerinden
        kontrol eder. Degerler:
        0 = hicbiri zorunlu degil (GUVENSIZ)
        1 = signing zorunlu
        2 = channel binding zorunlu
        3 = her ikisi de zorunlu (GUVENLI)"""
        try:
            # LdapPolicy DN: CN=LdapPolicy,CN=Services,CN=Windows NT,CN=Directory Service,...
            ldap_policy_dn = ("CN=LdapPolicy,CN=Services,CN=Windows NT,"
                              "CN=Directory Service,CN=Windows NT,"
                              "CN=Services,CN=Configuration," + self.conn.base_dn)
            escaped_ldap_policy = _escape_ldap_filter_value(ldap_policy_dn)
            res = self.conn.search(f"(distinguishedName={escaped_ldap_policy})",
                                   attrs=["lDAPAdminLimits"])
            if res:
                raw = res[0].get("attributes", {}).get("lDAPAdminLimits")
                ldap_limits = raw[0] if isinstance(raw, list) and raw else raw
                if isinstance(ldap_limits, str):
                    # Parse LdapEnforceChannelBinding ve RequireSigning
                    cb_match = re.search(r'LdapEnforceChannelBinding[=\s]+(\d+)',
                                         ldap_limits, re.IGNORECASE)
                    sign_match = re.search(r'RequireSigning[=\s]+(\d+)',
                                           ldap_limits, re.IGNORECASE)
                    cb_enforced = bool(cb_match and int(cb_match.group(1)) >= 2)
                    sign_enforced = bool(sign_match and int(sign_match.group(1)) >= 1)
                    self.data["ldap_security"] = {
                        "signing_enforced": sign_enforced,
                        "cb_enforced": cb_enforced,
                        "raw": ldap_limits[:500]
                    }
                    log(f"LDAP security: Signing={'ON' if sign_enforced else 'OFF'}, "
                        f"ChannelBinding={'ON' if cb_enforced else 'OFF'}", 
                        "SUCCESS" if (sign_enforced and cb_enforced) else "WARN")
                else:
                    self.data["ldap_security"] = {"signing_enforced": False, "cb_enforced": False}
                    log("LDAP security: LdapPolicy okunamadi — varsayilan olarak korumasiz kabul edildi", "WARN")
            else:
                # LdapPolicy yoksa default: koruma yok
                self.data["ldap_security"] = {"signing_enforced": False, "cb_enforced": False}
                log("LDAP security: LdapPolicy bulunamadi — korumasiz", "WARN")
        except Exception as ex:
            self.data["ldap_security"] = {"signing_enforced": False, "cb_enforced": False}
            log(f"LDAP security check failed: {ex}", "WARN")

    def _enum_computers(self):
        try:
            res = self.conn.search("(objectClass=computer)",
                ["sAMAccountName","operatingSystem","operatingSystemVersion",
                 "lastLogonTimestamp","description","userAccountControl","dNSHostName",
                 "whenCreated","ms-Mcs-AdmPwd","msLAPS-Password","msLAPS-PasswordExpirationTime",
                 "primaryGroupID","objectSid","location","msDS-AllowedToActOnBehalfOfOtherIdentity",
                 "msDS-KeyCredentialLink","msDS-AllowedToDelegateTo","servicePrincipalName"])
            for e in res:
                uac  = int(self._attr(e,"userAccountControl",0) or 0)
                pgid = int(self._attr(e,"primaryGroupID",0) or 0)
                is_dc = pgid in (516, 521)
                laps_legacy = bool(e.get("attributes",{}).get("ms-Mcs-AdmPwd"))
                laps_new = bool(e.get("attributes",{}).get("msLAPS-Password"))
                laps_configured = laps_legacy or laps_new
                # LAPS sifresini kimler okuyabilir? msLAPS-PasswordExpirationTime
                # doluysa LAPS aktiftir ve sifre donusumu calisiyordur
                laps_expiry = e.get("attributes",{}).get("msLAPS-PasswordExpirationTime")
                laps_active = laps_configured and bool(laps_expiry)
                name  = self._attr(e,"sAMAccountName","").rstrip("$")
                ll    = filetime_to_dt(self._attr(e,"lastLogonTimestamp",0))
                shadow = bool(e.get("attributes",{}).get("msDS-KeyCredentialLink"))
                rbcd_raw = e.get("attributes",{}).get("msDS-AllowedToActOnBehalfOfOtherIdentity")
                rbcd = None
                if rbcd_raw and IMPACKET_LDAP:
                    try:
                        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=rbcd_raw)
                        if sd['Dacl']:
                            rbcd_sids = []
                            for ace in sd['Dacl']['Data']:
                                if ace['AceType'] in (0x00, 0x05):
                                    sid = ace['Ace']['Sid'].formatCanonical()
                                    rbcd_sids.append(sid)
                            rbcd = rbcd_sids
                    except Exception:
                        pass
                # Constrained delegation (msDS-AllowedToDelegateTo) — MUST be parsed BEFORE comp dict
                allowed_to_delegate = e.get("attributes",{}).get("msDS-AllowedToDelegateTo",[])
                if not isinstance(allowed_to_delegate, list):
                    allowed_to_delegate = [allowed_to_delegate] if allowed_to_delegate else []
                constrained_targets = []
                for tgt_dn in allowed_to_delegate:
                    tgt_name = dn_to_name(str(tgt_dn))
                    if tgt_name:
                        constrained_targets.append(tgt_name)
                # SPN'ler (Silver Ticket analizi icin)
                comp_spns = e.get("attributes",{}).get("servicePrincipalName",[])
                if not isinstance(comp_spns, list):
                    comp_spns = [comp_spns] if comp_spns else []

                comp  = {
                    "name": name, "dns": self._attr(e,"dNSHostName"),
                    "os": self._attr(e,"operatingSystem"),
                    "os_version": self._attr(e,"operatingSystemVersion"),
                    "dn": e.get("dn",""), "description": self._attr(e,"description"),
                    "location": self._attr(e,"location"),
                    "enabled": not bool(uac & 2),
                    "trusted_for_delegation": bool(uac & 524288),
                    "laps_configured": laps_configured,
                    "laps_legacy": laps_legacy,
                    "laps_new": laps_new,
                    "laps_active": laps_active,
                    "is_dc": is_dc,
                    "last_logon_days": days_since(ll),
                    "created": str(self._attr(e,"whenCreated","")),
                    "sid": str(self._attr(e,"objectSid","")),
                    "sessions": [], "loggedon": [], "local_admins": [],
                    "rdp_open": False, "rdp_users": [], "shares": [],
                    "rbcd": rbcd,
                    "shadow_creds": shadow,
                    "constrained_delegation": len(constrained_targets) > 0,
                    "constrained_targets": constrained_targets,
                    "spns": comp_spns,
                    "winrm_open": False,
                }
                if is_dc: self.data["dc_hosts"].append(name.upper())
                if comp["trusted_for_delegation"] and not is_dc:
                    log(f"Unconstrained delegation: {C.YELLOW}{name}{C.RESET}", "WARN")
                if rbcd:
                    log(f"RBCD configured on {name}: {rbcd}", "WARN")

                if shadow:
                    self.data["shadow_creds"].append({"user": name+"$", "dn": comp["dn"]})
                self.data["computers"].append(comp)
            log(f"Computers: {len(self.data['computers'])}  DCs:{len(self.data['dc_hosts'])}", "SUCCESS")
        except Exception as ex:
            log(f"Computers: {ex}", "WARN")

    def _enum_ous_gpos(self):
        try:
            res = self.conn.search("(objectClass=organizationalUnit)",
                ["name","description","gpLink","whenCreated"])
            for e in res:
                gpl = self._attr(e,"gpLink","")
                self.data["ous"].append({
                    "name": self._attr(e,"name"), "dn": e.get("dn",""),
                    "description": self._attr(e,"description"),
                    "gp_linked": bool(gpl), "gp_link_raw": gpl,
                    "created": str(self._attr(e,"whenCreated","")),
                })
            log(f"OUs: {len(self.data['ous'])}", "SUCCESS")
        except Exception as ex:
            log(f"OUs: {ex}", "WARN")

        try:
            res = self.conn.search("(objectClass=groupPolicyContainer)",
                ["displayName","gPCFileSysPath","versionNumber","whenCreated","flags"])
            gpo_by_dn = {}
            for e in res:
                dn = e.get("dn","")
                m = re.search(r'\{[A-Fa-f0-9\-]+\}', dn)
                guid = m.group(0) if m else dn
                gpo = {"name": self._attr(e,"displayName"), "dn": dn, "guid": guid,
                      "path": self._attr(e,"gPCFileSysPath"),
                      "version": self._attr(e,"versionNumber"),
                      "disabled": int(self._attr(e,"flags",0) or 0),
                      "created": str(self._attr(e,"whenCreated","")), "linked_ous": []}
                gpo_by_dn[dn.upper()] = gpo
                self.data["gpos"].append(gpo)
            log(f"GPOs: {len(self.data['gpos'])}", "SUCCESS")

            for ou in self.data["ous"]:
                raw = ou.get("gp_link_raw","")
                if not raw: continue
                for m in re.finditer(r'LDAP://([^;]+);(\d)', raw, re.IGNORECASE):
                    link_dn, flags = m.group(1), int(m.group(2))
                    gpo = gpo_by_dn.get(link_dn.upper())
                    if gpo:
                        gpo["linked_ous"].append(ou["name"])
                        self.data["gpo_links"].append({
                            "gpo": gpo["name"], "ou": ou["name"], "flags": flags,
                            "enforced": bool(flags & 2), "disabled": bool(flags & 1)})
            log(f"GPO links: {len(self.data['gpo_links'])}", "DATA")
        except Exception as ex:
            log(f"GPOs: {ex}", "WARN")

    def _enum_admins(self):
        priv_groups = ["Domain Admins","Enterprise Admins","Schema Admins","Administrators",
                      "Account Operators","Backup Operators","Print Operators","Server Operators",
                      "Group Policy Creator Owners","DNSAdmins","Remote Management Users",
                      "Remote Desktop Users"]
        da_names = set()
        for grp in priv_groups:
            try:
                res = self.conn.search(f"(&(objectClass=group)(sAMAccountName={grp}))",
                                       ["member","sAMAccountName"])
                for e in res:
                    members = e.get("attributes",{}).get("member",[])
                    if not isinstance(members,list): members=[members] if members else []
                    for m in members:
                        mname = dn_to_name(m)
                        self.data["admins"].append({"group":grp,"member_dn":m,"member_name":mname})
                        if grp in ("Domain Admins","Enterprise Admins"):
                            da_names.add(mname.upper())
                    if members: log(f"{grp}: {len(members)}", "WARN")
            except Exception as ex:
                log(f"_enum_admins {grp}: {ex}", "WARN")
        self.data["da_users"] = sorted(da_names)
        log(f"Domain Admins: {', '.join(da_names) or 'None'}", "SUCCESS")

    def _report_spns(self):
        if self.data["spns"]:
            log(f"Kerberoastable ({len(self.data['spns'])}):", "WARN")
            for s in self.data["spns"]: log(f"  {s['user']}: {s['spns']}", "DATA")

    def _report_asrep(self):
        if self.data["asrep"]:
            log(f"AS-REP Roastable: {', '.join(self.data['asrep'])}", "CRIT")

    def _check_nopac(self):
        """NoPac (CVE-2021-42287 / CVE-2021-42278) — domain functional level
        ve DC OS versiyonu uzerinden potansiyel etkiyi degerlendirir.
        Not: Kesin tespit icin samr name impersonate testi gerekir;
        burada risk gostergesi sunulur."""
        try:
            # Domain functional level (msDS-Behavior-Version)
            res = self.conn.search("(objectClass=domainDNS)",
                ["msDS-Behavior-Version", "name"])
            behavior = 0
            if res:
                behavior = int(self._attr(res[0], "msDS-Behavior-Version", 0) or 0)
            # NoPac yamasi: KB5008380 / KB5008602 sonrasi samr filter
            # Functional level >= 2008 (3) ve yamasiz ise risk var
            # Behavior version: 0=2000, 1=2003, 2=2008, 3=2008R2,
            #                    4=2012, 5=2012R2, 6=2016, 7=2019/2022
            DFL_MAP = {0:"Windows 2000",1:"Windows Server 2003",2:"Windows Server 2008",
                       3:"Windows Server 2008 R2",4:"Windows Server 2012",
                       5:"Windows Server 2012 R2",6:"Windows Server 2016",
                       7:"Windows Server 2019/2022",8:"Windows Server 2025"}
            potentially_vuln = behavior >= 3  # 2008 R2 ve uzeri (2008/behavior=2 NoPac exploit edilemez)
            maq = int(self.data.get("domain", {}).get("machine_account_quota", 10) or 10)
            risky_dcs = [c["name"] for c in self.data.get("computers", [])
                         if c.get("is_dc") and c.get("enabled")]
            self.data["nopac_risk"] = {
                "potentially_vulnerable": potentially_vuln,
                "domain_behavior_version": behavior,
                "dfl_string": DFL_MAP.get(behavior, f"Unknown ({behavior})"),
                "quota": maq,
                "risky_dcs": risky_dcs,
                "note": "Kesin tespit icin: noPac.py -dc-ip <DC> -use-ldap veya samr name impersonate testi onerilir (KB5008380/KB5008602)",
            }
            if potentially_vuln:
                log(f"NoPac: Domain functional level >= 2008 (v{behavior}) — "
                    "yamali degilse risk var", "WARN")
            else:
                log(f"NoPac: Functional level v{behavior} — risk dusuk", "INFO")
        except Exception as ex:
            self.data["nopac_risk"] = {"potentially_vulnerable": False, "error": str(ex)}
            log(f"NoPac check failed: {ex}", "WARN")

    def _enum_trusts(self):
        try:
            res = self.conn.search("(objectClass=trustedDomain)",
                ["name","trustDirection","trustType","trustAttributes","flatName",
                 "securityIdentifier"])
            td = {1:"Inbound",2:"Outbound",3:"Bidirectional"}
            tt = {1:"Windows NT",2:"Active Directory",3:"Kerberos"}
            for e in res:
                d = int(self._attr(e,"trustDirection",0) or 0)
                t = int(self._attr(e,"trustType",0) or 0)
                ta= int(self._attr(e,"trustAttributes",0) or 0)
                # Forest-level trust attribute analysis
                # bit 0x01 (1): TRUST_ATTRIBUTE_NON_TRANSITIVE
                # bit 0x04 (4): TRUST_ATTRIBUTE_CROSS_ORGANIZATION
                # bit 0x08 (8): TRUST_ATTRIBUTE_WITHIN_FOREST + TGT delegation
                # bit 0x20 (32): TRUST_ATTRIBUTE_FOREST_TRANSITIVE
                # bit 0x40 (64): TRUST_ATTRIBUTE_QUARANTINED_DOMAIN (SID filtering ON)
                # bit 0x200 (512): TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION (weak crypto)
                sid_filtering = bool(ta & 0x40)        # QUARANTINED_DOMAIN
                within_forest = bool(ta & 0x08)         # WITHIN_FOREST
                selective_auth = bool(ta & 0x04)        # CROSS_ORGANIZATION
                tgt_delegation = bool(ta & 0x08)        # Same bit as within_forest
                forest_transitive = bool(ta & 0x20)     # FOREST_TRANSITIVE
                uses_rc4 = bool(ta & 0x200)             # Weak crypto
                trust = {
                    "name": self._attr(e,"name"),
                    "flat_name": self._attr(e,"flatName"),
                    "direction": td.get(d,f"Unknown({d})"),
                    "type": tt.get(t,f"Unknown({t})"),
                    "transitive": not bool(ta & 0x1),
                    "forest_trust": bool(ta & 0x8),
                    "sid_filtering": sid_filtering,
                    "selective_auth": selective_auth,
                    "within_forest": within_forest,
                    "tgt_delegation": tgt_delegation,
                    "forest_transitive": forest_transitive,
                    "uses_rc4": uses_rc4,
                    "trust_sid": str(self._attr(e,"securityIdentifier","")),
                    "cross_forest_groups": [],
                }
                self.data["trusts"].append(trust)
                log(f"Trust: {trust['name']} [{trust['direction']}] "
                    f"SIDFilter={'ON' if sid_filtering else 'OFF'} "
                    f"Forest={'Yes' if within_forest else 'No'} "
                    f"RC4={'Weak!' if uses_rc4 else 'OK'}", "WARN")
                if not sid_filtering:
                    log(f"  └─ SID filtering OFF → cross-forest privilege escalation possible", "CRIT")
            if not self.data["trusts"]: log("No domain trusts", "INFO")

            # Enumerate Foreign Security Principals (cross-forest group memberships)
            try:
                fsp_res = self.conn.search("(objectClass=foreignSecurityPrincipal)",
                    ["name","memberOf","sAMAccountName"])
                trust_by_sid = {t.get("trust_sid",""): t for t in self.data["trusts"]}
                for fsp in fsp_res:
                    fsp_sid = self._attr(fsp, "sAMAccountName", "")
                    fsp_dn = fsp.get("dn","")
                    # Match FSP to trust
                    for trust_sid, trust in trust_by_sid.items():
                        if trust_sid and fsp_sid.startswith(trust_sid[:20]):
                            trust["cross_forest_groups"].append({
                                "sid": fsp_sid, "dn": fsp_dn,
                            })
                for t in self.data["trusts"]:
                    if t.get("cross_forest_groups"):
                        log(f"  FSP: {t['name']} → {len(t['cross_forest_groups'])} cross-forest groups",
                            "WARN")
            except Exception:
                pass
        except Exception as ex:
            log(f"Trusts: {ex}", "WARN")

    def _enum_dacls(self):
        if not (LDAP3_AVAILABLE and IMPACKET_LDAP):
            log("DACL analysis requires ldap3 + impacket — skipped", "WARN")
            return
        try:
            hv = []
            for u in self.data["users"]:
                if u.get("admin_count") and u.get("dn"):
                    hv.append({"dn":u["dn"],"name":u["name"],"type":"user"})
            for g in self.data["groups"]:
                if g.get("admin_count") and g.get("dn"):
                    hv.append({"dn":g["dn"],"name":g["name"],"type":"group"})
            if self.data["domain"].get("dn"):
                hv.append({"dn":self.data["domain"]["dn"],
                          "name":self.data["domain"].get("name","domain"),"type":"domain"})
            log(f"Analyzing DACLs on {len(hv)} high-value objects...", "INFO")
            edges = DACLAnalyzer(self.conn).analyze_objects(hv)
            self.data["acl_edges"] = edges
            log(f"Dangerous ACL edges: {len(edges)}", "CRIT" if edges else "SUCCESS")
            for e in edges[:5]:
                log(f"  {e['severity']}: {e['source']} -> {e['right']} -> {e['target']}", "DATA")
        except Exception as ex:
            log(f"DACL analysis: {ex}", "WARN")

    def _enum_adcs(self):
        """Genisletilmis ADCS enumerasyonu: ESC1-ESC8 + ESC11.
        Enrollment Services, Certificate Templates, CA ACL, Web Enrollment."""
        if not LDAP3_AVAILABLE:
            return
        try:
            # === ESC8: Web Enrollment endpoints ===
            ca_base = "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration," + self.conn.base_dn
            res = self.conn.search("(objectClass=pKIEnrollmentService)",
                ["cn","dNSHostName","pKIEnrollmentService","pKICertificateNameFlag","flags"],
                base=ca_base)
            ca_services = []
            for e in res:
                ca_name = self._attr(e, "cn")
                ca_dns  = self._attr(e, "dNSHostName")
                ca_uri  = self._attr(e, "pKIEnrollmentService", "")
                ca_flags = int(self._attr(e, "flags", 0) or 0)
                has_web = "http" in str(ca_uri).lower() if ca_uri else False
                ca_services.append({
                    "name": ca_name, "dns": ca_dns, "uri": ca_uri,
                    "web_enrollment": has_web,
                    "flags": ca_flags
                })
                # ESC8: HTTP endpoints -> NTLM relay risk
                if has_web:
                    self.data["adcs_esc"].append({
                        "id": "8",
                        "template": f"CA:{ca_name}",
                        "severity": "HIGH",
                        "description": f"ESC8: Web enrollment at {ca_uri}. NTLM relay to CA -> request certificate as DA.",
                        "steps": [
                            f"ntlmrelayx.py -t {ca_uri}/certsrv/ -smb2support --adcs --template DomainController",
                            "Coerce DC/LocalSystem auth to attacker relay server (PrinterBug/PetitPotam)",
                            "Obtain DC certificate -> DCSync -> krbtgt hash"
                        ]
                    })
                # ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag (0x40000)
                if ca_flags & 0x40000:
                    self.data["adcs_esc"].append({
                        "id": "6",
                        "template": f"CA:{ca_name}",
                        "severity": "CRITICAL",
                        "description": "ESC6: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag. ANY template with Client Auth EKU can specify SAN as DA.",
                        "steps": [
                            f"certipy req -ca '{ca_name}' -template User -upn administrator@domain -dns <DC>",
                            "PKINIT auth with obtained certificate -> DA TGT"
                        ]
                    })
            if ca_services:
                log(f"AD CS Enrollment Services: {len(ca_services)}", "INFO")

            # === ESC7: CA Manager/Officer ACL ===
            for ca in ca_services:
                ca_cn = ca.get("name", "")
                if not ca_cn: continue
                ca_dn = f"CN={ca_cn},{ca_base}"
                try:
                    sd_control = security_descriptor_control(sdflags=0x04)
                    esc_dn = _escape_ldap_filter_value(ca_dn)
                    res_ca = self.conn.search(f"(distinguishedName={esc_dn})",
                        ["nTSecurityDescriptor"], controls=sd_control)
                    if res_ca and IMPACKET_LDAP:
                        raw = res_ca[0].get("attributes",{}).get("nTSecurityDescriptor")
                        if isinstance(raw, list): raw = raw[0] if raw else None
                        if isinstance(raw, str):
                            try: raw = base64.b64decode(raw)
                            except Exception: raw = None
                        if raw:
                            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
                            if sd['Dacl']:
                                # Well-known ADCS CA extended right GUIDs
                                CA_MANAGE_CA_GUID = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
                                CA_MANAGE_CERTIFICATES_GUID = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

                                for ace in sd['Dacl']['Data']:
                                    if ace['AceType'] in (0x00, 0x05):
                                        sid = ace['Ace']['Sid'].formatCanonical()
                                        mask = int(ace['Ace']['Mask']['Mask'])
                                        # Check for GenericAll/GenericWrite/WriteDACL/WriteOwner on CA object
                                        has_dangerous_generic = (
                                            (mask & 0x000F01FF) == 0x000F01FF or  # GenericAll
                                            (mask & 0x00020028) == 0x00020028 or  # GenericWrite
                                            (mask & 0x00040000) == 0x00040000 or  # WriteDACL
                                            (mask & 0x00080000) == 0x00080000     # WriteOwner
                                        )
                                        # Check for ManageCA / ManageCertificates extended rights via GUID
                                        has_ca_right = False
                                        right_name = ""
                                        if ace['AceType'] == 0x05:  # OBJECT_ACE — check GUID
                                            guid = _guid_from_ace(ace['Ace'])
                                            if guid and guid.lower() == CA_MANAGE_CA_GUID.lower():
                                                has_ca_right = True
                                                right_name = "ManageCA"
                                            elif guid and guid.lower() == CA_MANAGE_CERTIFICATES_GUID.lower():
                                                has_ca_right = True
                                                right_name = "ManageCertificates"

                                        if has_dangerous_generic or has_ca_right:
                                            principal = self.conn.resolve_sid(sid)
                                            allowlist = {"DOMAIN ADMINS","ENTERPRISE ADMINS","SYSTEM","ADMINISTRATORS",
                                                         "CREATOR OWNER"}
                                            if principal.upper() not in allowlist and not principal.endswith("$"):
                                                right_label = right_name if has_ca_right else "GenericWrite/All"
                                                self.data["adcs_esc"].append({
                                                    "id": "7",
                                                    "template": f"CA:{ca_cn}",
                                                    "severity": "CRITICAL",
                                                    "description": f"ESC7: {principal} has {right_label} on CA {ca_cn}. Can manage CA and enable SAN for all templates.",
                                                    "steps": [
                                                        f"certipy ca -ca '{ca_cn}' -enable-template 'DomainController'",
                                                        "Or add SAN flag: certipy ca -ca <CA> -editflag EDITF_ATTRIBUTESUBJECTALTNAME2",
                                                        "Request DC certificate -> DCSync"
                                                    ]
                                                })
                except Exception:
                    pass

            # === Certificate Templates (ESC1, ESC2, ESC3, ESC4, ESC11) ===
            config_nc = ("CN=Certificate Templates,CN=Public Key Services,"
                         "CN=Services,CN=Configuration," + self.conn.base_dn)
            res = self.conn.search("(objectClass=pKICertificateTemplate)",
                ["cn","msPKI-Certificate-Name-Flag","msPKI-Enrollment-Flag",
                 "pKIExtendedKeyUsage","msPKI-Cert-Template-OID","msPKI-Minimal-Key-Size",
                 "msPKI-Certificate-Policy","msPKI-RA-Signature","msPKI-Enrollment-Servers",
                 "msPKI-RA-Application-Policies","nTSecurityDescriptor"],
                base=config_nc)
            for e in res:
                cn = self._attr(e,"cn")
                name_flag = int(self._attr(e,"msPKI-Certificate-Name-Flag",0) or 0)
                eku = self._attr(e,"pKIExtendedKeyUsage","")
                enroll_flag = int(self._attr(e,"msPKI-Enrollment-Flag",0) or 0)
                key_size = int(self._attr(e,"msPKI-Minimal-Key-Size",0) or 0)
                ra_sig = int(self._attr(e,"msPKI-RA-Signature",0) or 0)

                # === ESC1: ENROLLEE_SUPPLIES_SUBJECT + Client Auth ===
                if name_flag & 0x1:
                    if "Client Authentication" in eku or "1.3.6.1.5.5.7.3.2" in eku:
                        self.data["adcs_esc"].append({
                            "id": "1","template": cn,"severity": "CRITICAL",
                            "description": f"ESC1: {cn} allows enrollee-supplied subject + Client Auth EKU.",
                            "steps": [f"certipy req -template '{cn}' -upn administrator@domain -ca <CA>",
                                      "certipy auth -pfx admin.pfx -> DA TGT"]
                        })
                    else:
                        self.data["adcs_esc"].append({
                            "id": "2","template": cn,"severity": "HIGH",
                            "description": f"ESC2: {cn} allows enrollee-supplied subject (no Client Auth).",
                            "steps": [f"certipy req -template '{cn}' -upn administrator@domain -ca <CA>",
                                      "Check if EKU can be used for auth"]
                        })
                # === ESC3: Enrollment Agent EKU ===
                if "Enrollment Agent" in eku or "1.3.6.1.4.1.311.20.2.1" in eku:
                    self.data["adcs_esc"].append({
                        "id": "3","template": cn,"severity": "HIGH",
                        "description": f"ESC3: {cn} is enrollment agent -> request certs as other users.",
                        "steps": ["certipy req -template '{cn}' -ca <CA>",
                                  "Use agent cert: certipy req -on-behalf-of administrator -template User"]
                    })
                # === ESC4: Weak template ACL (GenericWrite/GenericAll) ===
                if IMPACKET_LDAP:
                    raw_sd = e.get("attributes",{}).get("nTSecurityDescriptor")
                    if raw_sd:
                        try:
                            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
                            if sd['Dacl']:
                                for ace in sd['Dacl']['Data']:
                                    if ace['AceType'] in (0x00, 0x05):
                                        sid = ace['Ace']['Sid'].formatCanonical()
                                        mask = int(ace['Ace']['Mask']['Mask'])
                                        has_generic_write = (mask & 0x00020028) == 0x00020028
                                        has_generic_all  = (mask & 0x000F01FF) == 0x000F01FF
                                        if has_generic_write or has_generic_all:
                                            principal = self.conn.resolve_sid(sid)
                                            allowlist = {"DOMAIN ADMINS","ENTERPRISE ADMINS","SYSTEM",
                                                         "CREATOR OWNER","ADMINISTRATORS","SCHEMA ADMINS"}
                                            if principal.upper() not in allowlist and not principal.endswith("$"):
                                                self.data["adcs_esc"].append({
                                                    "id": "4","template": cn,"severity": "CRITICAL",
                                                    "description": f"ESC4: {principal} has write on {cn} template. Can enable ESC1 via SAN.",
                                                    "steps": [f"certipy template -template '{cn}' -add-supply-subject",
                                                              f"certipy req -template '{cn}' -upn administrator@domain"]
                                                })
                        except Exception:
                            pass
                # === ESC11: Weak key size / IFS mapping ===
                if 0 < key_size < 1024:
                    self.data["adcs_esc"].append({
                        "id": "11","template": cn,"severity": "MEDIUM",
                        "description": f"ESC11: {cn} uses weak key size ({key_size} bits). Factorization possible.",
                        "steps": [f"Factor {key_size}-bit key (cado-nfs/yafu)",
                                  "Impersonate key owner with factored private key"]
                    })
                # === ESC11 variant: RA required without signature ===
                if enroll_flag & 0x200 and ra_sig == 0:  # CT_FLAG_REQUIRE_ENROLLMENT_AGENT
                    self.data["adcs_esc"].append({
                        "id": "11","template": cn,"severity": "HIGH",
                        "description": f"ESC11b: {cn} requires enrollment agent but no RA signature check. Agent cert bypass possible.",
                        "steps": ["Obtain enrollment agent certificate (any template with agent EKU)",
                                  "Use agent cert without signature validation"]
                    })

                # === ESC9: No Security Extension (CT_FLAG_NO_SECURITY_EXTENSION) ===
                enroll_flag = int(e.get("attributes", {}).get("msPKI-Enrollment-Flag", 0) or 0)
                if enroll_flag & 0x80000:  # CT_FLAG_NO_SECURITY_EXTENSION
                    self.data["adcs_esc"].append({
                        "id": "9","template": cn,"severity": "HIGH",
                        "description": f"ESC9: {cn} has CT_FLAG_NO_SECURITY_EXTENSION. "
                                       "Certificate mapping bypass possible — any user can impersonate via certificate.",
                        "steps": ["certipy req -template TEMPLATE -ca CA -upn target@domain",
                                  "Use StrongCertificateBindingEnforcement=0 bypass to impersonate victim"]
                    })

                # === ESC12: CA with shell access (If CA admin has local admin) ===
                # The CA object security descriptor was already parsed for ESC7
                # ESC12 = shell access on CA through admin/manager rights escalation
                # This is detected implicitly via ESC7 (ManageCA → shell)

                # === ESC13: OID Group Link (
                oid_links = e.get("attributes", {}).get("msDS-OIDToGroupLink", [])
                if oid_links:
                    if not isinstance(oid_links, list):
                        oid_links = [oid_links] if oid_links else []
                    for link in oid_links:
                        self.data["adcs_esc"].append({
                            "id": "13","template": cn,"severity": "HIGH",
                            "description": f"ESC13: {cn} has OID-to-group link ({str(link)[:80]}). "
                                           "Issued certificate grants group membership via OID mapping.",
                            "steps": [f"Enroll {cn} cert → gain group membership via OID {str(link)[:60]}",
                                      "If group has DA: full domain compromise"]
                        })

            # === ESC10: Domain-wide StrongCertificateBindingEnforcement check ===
            # If ANY template has ESC9 (NO_SECURITY_EXTENSION), also check DC registry
            if any(e.get("id") == "9" for e in self.data["adcs_esc"]):
                self.data["adcs_esc"].append({
                    "id": "10","template": "DOMAIN-WIDE","severity": "MEDIUM",
                    "description": "ESC10: One or more templates have NO_SECURITY_EXTENSION. "
                                   "If StrongCertificateBindingEnforcement=0/1 on DCs, certificate mapping is weak. "
                                   "Check: reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\\StrongCertificateBindingEnforcement on each DC.",
                    "steps": ["On each DC: reg query HKLM\\SYSTEM\\CCS\\Services\\Kdc",
                              "If StrongCertificateBindingEnforcement is 0 or 1: any user cert can impersonate"]
                })

            if self.data["adcs_esc"]:
                escs = {}
                for e in self.data["adcs_esc"]:
                    eid = e.get("id","?")
                    escs[eid] = escs.get(eid,0)+1
                log(f"ADCS ESC: {dict(sorted(escs.items()))}", "CRIT" if any(k in escs for k in ['1','4','6','7','8']) else "WARN")
            else:
                log("ADCS: No ESC findings (or CA not deployed)", "INFO")
        except Exception as ex:
            import traceback
            log(f"ADCS enum error: {ex}", "WARN")


    # ── Yeni gelismis metodlar ──
    def _enum_adfs(self):
        """AD FS enumerasyonu: Configuration container, token-signing certificate,
        DKM key, service endpoint'leri. Golden SAML riski degerlendirmesi."""
        try:
            adfs_dn = "CN=ADFS,CN=Microsoft,CN=Program Data," + self.conn.base_dn
            escaped_adfs = _escape_ldap_filter_value(adfs_dn)
            res = self.conn.search("(objectClass=*)",
                ["cn","objectClass","description","whenCreated"], base=escaped_adfs)
            adfs_objects = [{"name":self._attr(e,"cn"),
                             "class":str(self._attr(e,"objectClass","")),
                             "created":str(self._attr(e,"whenCreated",""))} for e in res]
            scp_dn = "CN=System," + self.conn.base_dn
            res_scp = self.conn.search("(&(objectClass=serviceConnectionPoint)(keywords=ADFS))",
                ["cn","serviceDNSName","serviceBindingInformation","keywords"], base=scp_dn)
            adfs_endpoints = [{"name":self._attr(e,"cn"),
                               "dns":self._attr(e,"serviceDNSName"),
                               "binding":str(self._attr(e,"serviceBindingInformation",""))[:200]} for e in res_scp]
            self.data["adfs"] = {
                "configured": bool(adfs_objects or adfs_endpoints),
                "configuration_objects": adfs_objects,
                "endpoints": adfs_endpoints,
                "golden_saml_risk": bool(adfs_objects),
                "note": "ADFS varsa token-signing cert + DKM key -> Golden SAML ile kalici federasyon erisimi."
            }
            log(f"ADFS: {'Found' if adfs_objects else 'Not found'} (objs={len(adfs_objects)} ep={len(adfs_endpoints)})",
                "WARN" if adfs_objects else "INFO")
        except Exception as ex:
            self.data["adfs"] = {"configured":False, "error":str(ex)}
            log(f"ADFS enum: {ex} (domainde ADFS yoksa normal)", "INFO")

    def _enum_laps_readers(self):
        """LAPS sifrelerini kimlerin okuyabildigini DACL uzerinden tespit eder."""
        laps_readers = []
        if not IMPACKET_LDAP:
            log("LAPS reader enum: impacket ldap gerekli - atlandi", "WARN")
            return
        sd_control = security_descriptor_control(sdflags=0x04)
        for c in self.data.get("computers", []):
            if not c.get("laps_configured") or not c.get("dn"): continue
            try:
                escaped_dn = _escape_ldap_filter_value(c["dn"])
                res = self.conn.search(f"(distinguishedName={escaped_dn})",
                                       attrs=["nTSecurityDescriptor"], controls=sd_control)
                if not res: continue
                raw = res[0].get("attributes",{}).get("nTSecurityDescriptor")
                if isinstance(raw, list): raw = raw[0] if raw else None
                if isinstance(raw, str):
                    try: raw = base64.b64decode(raw)
                    except Exception: raw = None
                if not raw: continue
                sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
                if not sd['Dacl']: continue
                for ace in sd['Dacl']['Data']:
                    if ace['AceType'] not in (0x00, 0x05): continue
                    sid = ace['Ace']['Sid'].formatCanonical()
                    mask = int(ace['Ace']['Mask']['Mask'])
                    has_read = (mask & 0x10) or (mask & 0x80000000) or (mask & 0x100)
                    if not has_read: continue
                    principal = self.conn.resolve_sid(sid)
                    if (principal and not principal.endswith("$") and
                            principal.upper() not in ("SYSTEM","DOMAIN ADMINS","ENTERPRISE ADMINS","ADMINISTRATORS")):
                        laps_readers.append({"computer":c["name"],"reader":principal,"sid":sid,
                                             "laps_type":"legacy" if c.get("laps_legacy") else "new"})
            except Exception: pass
        seen = set(); uniq = []
        for r in laps_readers:
            k = (r["computer"],r["reader"])
            if k not in seen: seen.add(k); uniq.append(r)
        self.data["laps_readers"] = uniq
        log(f"LAPS readers: {len(uniq)} (non-admin with read access)", "CRIT" if uniq else "INFO")

    def _enum_schema_enterprise_admins(self):
        """Schema Admins + Enterprise Admins detay analizi. krbtgt sifre yasi."""
        result = {"schema_admins":[],"enterprise_admins":[],"krbtgt_info":{}}
        try:
            config_bn = "CN=Configuration," + self.conn.base_dn
            sa_dn = f"CN=Schema Admins,CN=Users,{config_bn}"
            escaped = _escape_ldap_filter_value(sa_dn)
            res = self.conn.search(f"(distinguishedName={escaped})", ["member","sAMAccountName"])
            if res:
                members = res[0].get("attributes",{}).get("member",[])
                if not isinstance(members,list): members=[members] if members else []
                result["schema_admins"] = [dn_to_name(m) for m in members if m]
        except Exception: pass
        try:
            ea_dn = f"CN=Enterprise Admins,CN=Users,{self.conn.base_dn}"
            escaped = _escape_ldap_filter_value(ea_dn)
            res = self.conn.search(f"(distinguishedName={escaped})", ["member","sAMAccountName"])
            if res:
                members = res[0].get("attributes",{}).get("member",[])
                if not isinstance(members,list): members=[members] if members else []
                result["enterprise_admins"] = [dn_to_name(m) for m in members if m]
        except Exception: pass
        try:
            res = self.conn.search("(&(objectClass=user)(sAMAccountName=krbtgt))",
                                   ["pwdLastSet","whenCreated"])
            if res:
                ps = filetime_to_dt(self._attr(res[0],"pwdLastSet",0))
                ps_days = days_since(ps) if ps else None
                result["krbtgt_info"] = {"pwd_last_set":str(ps) if ps else None,
                    "pwd_age_days":ps_days,
                    "rotation_needed":ps_days is None or ps_days>180,
                    "golden_ticket_survival":"Kalici" if (ps_days and ps_days>365) else "Kisa vadeli risk"}
        except Exception: pass
        self.data["schema_enterprise_admins"] = result
        log(f"SchemaAdmins:{len(result['schema_admins'])} EA:{len(result['enterprise_admins'])} "
            f"krbtgt_age:{result.get('krbtgt_info',{}).get('pwd_age_days','?')}d", "WARN")

    def _map_service_accounts(self):
        """SPN sahibi hesaplarin hangi bilgisayarlarda oturum actigini haritalar.
        Kerberoast kirilirsa lateral movement yolunu gosterir."""
        svc_map = []
        spn_users = {s["user"].upper() for s in self.data.get("spns",[])}
        for u in self.data.get("users",[]):
            if u.get("spns") or u["name"].upper() in spn_users:
                sessions_on = []
                for s in self.data.get("sessions",[])+self.data.get("loggedon",[]):
                    if s.get("user","").upper() == u["name"].upper():
                        h = s.get("host_name") or s.get("host","")
                        sessions_on.append(h.split(".")[0].upper())
                is_da = u["name"].upper() in {a["member_name"].upper() for a in self.data.get("admins",[])
                                               if a.get("group") in ("Domain Admins","Enterprise Admins")}
                svc_map.append({"user":u["name"],"spns":u.get("spns",[]),"is_da":is_da,
                    "password_never_expires":u.get("password_never_expires",False),
                    "pwd_last_set_days":u.get("pwd_last_set_days"),
                    "sessions_on":list(set(sessions_on)),
                    "admin_count":u.get("admin_count",0)})
        self.data["service_account_map"] = svc_map
        da_svc = [s for s in svc_map if s["is_da"]]
        sessioned = [s for s in svc_map if s["sessions_on"]]
        log(f"Service accounts: {len(svc_map)} (DA:{len(da_svc)} w/sessions:{len(sessioned)})",
            "WARN" if da_svc else "INFO")

    def _check_coercion_targets(self):
        """PrinterBug (MS-RPRN) ve PetitPotam (MS-EFSRPC) coercion hedefleri.
        DFSCoerce ve ShadowCoerce da not olarak eklenir."""
        printerbug = list(self.data.get("vuln_scan", {}).get("spooler", []))
        petitpotam = [c["name"] for c in self.data.get("computers", [])
                      if c.get("is_dc") and c.get("enabled")]
        self.data["printerbug_hosts"] = printerbug
        self.data["petitpotam_hosts"] = petitpotam
        if printerbug:
            log(f"PrinterBug coercible: {len(printerbug)} (Spooler active hosts)", "WARN")
        if petitpotam:
            log(f"PetitPotam targets: {len(petitpotam)} DC(s) — EFSRPC erisimi manuel dogrulanmalidir (yamali DC'lerde kapali olabilir)", "INFO")
        log("DFSCoerce/ShadowCoerce: Manual test required (MS-DFSNM / MS-FSRVP RPC interfaces)", "INFO")

    def _check_ntlm_relay_risk(self):
        """SMB signing kapali DC'ler NTLM relay riski altindadir.
        NOT: Bu NTLMv1 kabuluyle AYNI SEY DEGILDIR.
        NTLMv1, LmCompatibilityLevel registry degeri ile kontrol edilir (manuel kontrol gerekir)."""
        relay_risk = []
        for c in self.data.get("computers", []):
            if not c.get("is_dc") or not c.get("enabled"): continue
            if c["name"] in self.data.get("vuln_scan", {}).get("signing", []):
                relay_risk.append(c["name"])
        self.data["ntlm_relay_risk_hosts"] = relay_risk
        if relay_risk:
            log(f"NTLM Relay riski (SMB signing off on DCs): {len(relay_risk)} host(s) — {', '.join(relay_risk)}", "WARN")
        else:
            log("NTLM Relay: Tum DC'lerde SMB signing acik veya kontrol edilemedi", "INFO")
        # Ayrica NTLMv1 icin uyari: LmCompatibilityLevel manuel kontrol edilmelidir
        log("NTLMv1 tespiti icin LmCompatibilityLevel manuel kontrol edilmelidir (reg query HKLM\\System\\CCS\\Control\\Lsa\\LmCompatibilityLevel)", "INFO")

    def _build_delegation_matrix(self):
        """Tum delegasyon tiplerini matriste toplar: unconstrained, constrained, RBCD, shadow creds."""
        matrix = []
        for c in self.data.get("computers",[]):
            entry = {"name":c["name"],"is_dc":c.get("is_dc",False),
                     "unconstrained":c.get("trusted_for_delegation",False),
                     "constrained":c.get("constrained_delegation",False),
                     "constrained_targets":c.get("constrained_targets",[]),
                     "rbcd":bool(c.get("rbcd")),
                     "shadow_creds":c.get("shadow_creds",False)}
            if entry["unconstrained"] or entry["constrained"] or entry["rbcd"] or entry["shadow_creds"]:
                matrix.append(entry)
        for u in self.data.get("users",[]):
            if u.get("trusted_for_delegation") and u.get("enabled"):
                matrix.append({"name":u["name"],"is_dc":False,"unconstrained":True,
                               "constrained":False,"constrained_targets":[],
                               "rbcd":False,"shadow_creds":bool(u.get("shadow_creds"))})
        self.data["delegation_matrix"] = matrix
        log(f"Delegation matrix: {len(matrix)} entries", "WARN" if matrix else "INFO")


    def _enum_shadow_creds(self):
        """msDS-KeyCredentialLink (Shadow Credentials) tam kapsam analizi.
        Kullanici ve bilgisayar enumeration sirasinda toplanir; burada
        loglanir ve PKINIT zincirine isaret edilir."""
        sc = self.data.get("shadow_creds", [])
        # Tam kapsam: her shadow credential icin risk degerlendirmesi
        enriched = []
        for cred in sc:
            user = cred.get("user","")
            dn = cred.get("dn","")
            is_da = user.upper() in {a["member_name"].upper() for a in self.data.get("admins",[])
                                      if a.get("group") in ("Domain Admins","Enterprise Admins")}
            # Shadow Credentials = PKINIT ile TGT alabilme
            enriched.append({
                "user": user, "dn": dn, "is_da": is_da,
                "severity": "CRITICAL" if is_da else "HIGH",
                "attack": "Wh4tSh0t / PKINIT / certipy shadow auto",
                "remediation": f"Set-ADObject -Identity '{dn}' -Clear msDS-KeyCredentialLink",
                "chain_to_da": is_da,
            })
        self.data["shadow_creds"] = enriched
        log(f"Shadow Credentials: {len(enriched)} (DA:{sum(1 for e in enriched if e['is_da'])})",
            "CRIT" if any(e["is_da"] for e in enriched) else "WARN" if enriched else "INFO")

    def _enum_dcsync_rights(self):
        """DCSync hakki olan principal'lari domain DACL'inden tespit eder.
        DS-Replication-Get-Changes / Get-Changes-All extended right'lari
        domain nesnesi uzerinde aranir."""
        domain_dn = self.data["domain"].get("dn")
        if not domain_dn: return
        sd_control = security_descriptor_control(sdflags=0x04)
        escaped_domain_dn = _escape_ldap_filter_value(domain_dn)
        res = self.conn.search(f"(distinguishedName={escaped_domain_dn})",
                               attrs=["nTSecurityDescriptor"], controls=sd_control)
        if not res: return
        raw = res[0].get("attributes", {}).get("nTSecurityDescriptor")
        if isinstance(raw, list): raw = raw[0] if raw else None
        if isinstance(raw, str):
            try: raw = base64.b64decode(raw)
            except Exception: raw = None
        if raw and IMPACKET_LDAP:
            try:
                sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
                if sd['Dacl']:
                    for ace in sd['Dacl']['Data']:
                        if ace['AceType'] in (0x00, 0x05):
                            sid = ace['Ace']['Sid'].formatCanonical()
                            mask = int(ace['Ace']['Mask']['Mask'])
                            if ace['AceType'] == 0x05:  # OBJECT_ACE
                                guid = _guid_from_ace(ace['Ace'])
                                if guid and guid.lower() == "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2":
                                    principal = self.conn.resolve_sid(sid)
                                    self.data["dcsync_rights"].append({"user":principal,"sid":sid})
                                if guid and guid.lower() == "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2":
                                    principal = self.conn.resolve_sid(sid)
                                    self.data["dcsync_rights"].append({"user":principal,"sid":sid,"partial":True})
            except Exception as ex:
                log(f"DCSync SD parse: {ex}", "WARN")
        log(f"DCSync Rights: {len(self.data['dcsync_rights'])}",
            "CRIT" if self.data["dcsync_rights"] else "INFO")

    def _enum_fgpp(self):
        """Fine-Grained Password Policy enumerasyonu."""
        res = self.conn.search("(objectClass=msDS-PasswordSettings)",
            ["cn","msDS-PasswordSettingsPrecedence","msDS-PasswordReversibleEncryptionEnabled",
             "msDS-PasswordHistoryLength","msDS-PasswordComplexityEnabled",
             "msDS-MinimumPasswordLength","msDS-LockoutThreshold",
             "msDS-LockoutObservationWindow","msDS-LockoutDuration","msDS-AppliesTo"])
        for e in res:
            applies_to = self._attr(e, "msDS-AppliesTo", [])
            if not isinstance(applies_to, list): applies_to = [applies_to]
            lockout_thr = self._attr(e, "msDS-LockoutThreshold", 0)
            pwd_age_raw = self._attr(e, "msDS-PasswordAge", None)
            self.data["fgpp"].append({
                "name": self._attr(e, "cn"),
                "precedence": int(self._attr(e, "msDS-PasswordSettingsPrecedence", 0) or 0),
                "min_len": int(self._attr(e, "msDS-MinimumPasswordLength", 0) or 0),
                "complexity": bool(self._attr(e, "msDS-PasswordComplexityEnabled", False)),
                "lockout_threshold": int(lockout_thr or 0),
                "pwd_age_days": int(pwd_age_raw or 0)//-864000000000 if pwd_age_raw else None,
                "applies_to": [dn_to_name(dn) for dn in applies_to]
            })
        log(f"FGPP policies: {len(self.data['fgpp'])}", "WARN" if self.data["fgpp"] else "INFO")

    def _enum_gpo_write_perms(self):
        """GPO'lar uzerinde yazma yetkisi olan non-admin principal'lari tespit eder."""
        if not IMPACKET_LDAP: return
        sd_control = security_descriptor_control(sdflags=0x04)
        for gpo in self.data.get("gpos", []):
            dn = gpo.get("dn")
            if not dn: continue
            try:
                escaped_gpo_dn = _escape_ldap_filter_value(dn)
                res = self.conn.search(f"(distinguishedName={escaped_gpo_dn})",
                                       attrs=["nTSecurityDescriptor"], controls=sd_control)
                if not res: continue
                raw = res[0].get("attributes",{}).get("nTSecurityDescriptor")
                if isinstance(raw, list): raw = raw[0] if raw else None
                if isinstance(raw, str):
                    try: raw = base64.b64decode(raw)
                    except Exception: raw = None
                if not raw: continue
                sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
                if sd['Dacl']:
                    for ace in sd['Dacl']['Data']:
                        if ace['AceType'] in (0x00, 0x05):
                            sid = ace['Ace']['Sid'].formatCanonical()
                            if sid in ("S-1-5-18","S-1-5-32-544"): continue
                            mask = int(ace['Ace']['Mask']['Mask'])
                            is_gen_all  = (mask & 0x000F01FF) == 0x000F01FF
                            is_gen_write = (mask & 0x00020028) == 0x00020028
                            is_write_dacl  = (mask & 0x00040000) == 0x00040000
                            is_write_owner = (mask & 0x00080000) == 0x00080000
                            if is_gen_all or is_gen_write or is_write_dacl or is_write_owner:
                                principal = self.conn.resolve_sid(sid)
                                _GPO_ALLOWLIST = {
                                    "DOMAIN ADMINS","ENTERPRISE ADMINS","SCHEMA ADMINS",
                                    "ADMINISTRATORS","ADMINISTRATOR","SYSTEM",
                                    "CREATOR OWNER","GROUP POLICY CREATOR OWNERS",
                                    "DOMAIN CONTROLLERS","ENTERPRISE DOMAIN CONTROLLERS",
                                }
                                if (principal and not principal.endswith("$") and
                                        principal.upper() not in _GPO_ALLOWLIST):
                                    self.data["gpo_write_perms"].append({"user":principal,"gpo":gpo["name"]})
            except Exception:
                pass
        log(f"GPO write: {len(self.data['gpo_write_perms'])}",
            "CRIT" if self.data["gpo_write_perms"] else "INFO")

    def _enum_adminsdholder(self):
        """AdminSDHolder nesnesi uzerinde varsayilan olmayan yazma yetkilerini tespit eder."""
        if not IMPACKET_LDAP: return
        adminsd_dn = "CN=AdminSDHolder,CN=System," + self.conn.base_dn
        sd_control = security_descriptor_control(sdflags=0x04)
        escaped_adminsd_dn = _escape_ldap_filter_value(adminsd_dn)
        res = self.conn.search(f"(distinguishedName={escaped_adminsd_dn})",
                               attrs=["nTSecurityDescriptor"], controls=sd_control)
        if not res: return
        raw = res[0].get("attributes",{}).get("nTSecurityDescriptor")
        if isinstance(raw, list): raw = raw[0] if raw else None
        if isinstance(raw, str):
            try: raw = base64.b64decode(raw)
            except Exception: raw = None
        if raw:
            try:
                sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
                if sd['Dacl']:
                    for ace in sd['Dacl']['Data']:
                        if ace['AceType'] in (0x00, 0x05):
                            sid = ace['Ace']['Sid'].formatCanonical()
                            if sid in ("S-1-5-18","S-1-5-32-544"): continue
                            mask = int(ace['Ace']['Mask']['Mask'])
                            is_gen_all   = (mask & 0x000F01FF) == 0x000F01FF
                            is_gen_write = (mask & 0x00020028) == 0x00020028
                            is_write_dacl  = (mask & 0x00040000) == 0x00040000
                            is_write_owner = (mask & 0x00080000) == 0x00080000
                            if is_gen_all or is_gen_write or is_write_dacl or is_write_owner:
                                principal = self.conn.resolve_sid(sid)
                                _ADMINSD_ALLOWLIST = {
                                    "DOMAIN ADMINS","ENTERPRISE ADMINS","SCHEMA ADMINS",
                                    "ADMINISTRATORS","ADMINISTRATOR","SYSTEM",
                                    "ACCOUNT OPERATORS","SERVER OPERATORS","PRINT OPERATORS",
                                    "BACKUP OPERATORS","GROUP POLICY CREATOR OWNERS",
                                    "ENTERPRISE DOMAIN CONTROLLERS","CREATOR OWNER",
                                }
                                if (principal and not principal.endswith("$") and
                                        principal.upper() not in _ADMINSD_ALLOWLIST):
                                    if is_gen_all: right = "GenericAll"
                                    elif is_gen_write: right = "GenericWrite"
                                    elif is_write_dacl: right = "WriteDACL"
                                    elif is_write_owner: right = "WriteOwner"
                                    else: right = "Unknown"
                                    self.data["adminsd_acl"].append({"user":principal,"right":right})
            except Exception as ex:
                log(f"AdminSDHolder SD parse: {ex}", "WARN")
        log(f"AdminSDHolder anomalies: {len(self.data['adminsd_acl'])}",
            "CRIT" if self.data["adminsd_acl"] else "INFO")

    def _enum_sensitive_files(self):
        """SYSVOL ve Netlogon paylasimlarinda hassas dosya taramasi."""
        if not self.smb: return
        sensitive = []
        for dc in self.data.get("dc_hosts", []):
            dc_obj = next((c for c in self.data.get("computers",[]) if c["name"].upper()==dc), None)
            if dc_obj:
                dc_name = dc_obj.get("dns") or dc_obj["name"]
                try:
                    files = self.smb.walk_share(dc_name, "SYSVOL")
                    for f in files:
                        if f.get("gpp"):
                            sensitive.append({"host":dc,"share":"SYSVOL","path":f["path"],"type":"GPP_Password"})
                        elif any(str(f.get("path","")).lower().endswith(ext) for ext in
                                 [".kdbx",".pfx",".p12","web.config","app.config",
                                  ".vmdk",".ova",".rdg","unattend.xml","sysprep.inf",
                                  "unattended.xml","autounattend.xml"]):
                            sensitive.append({"host":dc,"share":"SYSVOL","path":f["path"],"type":"Sensitive"})
                except Exception:
                    pass
        self.data["sensitive_files"] = sensitive
        log(f"Sensitive files: {len(sensitive)}", "CRIT" if sensitive else "INFO")

    def _vuln_scan(self):
        """Zafiyet taramasi: Spooler (deep), ZeroLogon, SMB signing, WinRM."""
        vuln = {"spooler":[],"zerologon":[],"signing":[],"printnightmare":[]}
        for c in self.data.get("computers", []):
            host = c.get("dns") or c["name"]
            if self.smb:
                pn_result = self.smb.check_printnightmare_deep(host)
                if pn_result["spooler"]:
                    vuln["spooler"].append(c["name"])
                vuln["printnightmare"].append({"host": c["name"], **pn_result})
            if c.get("is_dc") and self.smb and NRPC_AVAILABLE:
                zl = self.smb.check_zerologon(host)
                if zl is True:
                    vuln["zerologon"].append(c["name"])
                    log(f"ZeroLogon (CVE-2020-1472) ACIK: {c['name']}", "CRIT")
                elif zl is None:
                    log(f"ZeroLogon test edilemedi: {c['name']}", "WARN")
            if self.smb and self.smb.test_winrm(host):
                c["winrm_open"] = True
                self.data["winrm_hosts"].append(c["name"])
            signing = self.smb.check_signing(host) if self.smb else None
            if signing is False:
                vuln["signing"].append(c["name"])
        self.data["vuln_scan"] = vuln
        log(f"Vuln: Spooler={len(vuln['spooler'])} ZeroLogon={len(vuln['zerologon'])} "
            f"WinRM={len(self.data['winrm_hosts'])} SignOff={len(vuln['signing'])} "
            f"PrintNightmare={len(vuln['printnightmare'])}", "WARN")

    def _enum_gpo_contents(self):
        """GPO deep parser — SYSVOL'daki Groups.xml/Services.xml/ScheduledTasks.xml
        icindeki cpassword sifrelerini cozer; .bat/.ps1/.vbs/.psm1 dosyalarinda
        hardcoded credential tarar; Registry.xml'de autorun/key bulur."""
        if not self.smb:
            return
        gpo_contents = []
        cred_patterns = [
            (r'(?i)(?:password|passw[o0]rd|pass|pwd|pw|parola|sifre|şifre)\s*[:=]\s*(\S{3,48})', "label"),
            (r'(?i)(?:username|kullanici|kullanıcı|user|login)\s*[:=]\s*(\S+).*(?:password|pass|pwd|pw|parola)\s*[:=]\s*(\S{3,48})', "full_creds"),
            (r'(?i)(?:\$|Set-)\s*(?:password|pass|pwd|credential|secret)\s*=\s*["\']([^"\']{4,48})["\']', "ps_variable"),
            (r'(?i)(?:net\s+user\s+\S+\s+)(\S{3,48})', "net_user"),
        ]
        scanned = 0; found_creds = 0; gpp_decrypted = 0

        for dc in self.data.get("dc_hosts", []):
            dc_obj = next((c for c in self.data.get("computers", [])
                           if c["name"].upper() == dc), None)
            if not dc_obj: continue
            dc_name = dc_obj.get("dns") or dc_obj["name"]

            # Walk SYSVOL for GPO XML files
            try:
                files = self.smb.walk_gpo_dir(dc_name, "SYSVOL")
                for f in files:
                    scanned += 1
                    fname = f["name"].lower()
                    fpath = f["path"]
                    file_type = None

                    # ── GPP XML files with potential cpassword ──
                    if fname in ("groups.xml", "services.xml", "scheduledtasks.xml",
                                 "datasources.xml", "drives.xml", "printers.xml"):
                        file_type = "gpp_xml"
                        content = self.smb.read_gpo_file(dc_name, "SYSVOL", fpath)
                        if not content: continue

                        # Extract and decrypt cpassword attributes
                        for m in re.finditer(r'cpassword="([^"]+)"', content, re.IGNORECASE):
                            dec = cpassword_decrypt(m.group(1))
                            if dec:
                                gpp_decrypted += 1
                                gpo_contents.append({
                                    "dc": dc, "gpo_path": fpath, "file": fname,
                                    "type": "cpassword_decrypted",
                                    "credential": dec,
                                    "raw_encrypted": m.group(1)[:40] + "...",
                                })
                                log(f"  GPP cpassword: {fpath} → {dec[:30]}", "CRIT")

                        # Also look for plaintext passwords in XML content
                        for pat, ptype in cred_patterns[:2]:
                            for pm in re.finditer(pat, content):
                                cred = pm.groups()[-1] if pm.groups() else ""
                                if cred and len(cred) >= 3:
                                    gpo_contents.append({
                                        "dc": dc, "gpo_path": fpath, "file": fname,
                                        "type": f"xml_{ptype}",
                                        "credential": cred,
                                    })
                                    found_creds += 1

                    # ── Script files: .bat, .ps1, .psm1, .vbs, .cmd ──
                    elif fname.endswith((".bat", ".ps1", ".psm1", ".vbs", ".cmd")):
                        file_type = "script"
                        content = self.smb.read_gpo_file(dc_name, "SYSVOL", fpath)
                        if not content: continue

                        for pat, ptype in cred_patterns:
                            for pm in re.finditer(pat, content, re.DOTALL):
                                cred = pm.groups()[-1] if pm.groups() else ""
                                if cred and len(cred) >= 3:
                                    if ptype == "full_creds" and len(pm.groups()) >= 2:
                                        gpo_contents.append({
                                            "dc": dc, "gpo_path": fpath, "file": fname,
                                            "type": f"script_{ptype}",
                                            "credential": f"{pm.group(1)}:{cred}",
                                        })
                                    elif ptype != "full_creds":
                                        gpo_contents.append({
                                            "dc": dc, "gpo_path": fpath, "file": fname,
                                            "type": f"script_{ptype}",
                                            "credential": cred,
                                        })
                                    found_creds += 1

                    # ── Registry.xml: run keys, autorun ──
                    elif fname == "registry.xml":
                        file_type = "registry_xml"
                        content = self.smb.read_gpo_file(dc_name, "SYSVOL", fpath)
                        if not content:
                            continue
                        # Extract run/autorun keys
                        for rk in re.finditer(
                                r'(?i)(?:HKLM|HKCU|HKCR|HKU)\\\\[^"]*(?:Run|RunOnce|RunOnceEx|Autorun|AutoRun|Policies\\\\Explorer\\\\Run)\\\\[^"]*',
                                content):
                            gpo_contents.append({
                                "dc": dc, "gpo_path": fpath, "file": fname,
                                "type": "registry_autorun",
                                "credential": rk.group(0)[:120],
                            })
                        # Check for cpassword in registry.xml too
                        for m in re.finditer(r'cpassword="([^"]+)"', content, re.IGNORECASE):
                            dec = cpassword_decrypt(m.group(1))
                            if dec:
                                gpp_decrypted += 1
                                gpo_contents.append({
                                    "dc": dc, "gpo_path": fpath, "file": fname,
                                    "type": "cpassword_decrypted",
                                    "credential": dec,
                                })

                    # ── Sensitive files ──
                    elif fname.endswith((".kdbx", ".pfx", ".p12", ".ovf", ".ova", ".vmdk",
                                         "web.config", "app.config", ".rdg", "unattend.xml",
                                         "sysprep.inf", "unattended.xml", "autounattend.xml")):
                        gpo_contents.append({
                            "dc": dc, "gpo_path": fpath, "file": fname,
                            "type": "sensitive_file",
                            "credential": fpath,
                        })

            except Exception as ex:
                log(f"GPO crawl failed on {dc_name}: {ex}", "WARN")

        self.data["gpo_contents"] = gpo_contents
        log(f"GPO deep scan: {scanned} files on SYSVOL, "
            f"{gpp_decrypted} GPP passwords decrypted, "
            f"{found_creds} script credentials found, "
            f"{sum(1 for g in gpo_contents if g['type']=='sensitive_file')} sensitive files",
            "CRIT" if (gpp_decrypted or found_creds) else "SUCCESS")

    def _enum_ou_dacls(self):
        """OU konteynerlerinde ACL analizi. OU seviyesinde GenericAll/WriteOwner
        olan hesaplar, o OU altindaki tum objelere hukmedebilir."""
        if not IMPACKET_LDAP:
            return
        ou_acls = []
        sd_control = security_descriptor_control(sdflags=0x04)
        ous = self.data.get("ous", [])
        if len(ous) > 50:
            log(f"OU ACL analysis truncated: analyzing first 50 of {len(ous)} OUs (use --threads to speed up)", "WARN")
        for ou in ous[:50]:  # limit to avoid timeout in large domains
            try:
                escaped = _escape_ldap_filter_value(ou["dn"])
                res = self.conn.search(f"(distinguishedName={escaped})",
                                       attrs=["nTSecurityDescriptor"], controls=sd_control)
                if not res: continue
                raw = res[0].get("attributes", {}).get("nTSecurityDescriptor")
                if isinstance(raw, list): raw = raw[0] if raw else None
                if isinstance(raw, str):
                    try: raw = base64.b64decode(raw)
                    except Exception: raw = None
                if not raw: continue
                sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
                if not sd.get('Dacl'): continue
                dangerous = []
                for ace in sd['Dacl']['Data']:
                    if ace['AceType'] not in (0x00, 0x05): continue
                    sid = ace['Ace']['Sid'].formatCanonical()
                    if sid in ("S-1-5-18", "S-1-5-32-544", "S-1-5-9"): continue
                    mask = int(ace['Ace']['Mask']['Mask'])
                    if (mask & 0x000F01FF) == 0x000F01FF: right = "GenericAll"
                    elif (mask & 0x00020028) == 0x00020028: right = "GenericWrite"
                    elif (mask & 0x00040000) == 0x00040000: right = "WriteDACL"
                    elif (mask & 0x00080000) == 0x00080000: right = "WriteOwner"
                    else: continue
                    principal = self.conn.resolve_sid(sid)
                    if principal:
                        dangerous.append({"principal": principal, "right": right})
                if dangerous:
                    # Count objects under this OU
                    obj_count = sum(1 for u in self.data.get("users", [])
                                    if ou["dn"] in u.get("dn", "")) + \
                                sum(1 for g in self.data.get("groups", [])
                                    if ou["dn"] in g.get("dn", "")) + \
                                sum(1 for c in self.data.get("computers", [])
                                    if ou["dn"] in c.get("dn", ""))
                    ou_acls.append({
                        "ou": ou["name"], "ou_dn": ou["dn"],
                        "object_count": obj_count,
                        "dangerous_aces": dangerous,
                    })
            except Exception:
                pass
        self.data["ou_acls"] = ou_acls
        log(f"OU ACL analysis: {len(ou_acls)} OUs with dangerous ACEs",
            "CRIT" if ou_acls else "INFO")

    def _enum_exchange_perms(self):
        """Exchange Trusted Subsystem / Windows Permissions / Org Management
        uyelerinden DCSync hakki olanlari tespit eder."""
        exchange_member_names = set()
        for g in self.data.get("groups", []):
            if g.get("name","") in ("Exchange Trusted Subsystem",
                                    "Exchange Windows Permissions",
                                    "Organization Management"):
                for m in g.get("members", []):
                    name = dn_to_name(m)
                    if name: exchange_member_names.add(name.upper())
        for d in self.data.get("dcsync_rights", []):
            uname = (d.get("user") or "").upper()
            if uname in exchange_member_names:
                entry = {**d, "via": "Exchange Group"}
                if entry not in self.data.get("exchange_dcsync", []):
                    self.data["exchange_dcsync"].append(entry)
        log(f"Exchange DCSync: {len(self.data.get('exchange_dcsync',[]))}",
            "CRIT" if self.data.get("exchange_dcsync") else "INFO")

    def _password_spray(self, password):
        """Parola sprey saldirisi."""
        user_list = [u["name"] for u in self.data.get("users",[]) if u.get("enabled")]
        lockout = int(self.data.get("domain",{}).get("lockout_threshold",0))
        valid = self.conn.password_spray(user_list, password, lockout)
        log(f"Spray valid: {len(valid)}", "CRIT" if valid else "INFO")

    def _validate_credentials(self):
        """Tum bulunan credential'lari test et: description, GPO, spray pass."""
        validated = []
        candidates = set()  # (username, password) tuples

        # Collect from description_passwords
        for f in self.data.get("description_passwords", []):
            cred = f.get("found_credential", "")
            user = f.get("found_username", "") or f.get("user", "")
            if cred and len(cred) >= 3:
                candidates.add((user, cred))
                # Also try the owner user with this password
                if f.get("user"):
                    candidates.add((f["user"], cred))

        # Collect from GPO contents
        for g in self.data.get("gpo_contents", []):
            cred = g.get("credential", "")
            if cred and len(cred) >= 3 and ":" not in cred[:3]:
                # Try common usernames with GPO-found passwords
                for u in self.data.get("users", []):
                    if u.get("enabled") and u.get("admin_count", 0) > 0:
                        candidates.add((u["name"], cred))

        # Collect from spray pass
        spray_pass = getattr(self, '_spray_password', None)
        if spray_pass:
            for u in self.data.get("users", []):
                if u.get("enabled"):
                    candidates.add((u["name"], spray_pass))

        if not candidates:
            log("No credentials to validate", "INFO")
            self.data["validated_credentials"] = []
            return

        log(f"Validating {len(candidates)} credential candidates...", "INFO")
        tested = 0; valid_count = 0

        for username, password in list(candidates)[:100]:  # limit to 100 to avoid lockout
            if not username or not password:
                continue
            tested += 1
            is_valid, user_info = self.conn.test_credential_ldap(username, password)
            result = {
                "username": username, "password": password[:30] + "..." if len(password) > 30 else password,
                "method": "LDAP", "valid": is_valid,
                "is_da": user_info.get("is_da", False) if user_info else False,
                "admin_count": user_info.get("admin_count", 0) if user_info else 0,
            }
            validated.append(result)
            if is_valid:
                valid_count += 1
                level = "CRIT" if user_info and user_info.get("is_da") else "SUCCESS"
                log(f"  VALID: {username}:{password[:20]}... "
                    f"({'DA!' if user_info and user_info.get('is_da') else 'user'})", level)

        self.data["validated_credentials"] = validated
        log(f"Credential validation: {valid_count}/{tested} valid", "CRIT" if valid_count else "SUCCESS")

    # ── MSSQL/SCCM/LAPS methods ──
    def _enum_mssql(self):
        """MSSQL enumeration via LDAP SPN scan. Finds SQL servers and service accounts."""
        mssql = []
        for spn_entry in self.data.get("spns", []):
            for spn in (spn_entry.get("spns", []) or []):
                if not isinstance(spn, str): continue
                if "MSSQL" in spn.upper():
                    parts = spn.split("/")
                    host_port = parts[1] if len(parts) > 1 else "?"
                    host = host_port.split(":")[0]
                    port = host_port.split(":")[1] if ":" in host_port else "1433"
                    mssql.append({
                        "host": host, "port": port, "service_account": spn_entry["user"],
                        "spn": spn, "is_da": spn_entry["user"].upper() in
                                   {a["member_name"].upper() for a in self.data.get("admins", [])
                                    if a.get("group") in ("Domain Admins", "Enterprise Admins")}
                    })
        self.data["mssql_servers"] = mssql
        log(f"MSSQL servers: {len(mssql)} (da_svc={sum(1 for m in mssql if m['is_da'])})",
            "WARN" if mssql else "INFO")

    def _enum_sccm(self):
        """SCCM/MECM enumeration — System Management container, NAA account, site servers."""
        sccm = []
        try:
            sm_dn = "CN=System Management,CN=System," + self.conn.base_dn
            escaped = _escape_ldap_filter_value(sm_dn)
            res = self.conn.search(f"(objectClass=*)", attrs=["cn","name","description","mSSMSSiteCode"],
                                   base=escaped)
            for e in res:
                sccm.append({
                    "name": self._attr(e, "cn") or self._attr(e, "name"),
                    "site_code": self._attr(e, "mSSMSSiteCode"),
                    "description": self._attr(e, "description"),
                })
        except Exception:
            pass
        # Find SCCM SPNs (MS-SMS)
        for spn_entry in self.data.get("spns", []):
            for spn in (spn_entry.get("spns", []) or []):
                if isinstance(spn, str) and "SMS" in spn.upper():
                    sccm.append({"type": "SCCM_SPN", "service_account": spn_entry["user"], "spn": spn})
        self.data["sccm"] = sccm
        log(f"SCCM sites: {len(sccm)}",
            "WARN" if sccm else "INFO")

    def _read_laps_passwords(self):
        """LAPS sifrelerini oku. Kullanicinin ms-Mcs-AdmPwd / msLAPS-Password
        okuma yetkisi varsa, her bilgisayarin LAPS sifresini ceker."""
        laps_pwds = []
        for c in self.data.get("computers", []):
            if not c.get("laps_configured"):
                continue
            try:
                escaped = _escape_ldap_filter_value(c.get("dn", ""))
                res = self.conn.search(f"(distinguishedName={escaped})",
                                       attrs=["ms-Mcs-AdmPwd", "msLAPS-Password",
                                              "msLAPS-PasswordExpirationTime"])
                if res:
                    attrs = res[0].get("attributes", {})
                    pwd = attrs.get("msLAPS-Password") or attrs.get("ms-Mcs-AdmPwd")
                    if pwd:
                        if isinstance(pwd, list): pwd = pwd[0] if pwd else ""
                        if not pwd: continue  # skip empty passwords (false positive)
                        laps_pwds.append({
                            "computer": c["name"], "password": str(pwd),
                            "source": "msLAPS-Password" if attrs.get("msLAPS-Password")
                                      else "ms-Mcs-AdmPwd",
                        })
            except Exception:
                pass
        self.data["laps_passwords"] = laps_pwds
        log(f"LAPS passwords read: {len(laps_pwds)} computers",
            "CRIT" if laps_pwds else "SUCCESS")

    def _build_remediation(self):
        """Dinamik remediation PowerShell betikleri."""
        snippets = []
        domain_dn = self.data.get("domain",{}).get("dn","DC=domain,DC=local")
        domain_nm = self.data.get("domain",{}).get("name","DOMAIN")
        d = self.data.get("domain",{})
        if int(d.get("min_pwd_length",0) or 0) < 12:
            snippets.append({"title":"[PwdPolicy] Min password length < 12","mitre":"T1110.003",
                "psh":f"Set-ADDefaultDomainPasswordPolicy -Identity '{domain_nm}' -MinPasswordLength 14"})
        if int(d.get("lockout_threshold",0) or 0) == 0:
            snippets.append({"title":"[PwdPolicy] No lockout threshold","mitre":"T1110.003",
                "psh":f"Set-ADDefaultDomainPasswordPolicy -Identity '{domain_nm}' -LockoutThreshold 5"})
        if int(d.get("machine_account_quota",10) or 10) > 0:
            snippets.append({"title":"[MAQ] Set MachineAccountQuota=0","mitre":"T1136.002",
                "psh":f"Set-ADDomain -Identity '{domain_dn}' -Replace @{{'ms-DS-MachineAccountQuota'='0'}}"})
        # ASREP
        for user in self.data.get("asrep",[]):
            u_obj = next((u for u in self.data.get("users",[]) if u["name"]==user), {})
            snippets.append({"title":f"[ASREP] Enable pre-auth: {user}","mitre":"T1558.004",
                "psh":f"Set-ADAccountControl -Identity '{u_obj.get('dn',user)}' -DoesNotRequirePreAuth $false"})
        # Shadow Creds
        for sc in self.data.get("shadow_creds",[]):
            snippets.append({"title":f"[ShadowCreds] Clear: {sc.get('user','')}","mitre":"T1556.006",
                "psh":f"Set-ADObject -Identity '{sc.get('dn','')}' -Clear msDS-KeyCredentialLink"})
        # Unconstrained delegation
        for comp in self.data.get("computers",[]):
            if comp.get("trusted_for_delegation") and not comp.get("is_dc"):
                snippets.append({"title":f"[Delegation] Disable unconstrained: {comp['name']}","mitre":"T1558.001",
                    "psh":f"Set-ADComputer -Identity '{comp.get('dn',comp['name'])}' -TrustedForDelegation $false"})
            # RBCD
            if comp.get("rbcd") and not comp.get("is_dc"):
                snippets.append({"title":f"[RBCD] Clear delegation: {comp['name']}","mitre":"T1134.001",
                    "psh":f"Set-ADComputer -Identity '{comp.get('dn',comp['name'])}' -Clear msDS-AllowedToActOnBehalfOfOtherIdentity"})
        # Spooler
        for host in self.data.get("vuln_scan",{}).get("spooler",[]):
            snippets.append({"title":f"[Spooler] Disable: {host}","mitre":"T1187",
                "psh":f"Invoke-Command -ComputerName '{host}' {{Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled}}"})
        # DCSync
        da_upper = {u.upper() for u in self.data.get("da_users",[])}
        for ds in self.data.get("dcsync_rights",[]):
            if (ds.get("user","")).upper() in da_upper: continue
            _u = ds.get("user", ds.get("sid",""))
            snippets.append({"title":f"[DCSync] Revoke: {_u}","mitre":"T1003.006",
                "psh":f"$dn = '{domain_dn}'; "
                      f"$acl = Get-Acl -Path \"AD:\\$dn\"; "
                      f"$user = [System.Security.Principal.NTAccount]'{_u}'; "
                      f"$rule = $acl.Access | Where-Object {{ $_.IdentityReference -eq $user }}; "
                      f"if ($rule) {{ $acl.RemoveAccessRule($rule); Set-Acl -Path \"AD:\\$dn\" -AclObject $acl }}"})
        # ZeroLogon remediation
        for host in self.data.get("vuln_scan",{}).get("zerologon",[]):
            snippets.append({"title":f"[ZeroLogon] Patch DC: {host}","mitre":"CVE-2020-1472",
                "psh":f"# Install KB4565349 or later on {host}. Verify with: Get-HotFix -Id KB4565349"})
        # LAPS readers remediation
        for lr in self.data.get("laps_readers",[]):
            snippets.append({"title":f"[LAPS] Remove read access from {lr['reader']} on {lr['computer']}","mitre":"T1552.006",
                "psh":f"$acl = Get-Acl -Path \"AD:\\$((Get-ADComputer '{lr['computer']}').DistinguishedName)\"; "
                      f"$user = [System.Security.Principal.NTAccount]'{lr['reader']}'; "
                      f"$rule = $acl.Access | Where-Object {{ $_.IdentityReference -eq $user -and $_.ActiveDirectoryRights -match 'ReadProperty' }}; "
                      f"if ($rule) {{ $acl.RemoveAccessRule($rule); Set-Acl -Path \"AD:\\$((Get-ADComputer '{lr['computer']}').DistinguishedName)\" -AclObject $acl }}"})
        self.data["remediation_snippets"] = snippets
        log(f"Remediation scripts: {len(snippets)}", "SUCCESS")

    # ── SMB methods ──
    def _active_hosts(self, include_dcs=False):
        out = []
        for c in self.data.get("computers", []):
            if not c.get("enabled"): continue
            if not include_dcs and c.get("is_dc"): continue
            out.append((c["name"].upper(), c.get("dns") or c["name"]))
        return out

    def _smb_sessions(self):
        if not self.smb: return
        hosts = self._active_hosts(include_dcs=True)
        log(f"Session enum on {len(hosts)} hosts...", "INFO")
        def q(a):
            name, target = a
            return name, self.smb.get_sessions(target)
        seen = set()
        for name, sess in self._run_parallel(q, hosts):
            if sess:
                for s in sess:
                    dedup_key = (s.get("user",""), s.get("host_name",""), s.get("stype",""))
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        self.data["sessions"].append(s)
                        for c in self.data["computers"]:
                            if c["name"].upper() == name.upper(): c["sessions"].append(s)
        da = {u.upper() for u in self.data.get("da_users",[])}
        das = [s for s in self.data["sessions"] if s.get("user","").upper() in da]
        log(f"SMB sessions:{len(self.data['sessions'])} DA:{len(das)}", "SUCCESS")
        for s in das: log(f"  [DA SESSION] {s['user']} on {s['host_name']}", "CRIT")

    def _smb_loggedon(self):
        if not self.smb: return
        hosts = self._active_hosts(include_dcs=True)
        log(f"Loggedon enum on {len(hosts)} hosts...", "INFO")
        def q(a):
            name, target = a
            return name, self.smb.get_loggedon(target)
        seen = set()
        for name, users in self._run_parallel(q, hosts):
            if users:
                for u in users:
                    dedup_key = (u.get("user",""), u.get("host_name",""), u.get("stype",""))
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        self.data["loggedon"].append(u)
                        for c in self.data["computers"]:
                            if c["name"].upper() == name.upper(): c["loggedon"].append(u)
        da = {u.upper() for u in self.data.get("da_users",[])}
        dal = [u for u in self.data["loggedon"] if u.get("user","").upper() in da]
        log(f"Logged-on:{len(self.data['loggedon'])} DA:{len(dal)}", "SUCCESS")

    def _smb_local_admins(self):
        if not self.smb: return
        hosts = self._active_hosts()
        log(f"Local admin enum on {len(hosts)} hosts...", "INFO")
        def q(a):
            name, target = a
            return name, self.smb.get_local_admins(target, self.conn)
        for name, admins in self._run_parallel(q, hosts):
            if admins:
                seen_la = set()
                for la in admins:
                    k = (la.get("user",""), la.get("host",""))
                    if k not in seen_la:
                        seen_la.add(k)
                        self.data["local_admins"].append(la)
                        for c in self.data["computers"]:
                            if c["name"].upper() == name.upper(): c["local_admins"].append(la)
        log(f"Local admin mappings: {len(self.data['local_admins'])}", "SUCCESS")

    def _smb_rdp(self):
        if not self.smb: return
        hosts = self._active_hosts()
        log(f"RDP scan on {len(hosts)} hosts...", "INFO")
        def chk(a):
            name, target = a
            return name, self.smb.check_port(target, 3389)
        for name, is_open in self._run_parallel(chk, hosts):
            for c in self.data["computers"]:
                if c["name"].upper() == name.upper(): c["rdp_open"] = is_open
            if is_open:
                self.data["rdp_open"].append(name)
        log(f"RDP-open hosts: {len(self.data['rdp_open'])}", "SUCCESS")
        try:
            rdp_group_res = self.conn.search(
                "(&(objectClass=group)(sAMAccountName=Remote Desktop Users))", ["member"])
            dc_open = [h for h in self.data["rdp_open"] if h.upper() in self.data.get("dc_hosts",[])]
            for e in rdp_group_res:
                members = e.get("attributes",{}).get("member",[])
                if not isinstance(members,list): members=[members] if members else []
                for m in members:
                    mname = dn_to_name(m)
                    if not mname: continue
                    for name in dc_open:
                        self.data["rdp_access"].append({"user":mname,"host":name,"source":"Remote Desktop Users (DC)"})
            # LocalAdmin -> RDP chain
            rdp_set = {h.upper() for h in self.data["rdp_open"]}
            for la in self.data.get("local_admins",[]):
                h = la.get("host","").split(".")[0].upper()
                u = la.get("user","")
                if h in rdp_set and u:
                    self.data["rdp_access"].append({"user":u,"host":h,"source":"LocalAdmin→RDP"})
            for c in self.data["computers"]:
                if c.get("rdp_open"):
                    hn = c["name"].upper()
                    for entry in self.data["rdp_access"]:
                        if entry["host"].upper() == hn and entry["user"] not in c.get("rdp_users",[]):
                            c["rdp_users"].append(entry["user"])
        except Exception as ex:
            log(f"RDP enum: {ex}", "WARN")
        log(f"RDP access mappings: {len(self.data['rdp_access'])}", "DATA")

    def _smb_shares(self):
        if not self.smb: return
        hosts = self._active_hosts(include_dcs=True)
        log(f"Share enum on {len(hosts)} hosts...", "INFO")
        def q(a):
            name, target = a
            return name, self.smb.get_shares(target)
        for name, shares in self._run_parallel(q, hosts):
            if shares:
                for s in shares:
                    self.data["shares"].append(s)
                for c in self.data["computers"]:
                    if c["name"].upper() == name.upper():
                        for s in shares:
                            if s not in c.get("shares",[]): c["shares"].append(s)
        log(f"Shares: {len(self.data['shares'])}", "SUCCESS")

    # ── Attack Chain & Graph ──
    def _build_chains(self):
        engine = AttackChainEngine(self.data)
        self.data["attack_chains"] = engine.build()
        cr = sum(1 for c in self.data["attack_chains"] if c.get("severity")=="CRITICAL")
        hi = sum(1 for c in self.data["attack_chains"] if c.get("severity")=="HIGH")
        log(f"Attack chains: {len(self.data['attack_chains'])} CRITICAL:{cr} HIGH:{hi}",
            "CRIT" if cr else "SUCCESS")

    def _build_graph(self):
        node_map, edge_set, edges = {}, set(), []
        def add_node(id_, type_, **kw):
            if not id_: return
            if id_ not in node_map: node_map[id_] = {"id":id_,"type":type_,**kw}
            else: node_map[id_].update(kw)
        def add_edge(src, dst, rel, highlight=False, color=None):
            if not src or not dst: return
            k = (src,dst,rel)
            if k in edge_set: return
            edge_set.add(k)
            edges.append({"source":src,"target":dst,"relation":rel,"highlight":highlight,"color":color})
        DA = {u.upper() for u in self.data.get("da_users",[])}
        for u in self.data.get("users",[]):
            add_node(u["name"],"user",admin=u.get("admin_count",0),enabled=u.get("enabled",False),
                    spns=len(u.get("spns",[])),no_preauth=u.get("no_preauth",False),
                    is_da=u["name"].upper() in DA)
        for g in self.data.get("groups",[]):
            add_node(g["name"],"group",admin=g.get("admin_count",0))
        for c in self.data.get("computers",[]):
            add_node(c["name"],"computer",is_dc=c.get("is_dc",False),
                    rdp_open=c.get("rdp_open",False),delegation=c.get("trusted_for_delegation",False))
        for sp in ["DOMAIN ADMIN","KERBEROAST","ASREP-ROAST","UNCONSTRAINED DELEGATION","PASSWORD SPRAY"]:
            add_node(sp,"attack")
        grp_set = {g["name"] for g in self.data.get("groups",[])}
        for u in self.data.get("users",[]):
            for gdn in u.get("groups",[]):
                gname = dn_to_name(gdn)
                if gname in grp_set:
                    is_priv = any(g["name"]==gname and g.get("admin_count") for g in self.data.get("groups",[]))
                    add_edge(u["name"],gname,"MemberOf",highlight=is_priv,color="#ef4444" if is_priv else None)
        for a in self.data.get("admins",[]):
            if a["group"] in ("Domain Admins","Enterprise Admins"):
                add_edge(a["member_name"],"DOMAIN ADMIN","IsDomainAdmin",highlight=True,color="#ef4444")
        for s in self.data.get("sessions",[])+self.data.get("loggedon",[]):
            user = s.get("user","").split("\\")[-1]
            host = (s.get("host_name") or s.get("host","")).split(".")[0].upper()
            if not user or not host: continue
            is_da = user.upper() in DA
            add_node(user,"user"); add_node(host,"computer")
            add_edge(user,host,"HasSession",highlight=is_da,color="#ef4444" if is_da else "#f97316")
        for la in self.data.get("local_admins",[]):
            u, h = la.get("user",""), la.get("host","").split(".")[0].upper()
            if u and h:
                add_node(u,"user"); add_node(h,"computer")
                add_edge(u,h,"LocalAdmin",highlight=True,color="#f97316")
        for r in self.data.get("rdp_access",[]):
            u, h = r.get("user",""), r.get("host","").split(".")[0].upper()
            if u and h: add_edge(u,h,"CanRDP",color="#a855f7")
        for s in self.data.get("spns",[]):
            add_edge(s["user"],"KERBEROAST","Kerberoastable",highlight=True,color="#ef4444")
        for u in self.data.get("asrep",[]):
            add_edge(u,"ASREP-ROAST","ASREPRoastable",highlight=True,color="#ef4444")
        for c in self.data.get("computers",[]):
            if c.get("trusted_for_delegation") and not c.get("is_dc"):
                add_edge(c["name"],"UNCONSTRAINED DELEGATION","TrustedFor",highlight=True,color="#eab308")
        for ae in self.data.get("acl_edges",[]):
            src,tgt,right,sev = ae.get("source",""),ae.get("target",""),ae.get("right",""),ae.get("severity","HIGH")
            if src and tgt:
                add_node(src,"user"); add_node(tgt,"user")
                add_edge(src,tgt,right,highlight=True,color="#ef4444" if sev=="CRITICAL" else "#f97316")
        self.data["edges"] = edges
        self.data["graph_nodes"] = list(node_map.values())
        log(f"Graph: {len(node_map)} nodes, {len(edges)} edges", "SUCCESS")

    def _finalize_meta(self):
        s = self.data
        cr = sum(1 for c in s.get("attack_chains",[]) if c.get("severity")=="CRITICAL")
        hi = sum(1 for c in s.get("attack_chains",[]) if c.get("severity")=="HIGH")
        self.data["meta"] = {
            "target": self.conn.host, "domain": self.conn.domain,
            "base_dn": self.conn.base_dn,
            "enum_time": datetime.datetime.now().isoformat(),
            "stats": {
                "users": len(s.get("users",[])), "groups": len(s.get("groups",[])),
                "computers": len(s.get("computers",[])), "ous": len(s.get("ous",[])),
                "gpos": len(s.get("gpos",[])), "spns": len(s.get("spns",[])),
                "asrep_users": len(s.get("asrep",[])), "edges": len(s.get("edges",[])),
                "sessions": len(s.get("sessions",[])), "loggedon": len(s.get("loggedon",[])),
                "local_admins": len(s.get("local_admins",[])),
                "rdp_open": len(s.get("rdp_open",[])),
                "attack_chains": len(s.get("attack_chains",[])),
                "critical_chains": cr, "high_chains": hi,
                "da_users": len(s.get("da_users",[])),
                "acl_edges": len(s.get("acl_edges",[])),
                "gpo_links": len(s.get("gpo_links",[])),
                "shares": len(s.get("shares",[])),
                "adcs_esc": len(s.get("adcs_esc",[])),
                "shadow_creds": len(s.get("shadow_creds",[])),
                "dcsync_rights": len(s.get("dcsync_rights",[])),
                "fgpp": len(s.get("fgpp",[])),
                "gpo_write_perms": len(s.get("gpo_write_perms",[])),
                "adminsd_acl": len(s.get("adminsd_acl",[])),
                "sensitive_files": len(s.get("sensitive_files",[])),
                "winrm_hosts": len(s.get("winrm_hosts",[])),
                "exchange_dcsync": len(s.get("exchange_dcsync",[])),
                "description_passwords": len(s.get("description_passwords",[])),
                "gpo_credentials": len(s.get("gpo_contents",[])),
                "validated_credentials": sum(1 for v in s.get("validated_credentials",[]) if v.get("valid")),
                "ou_acls": len(s.get("ou_acls", [])),
                "mssql_servers": len(s.get("mssql_servers", [])),
                "sccm_sites": len(s.get("sccm", [])),
                "laps_passwords_read": len(s.get("laps_passwords", [])),
                "remediation_snippets": len(s.get("remediation_snippets",[])),
                "tombstoned_objects": len(s.get("tombstoned_objects",[])),
                "protected_users_gap": sum(
                    1 for a in s.get("admins",[]) if a.get("group") in ("Domain Admins","Enterprise Admins")
                    and a.get("member_name","").upper()
                    not in {m.upper() for m in s.get("protected_users_members",[])}),
                "delegation_matrix": len(s.get("delegation_matrix",[])),
                "printerbug_hosts": len(s.get("printerbug_hosts",[])),
                "petitpotam_hosts": len(s.get("petitpotam_hosts",[])),
                "ntlm_relay_risk_hosts": len(s.get("ntlm_relay_risk_hosts",[])),
                "ldap_signing_enforced": s.get("ldap_security",{}).get("signing_enforced"),
                "channel_binding_enforced": s.get("ldap_security",{}).get("cb_enforced"),
                "nopac_risk": s.get("nopac_risk",{}).get("potentially_vulnerable",False),
                "mitre_ttps": len(set(r.get("mitre","") for r in s.get("remediation_snippets",[]) if r.get("mitre"))),
                "laps_readers": len(s.get("laps_readers",[])),
                "service_accounts": len(s.get("service_account_map",[])),
            }
        }


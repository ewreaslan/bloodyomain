#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Bloodyomain — Active Directory Enumeration & Attack Path Visualization
Full Integration: Password Spray, BloodHound Export, Shadow Credentials, DCSync Audit,
FGPP, GPO Write Permissions, AdminSDHolder, Sensitive Files, Spooler, ZeroLogon,
WinRM, Cross-Forest Trust, Exchange Permissions, Async LDAP, Remediation Snippets
"""
import argparse
import json
import sys
import os
import ssl
import socket
import datetime
import getpass
import re
import base64
import concurrent.futures
import threading
import binascii
import hashlib
from pathlib import Path
from collections import defaultdict


# ── Optional deps ──
try:
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, ALL_ATTRIBUTES, Tls, ANONYMOUS, SIMPLE
    from ldap3.core.exceptions import LDAPException
    try:
        from ldap3.protocol.microsoft import security_descriptor_control
    except ImportError:
        def security_descriptor_control(*a, **k): return []
    LDAP3_AVAILABLE = True
    _Server = Server
    _Connection = Connection
    _ALL = ALL
    _NTLM = NTLM
    _SUBTREE = SUBTREE
    _ALL_ATTRIBUTES = ALL_ATTRIBUTES
    _Tls = Tls
    _ANONYMOUS = ANONYMOUS
    _SIMPLE = SIMPLE
    _LDAPException = LDAPException
except ImportError:
    LDAP3_AVAILABLE = False
    ALL = NTLM = SUBTREE = Tls = ANONYMOUS = SIMPLE = None
    ALL_ATTRIBUTES = "*"
    def security_descriptor_control(*a, **k): return []

try:
    from impacket.dcerpc.v5 import transport, wkst, srvs, samr, scmr
    from impacket.smbconnection import SMBConnection
    from impacket.ntlm import compute_lmhash, compute_nthash
    try:
        from impacket.ldap import ldaptypes
        IMPACKET_LDAP = True
    except ImportError:
        IMPACKET_LDAP = False
    try:
        from impacket.dcerpc.v5 import nrpc
        NRPC_AVAILABLE = True
    except ImportError:
        NRPC_AVAILABLE = False
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False
    IMPACKET_LDAP = False
    NRPC_AVAILABLE = False


# ── ANSI ──
class C:
    RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"; BLUE="\033[94m"
    MAGENTA="\033[95m"; CYAN="\033[96m"; GRAY="\033[90m"
    BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

BANNER = f"""{C.RED}{C.BOLD}
 ███████╗ ██╗      ██████╗   ██████╗  ██████╗  ██╗   ██╗
 ██╔══██╗ ██║     ██╔═══██╗ ██╔═══██╗ ██╔══██╗ ╚██╗ ██╔╝
 ██████╔╝ ██║     ██║   ██║ ██║   ██║ ██║  ██║  ╚████╔╝
 ██╔══██╗ ██║     ██║   ██║ ██║   ██║ ██║  ██║   ╚██╔╝
 ██████╔╝ ███████╗╚██████╔╝ ╚██████╔╝ ██████╔╝    ██║
 ╚═════╝  ╚══════╝ ╚═════╝   ╚═════╝  ╚═════╝     ╚═╝
{C.RESET}{C.RED}      ██████╗ ███╗   ███╗  █████╗  ██╗ ███╗   ██╗
      ██╔══██╗████╗ ████║ ██╔══██╗ ██║ ████╗  ██║
      ██║  ██║██╔████╔██║ ███████║ ██║ ██╔██╗ ██║
      ██████╔╝██║╚██╔╝██║ ██╔══██║ ██║ ██║╚██╗██║
      ╚═════╝ ╚═╝     ╚═╝ ╚═╝  ╚═╝ ╚═╝ ╚═╝  ╚═══╝
{C.RESET}{C.GRAY}Bloodymain — AD Enumeration & Attack Path Visualization{C.RESET}
{C.DIM}LDAP · SMB · DACL · Sessions · RDP · Attack Chains · Full Audit{C.RESET}
"""

_lock = threading.Lock()
def log(msg, level="INFO"):
    icons = {"INFO": f"{C.CYAN}[*]{C.RESET}", "SUCCESS": f"{C.GREEN}[+]{C.RESET}",
             "WARN": f"{C.YELLOW}[!]{C.RESET}", "ERROR": f"{C.RED}[-]{C.RESET}",
             "DATA": f"{C.BLUE}[~]{C.RESET}", "CRIT": f"{C.RED}{C.BOLD}[!!]{C.RESET}"}
    with _lock:
        print(f"  {icons.get(level,'[?]')} {msg}")

def section(title):
    with _lock:
        print(f"\n{C.BOLD}{C.YELLOW}{'─'*62}{C.RESET}")
        print(f"{C.BOLD}{C.YELLOW}  {title}{C.RESET}")
        print(f"{C.BOLD}{C.YELLOW}{'─'*62}{C.RESET}")

# ── Helpers ──
def _escape_ldap_filter_value(val):
    """LDAP filter icin DN/string kacis karakterleri (RFC 4515).
    Yildiz, parantez, ters slash ve NUL karakterleri kacirilmalidir."""
    if not val:
        return val
    # RFC 4515 LDAP filter escape: special chars -> \XX hex
    # Double backslashes required — single \5c etc. are Python octal escapes (control chars)!
    val = str(val).replace('\\', '\\5c')
    val = val.replace('*', '\\2a')
    val = val.replace('(', '\\28')
    val = val.replace(')', '\\29')
    val = val.replace('\0', '\\00')
    return val

def dn_to_name(dn):
    if not dn: return ""
    m = re.match(r'^(?:CN|cn)=([^,]+)', str(dn))
    return m.group(1) if m else str(dn).split(",")[0]

def filetime_to_dt(ft):
    try:
        ft = int(ft)
        if ft in (0, 9223372036854775807): return None
        return datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=ft//10)
    except (ValueError, TypeError, OverflowError): return None

def days_since(dt):
    if not dt: return None
    try: return (datetime.datetime.utcnow() - dt).days
    except (ValueError, TypeError, OverflowError): return None

WELL_KNOWN_SIDS = {
    "S-1-1-0":"Everyone","S-1-5-7":"Anonymous","S-1-5-18":"SYSTEM",
    "S-1-5-19":"LOCAL SERVICE","S-1-5-20":"NETWORK SERVICE",
    "S-1-5-32-544":"Administrators","S-1-5-32-545":"Users",
    "S-1-5-32-546":"Guests","S-1-5-32-548":"Account Operators",
    "S-1-5-32-549":"Server Operators","S-1-5-32-550":"Print Operators",
    "S-1-5-32-551":"Backup Operators","S-1-5-32-555":"Remote Desktop Users",
    "S-1-5-9":"Enterprise DCs",
}

# DANGEROUS_ACCESS mask degerleri:
# GenericAll     = 0x000F01FF (tum bitler)
# GenericWrite   = 0x00020028
# WriteOwner     = 0x00080000
# WriteDACL      = 0x00040000
# NOT: 0x10000000 = ADS_RIGHT_ACCESS_SYSTEM_SECURITY (GenericAll DEGILDIR!)
DANGEROUS_ACCESS = {
    0x000F01FF: "GenericAll",
    0x00020028: "GenericWrite",
    0x00080000: "WriteOwner",
    0x00040000: "WriteDACL",
}
DANGEROUS_GUIDS = {
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "Self-Membership",
}

def _guid_from_ace(ace_obj):
    """ACCESS_ALLOWED_OBJECT_ACE / ACCESS_DENIED_OBJECT_ACE içindeki ObjectType
    alanını standart tireli-hex GUID string'ine çevirir.
    Tüm GUID karşılaştırmaları (DACLAnalyzer, DCSync denetimi) bu fonksiyonu
    kullanmalı — byte-order dönüşümü unutulursa karşılaştırma hep başarısız olur."""
    try:
        raw = bytes(ace_obj['ObjectType'])
    except Exception:
        return None
    if not raw or len(raw) < 16:
        return None
    try:
        return (binascii.hexlify(raw[:4][::-1]).decode() + '-' +
                binascii.hexlify(raw[4:6][::-1]).decode() + '-' +
                binascii.hexlify(raw[6:8][::-1]).decode() + '-' +
                binascii.hexlify(raw[8:10]).decode() + '-' +
                binascii.hexlify(raw[10:16]).decode())
    except Exception:
        return None


# ── GPP cpassword Decrypt (MS fixed AES key) ──
def cpassword_decrypt(enc_b64):
    """Decrypt MS Group Policy Preferences cpassword (AES-256-CBC).
    Returns plaintext password or None on failure (pycryptodome required)."""
    try:
        from Cryptodome.Cipher import AES
    except ImportError:
        try:
            from Crypto.Cipher import AES
        except ImportError:
            return None
    key = binascii.unhexlify(
        "4e9906e8fcb66cc9faf49310620ffee8"
        "f496e806cc057990209b09a433b66c1b"
    )
    try:
        padded = base64.b64decode(enc_b64)
        iv = padded[:16]
        ciphertext = padded[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        plain = cipher.decrypt(ciphertext)
        pad_len = plain[-1]
        if isinstance(pad_len, int) and 1 <= pad_len <= 16:
            plain = plain[:-pad_len]
        return plain.decode("utf-16-le", errors="ignore").rstrip("\x00")
    except Exception:
        return None


# ── CVSS 3.1 Calculator ──
CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 6.42, "C": 7.52},
    "C": {"H": 0.56, "M": 0.22, "L": 0.0},
    "I": {"H": 0.56, "M": 0.22, "L": 0.0},
    "A": {"H": 0.56, "M": 0.22, "L": 0.0},
}
CVSS_SEVERITY_MAP = {  # by chain severity
    "CRITICAL": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "HIGH": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "MEDIUM": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L",
    "LOW": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
    "INFO": "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
}
CVSS_SCORES = {"CRITICAL": 9.8, "HIGH": 8.5, "MEDIUM": 5.5, "LOW": 2.3, "INFO": 0.1}

def compute_cvss31(chain_severity):
    """Return (vector_string, numerical_score) for a chain severity."""
    vector = CVSS_SEVERITY_MAP.get(chain_severity, CVSS_SEVERITY_MAP["MEDIUM"])
    score = CVSS_SCORES.get(chain_severity, 5.5)
    return vector, score


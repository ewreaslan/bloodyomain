#!/usr/bin/env python3
"""
Bloodyomain — Active Directory Enumeration & Attack Path Visualization
Full Integration: Password Spray, BloodHound Export, Shadow Credentials, DCSync Audit,
FGPP, GPO Write Permissions, AdminSDHolder, Sensitive Files, Spooler, ZeroLogon,
WinRM, Cross-Forest Trust, Exchange Permissions, Async LDAP, Remediation Snippets
"""

from bloodyomain.core import (
    # ANSI
    C,
    # Logging
    log, section, BANNER,
    # Helpers
    _escape_ldap_filter_value, dn_to_name, filetime_to_dt, days_since,
    _guid_from_ace, cpassword_decrypt,
    # Constants
    WELL_KNOWN_SIDS, DANGEROUS_ACCESS, DANGEROUS_GUIDS,
    # CVSS
    compute_cvss31, CVSS_WEIGHTS, CVSS_SEVERITY_MAP, CVSS_SCORES,
    # Optional dep flags
    LDAP3_AVAILABLE, IMPACKET_AVAILABLE, IMPACKET_LDAP, NRPC_AVAILABLE,
    security_descriptor_control,
)

from bloodyomain.connector import ADConnector, SMBEngine

# Re-export ldap3 types for test backward compatibility (mocked in tests)
try:
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, ALL_ATTRIBUTES, Tls, ANONYMOUS, SIMPLE
    from ldap3.core.exceptions import LDAPException
except ImportError:
    Server = Connection = ALL = NTLM = SUBTREE = ALL_ATTRIBUTES = Tls = ANONYMOUS = SIMPLE = None
    LDAPException = Exception

from bloodyomain.exporter import BloodHoundExporter
from bloodyomain.attack_chain import AttackChainEngine
from bloodyomain.dacl import DACLAnalyzer
from bloodyomain.enumerator import ADEnumerator
from bloodyomain.cli import main

__all__ = [
    'C', 'log', 'section', 'BANNER',
    '_escape_ldap_filter_value', 'dn_to_name', 'filetime_to_dt', 'days_since',
    '_guid_from_ace', 'cpassword_decrypt',
    'WELL_KNOWN_SIDS', 'DANGEROUS_ACCESS', 'DANGEROUS_GUIDS',
    'compute_cvss31',
    'LDAP3_AVAILABLE', 'IMPACKET_AVAILABLE', 'IMPACKET_LDAP', 'NRPC_AVAILABLE',
    'ADConnector', 'SMBEngine',
    'BloodHoundExporter',
    'AttackChainEngine',
    'DACLAnalyzer',
    'ADEnumerator',
    'main',
]

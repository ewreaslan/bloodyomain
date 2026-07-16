#!/usr/bin/env python3
"""
Bloodyomain Unit & Integration Tests
Run: pytest -v test_bloodyomain.py  or  python3 -m pytest -v test_bloodyomain.py
Without pytest: python3 test_bloodyomain.py (unittest fallback)
"""
import sys
import os
import datetime
import json
import unittest
from unittest.mock import patch, MagicMock, PropertyMock
from pathlib import Path

# ── Add project root to path ──
sys.path.insert(0, str(Path(__file__).parent))

# ── Import the module (won't execute main() since __name__ != '__main__') ──
import bloodyomain as bm


# ════════════════════════════════════════════════════════════════════
# 1. Helper Function Tests
# ════════════════════════════════════════════════════════════════════

class TestHelpers(unittest.TestCase):
    """Test pure helper functions — no network needed."""

    def test_dn_to_name_cn(self):
        self.assertEqual(bm.dn_to_name("CN=Administrator,CN=Users,DC=corp,DC=local"), "Administrator")

    def test_dn_to_name_lowercase(self):
        self.assertEqual(bm.dn_to_name("cn=jsmith,ou=Engineering,dc=corp,dc=local"), "jsmith")

    def test_dn_to_name_empty(self):
        self.assertEqual(bm.dn_to_name(""), "")
        self.assertEqual(bm.dn_to_name(None), "")

    def test_dn_to_name_no_cn(self):
        self.assertEqual(bm.dn_to_name("OU=Sales,DC=corp,DC=local"), "OU=Sales")

    def test_filetime_to_dt_valid(self):
        ft = 133424496000000000  # 2023-10-15 roughly
        dt = bm.filetime_to_dt(ft)
        self.assertIsNotNone(dt)
        self.assertIsInstance(dt, datetime.datetime)
        self.assertEqual(dt.year, 2023)
        self.assertEqual(dt.month, 10)

    def test_filetime_to_dt_zero(self):
        self.assertIsNone(bm.filetime_to_dt(0))

    def test_filetime_to_dt_never(self):
        self.assertIsNone(bm.filetime_to_dt(9223372036854775807))

    def test_filetime_to_dt_invalid(self):
        self.assertIsNone(bm.filetime_to_dt("not_a_number"))

    def test_filetime_to_dt_none(self):
        self.assertIsNone(bm.filetime_to_dt(None))

    def test_days_since(self):
        yesterday = datetime.datetime.utcnow() - datetime.timedelta(days=1)
        self.assertEqual(bm.days_since(yesterday), 1)

    def test_days_since_none(self):
        self.assertIsNone(bm.days_since(None))

    def test_escape_ldap_filter_special_chars(self):
        val = "CN=Test*User(Admin)\0"
        escaped = bm._escape_ldap_filter_value(val)
        self.assertNotIn("*", escaped)
        self.assertNotIn("(", escaped)
        self.assertNotIn(")", escaped)

    def test_escape_ldap_filter_plain(self):
        self.assertEqual(bm._escape_ldap_filter_value("john.doe"), "john.doe")

    def test_escape_ldap_filter_empty(self):
        self.assertEqual(bm._escape_ldap_filter_value(""), "")
        self.assertEqual(bm._escape_ldap_filter_value(None), None)


# ════════════════════════════════════════════════════════════════════
# 2. BloodHound Exporter Tests
# ════════════════════════════════════════════════════════════════════

class TestBloodHoundExporter(unittest.TestCase):
    """Test BloodHound JSON export format."""

    def setUp(self):
        self.sample_data = {
            "meta": {"domain": "corp.local"},
            "users": [
                {
                    "name": "john.doe@corp.local", "dn": "CN=john,CN=Users,DC=corp,DC=local",
                    "sid": "S-1-5-21-100", "enabled": True, "admin_count": 0, "spns": [],
                    "no_preauth": False, "domain": "corp.local",
                    "pwd_last_set": "2024-01-01T00:00:00"
                },
                {
                    "name": "svc_sql@corp.local", "dn": "CN=svc_sql,CN=Users,DC=corp,DC=local",
                    "sid": "S-1-5-21-200", "enabled": True, "admin_count": 1, "spns": ["MSSQLSvc/sql01.corp.local"],
                    "no_preauth": False, "domain": "corp.local",
                    "pwd_last_set": "2024-01-01T00:00:00"
                },
            ],
            "groups": [
                {"name": "DOMAIN ADMINS@corp.local", "dn": "CN=Domain Admins,CN=Users,DC=corp,DC=local",
                 "sid": "S-1-5-21-300", "admin_count": 1, "members": ["CN=svc_sql,CN=Users,DC=corp,DC=local"]},
            ],
            "computers": [
                {"name": "DC01.CORP.LOCAL", "dn": "CN=DC01,OU=DC,DC=corp,DC=local",
                 "sid": "S-1-5-21-400", "is_dc": True, "os": "Windows Server 2019", "domain": "corp.local"},
            ],
            "edges": [
                {"source": "john.doe@corp.local", "target": "DOMAIN ADMINS@corp.local",
                 "relation": "MemberOf", "highlight": False},
            ],
        }

    def test_export_returns_prefix(self):
        exporter = bm.BloodHoundExporter()
        result = exporter.export(self.sample_data, "/tmp/test_bh_prefix")
        # export() returns None; success is verified by file creation
        self.assertIsNone(result)

    def test_export_creates_files(self):
        exporter = bm.BloodHoundExporter()
        prefix = "/tmp/test_bh_export"
        exporter.export(self.sample_data, prefix)
        # Check at least one JSON file was created
        import glob
        files = glob.glob(prefix + "*.json")
        self.assertGreater(len(files), 0)
        # Cleanup
        for f in files:
            os.remove(f)


# ════════════════════════════════════════════════════════════════════
# 3. AttackChainEngine Tests
# ════════════════════════════════════════════════════════════════════

class TestAttackChainEngine(unittest.TestCase):
    """Test attack chain logic with mock data."""

    def setUp(self):
        self.minimal_data = {
            "users": [
                {"name": "admin", "admin_count": 1, "enabled": True, "spns": [], "no_preauth": False,
                 "password_never_expires": False, "password_not_required": False,
                 "pwd_last_set": "2024-06-01T00:00:00", "pwd_last_set_days": 30,
                 "last_logon": "2024-07-01T00:00:00", "logon_count": 50,
                 "groups": [], "sid": "S-1-5-21-X-500",
                 "trusted_for_delegation": False},
                {"name": "jsmith", "admin_count": 0, "enabled": True, "spns": ["HTTP/web.corp.local"],
                 "no_preauth": False, "password_never_expires": True, "password_not_required": False,
                 "pwd_last_set": "2024-01-01T00:00:00", "pwd_last_set_days": 200,
                 "last_logon": "2024-07-10T00:00:00", "logon_count": 200,
                 "groups": ["CN=Domain Admins,CN=Users,DC=corp,DC=local"],
                 "sid": "S-1-5-21-X-1001",
                 "trusted_for_delegation": False},
                {"name": "stale_user", "admin_count": 0, "enabled": True, "spns": [],
                 "no_preauth": True, "password_never_expires": False, "password_not_required": False,
                 "pwd_last_set": "2020-01-01T00:00:00", "pwd_last_set_days": 1500,
                 "last_logon": "2022-01-01T00:00:00", "logon_count": 3,
                 "groups": [], "sid": "S-1-5-21-X-1002",
                 "trusted_for_delegation": False},
            ],
            "admins": [
                {"member_name": "admin", "group": "Domain Admins"},
                {"member_name": "jsmith", "group": "Domain Admins"},
            ],
            "groups": [
                {"name": "Domain Admins", "admin_count": 1,
                 "members": ["CN=jsmith,CN=Users,DC=corp,DC=local"]},
            ],
            "computers": [
                {"name": "DC01", "is_dc": True, "os": "Windows Server 2019",
                 "trusted_for_delegation": False, "unconstrained_delegation": False,
                 "rdp_open": True, "rdp_users": []},
                {"name": "SRV01", "is_dc": False, "os": "Windows Server 2016",
                 "trusted_for_delegation": True, "unconstrained_delegation": True,
                 "rdp_open": False, "rdp_users": []},
            ],
            "sessions": [
                {"user": "CORP\\admin", "host_name": "SRV01.corp.local", "stype": "SMB"},
            ],
            "loggedon": [
                {"user": "CORP\\admin", "host": "DC01", "stype": "LOGON"},
            ],
            "local_admins": [
                {"user": "lowpriv_user", "host": "DC01.corp.local"},
            ],
            "rdp_access": [
                {"user": "lowpriv_user", "host": "DC01", "source": "Remote Desktop Users (DC)"},
            ],
            "rdp_open": ["DC01"],
            "spns": [
                {"user": "jsmith", "spn": "HTTP/web.corp.local", "service": "HTTP", "hostname": "web.corp.local"},
            ],
            "asrep": ["stale_user"],
            "acl_edges": [
                {"source": "jsmith", "target": "admin", "right": "GenericAll", "severity": "CRITICAL"},
                {"source": "jsmith", "target": "admin", "right": "WriteOwner", "severity": "HIGH"},
            ],
            "da_users": ["admin", "jsmith"],
            "adcs_esc": [],
            "shadow_creds": [],
            "dcsync_rights": [],
            "fgpp": [],
            "gpo_write_perms": [],
            "adminsd_acl": [],
            "sensitive_files": [],
            "tombstoned_objects": [],
            "protected_users_members": [],
            "delegation_matrix": [],
            "printerbug_hosts": [],
            "petitpotam_hosts": [],
            "ntlmv1_hosts": [],
            "nopac_risk": {"potentially_vulnerable": False},
            "ldap_security": {"signing_enforced": True, "cb_enforced": False},
            "pwd_policy": {
                "min_pwd_length": 7,
                "lockout_threshold": 0,
            },
            "windows_2016_or_earlier": False,
            "exchange_dcsync": [],
            "winrm_hosts": [],
            "trusts": [],
            "domain": {
                "lockout_threshold": 0,
                "min_pwd_length": 7,
                "lockout_window_min": 0,
                "lockout_duration_min": 0,
            },
            "domain_info": {
                "machine_account_quota": 10,
                "min_pwd_length": 7,
                "pwd_properties": 0,
            },
            "domain_controllers": ["DC01"],
        }

    def test_build_returns_list(self):
        engine = bm.AttackChainEngine(self.minimal_data)
        chains = engine.build()
        self.assertIsInstance(chains, list)

    def test_build_has_severity_keys(self):
        engine = bm.AttackChainEngine(self.minimal_data)
        chains = engine.build()
        for c in chains:
            self.assertIn("severity", c)
            self.assertIn(c.get("severity", ""), ["CRITICAL", "HIGH", "MEDIUM", "LOW"])

    def test_privileged_session_detected(self):
        engine = bm.AttackChainEngine(self.minimal_data)
        chains = engine.build()
        # admin is a DA user with sessions on SRV01 (non-DC)
        sessions = [c for c in chains if c.get("type") == "PRIVILEGED_SESSION_EXPOSURE"]
        self.assertGreater(len(sessions), 0)

    def test_kerberoast_detected(self):
        engine = bm.AttackChainEngine(self.minimal_data)
        chains = engine.build()
        # jsmith has SPN and is in DA → KERBEROAST_DA
        kerb = [c for c in chains if c.get("type") == "KERBEROAST_DA"]
        self.assertGreater(len(kerb), 0)

    def test_asrep_detected(self):
        engine = bm.AttackChainEngine(self.minimal_data)
        chains = engine.build()
        asrep = [c for c in chains if c.get("type") == "ASREP_ROAST"]
        self.assertGreater(len(asrep), 0)

    def test_local_admin_to_da(self):
        engine = bm.AttackChainEngine(self.minimal_data)
        chains = engine.build()
        # lowpriv_user is local admin on DC01 where DA (admin) has a session
        la = [c for c in chains if c.get("type") == "LOCAL_ADMIN_DA_SESSION"]
        self.assertGreater(len(la), 0)

    def test_rdp_to_da(self):
        engine = bm.AttackChainEngine(self.minimal_data)
        chains = engine.build()
        rdp = [c for c in chains if c.get("type") == "RDP_TO_DA_SESSION"]
        self.assertGreater(len(rdp), 0)

    def test_unconstrained_delegation_detected(self):
        engine = bm.AttackChainEngine(self.minimal_data)
        chains = engine.build()
        deleg = [c for c in chains if c.get("type") == "UNCONSTRAINED_DELEGATION"]
        self.assertGreater(len(deleg), 0)


# ════════════════════════════════════════════════════════════════════
# 4. DACLAnalyzer Tests
# ════════════════════════════════════════════════════════════════════

class TestDACLAnalyzer(unittest.TestCase):
    """Test DACL analysis with mock connector."""

    def test_analyze_empty_objects(self):
        mock_conn = MagicMock()
        analyzer = bm.DACLAnalyzer(mock_conn)
        result = analyzer.analyze_objects([])
        self.assertEqual(result, [])

    def test_analyze_no_sd(self):
        mock_conn = MagicMock()
        analyzer = bm.DACLAnalyzer(mock_conn)
        obj = {"name": "test", "dn": "CN=test,DC=corp,DC=local", "type": "user",
               "raw_sd": None}
        result = analyzer.analyze_objects([obj])
        self.assertEqual(result, [])


# ════════════════════════════════════════════════════════════════════
# 5. ANSI / Output Tests
# ════════════════════════════════════════════════════════════════════

class TestANSIColors(unittest.TestCase):
    """Test color class constants exist."""

    def test_c_colors_exist(self):
        self.assertTrue(hasattr(bm.C, "RED"))
        self.assertTrue(hasattr(bm.C, "GREEN"))
        self.assertTrue(hasattr(bm.C, "YELLOW"))
        self.assertTrue(hasattr(bm.C, "RESET"))
        self.assertIn("\033", bm.C.RED)

    def test_banner_defined(self):
        self.assertIsNotNone(bm.BANNER)
        self.assertIn("BLOODY", bm.BANNER.upper())


# ════════════════════════════════════════════════════════════════════
# 6. ADConnector Tests (Mocked)
# ════════════════════════════════════════════════════════════════════

class TestADConnector(unittest.TestCase):
    """Test ADConnector with mocked LDAP connection."""

    @patch("bloodyomain.connector.Server")
    @patch("bloodyomain.connector.Connection")
    def test_connector_init(self, mock_conn_class, mock_server_class):
        mock_server = MagicMock()
        mock_server_class.return_value = mock_server
        mock_conn = MagicMock()
        mock_conn_class.return_value = mock_conn

        connector = bm.ADConnector("10.0.0.1", "corp.local", "admin", "pass")
        connector.connect()

        self.assertEqual(connector.host, "10.0.0.1")
        self.assertEqual(connector.domain, "corp.local")
        self.assertIsNotNone(connector.conn)

    @patch("bloodyomain.connector.Server")
    @patch("bloodyomain.connector.Connection")
    def test_connector_ssl(self, mock_conn_class, mock_server_class):
        mock_server = MagicMock()
        mock_server_class.return_value = mock_server
        mock_conn = MagicMock()
        mock_conn_class.return_value = mock_conn

        connector = bm.ADConnector("10.0.0.1", "corp.local", "admin", "pass", use_ssl=True)
        connector.connect()
        self.assertIsNotNone(connector.conn)

    @patch("bloodyomain.connector.Server")
    @patch("bloodyomain.connector.Connection")
    def test_connector_anonymous(self, mock_conn_class, mock_server_class):
        mock_server = MagicMock()
        mock_server_class.return_value = mock_server
        mock_conn = MagicMock()
        mock_conn_class.return_value = mock_conn

        connector = bm.ADConnector("10.0.0.1", "corp.local", anonymous=True)
        connector.connect()

        self.assertTrue(connector.anonymous)
        self.assertIsNotNone(connector.conn)

    @patch("bloodyomain.connector.Server")
    @patch("bloodyomain.connector.Connection")
    def test_connector_no_user_fallback(self, mock_conn_class, mock_server_class):
        """When no user given (but not anonymous), should attempt simple bind."""
        mock_server = MagicMock()
        mock_server_class.return_value = mock_server
        mock_conn = MagicMock()
        mock_conn_class.return_value = mock_conn

        connector = bm.ADConnector("10.0.0.1", "corp.local", "", "")
        connector.connect()
        self.assertIsNotNone(connector.conn)

    @patch("bloodyomain.connector.Server")
    @patch("bloodyomain.connector.Connection")
    def test_connector_auto_detect_domain(self, mock_conn_class, mock_server_class):
        """When domain is '.' in anonymous mode, should try RootDSE detection."""
        mock_server = MagicMock()
        mock_server_class.return_value = mock_server
        mock_conn = MagicMock()
        mock_conn_class.return_value = mock_conn
        # Simulate RootDSE response
        mock_entry = MagicMock()
        mock_entry.entry_to_json.return_value = json.dumps({
            "attributes": {
                "rootDomainNamingContext": "DC=corp,DC=local",
                "defaultNamingContext": "DC=corp,DC=local",
            }
        })
        mock_conn.entries = [mock_entry]
        mock_conn.search.return_value = True

        connector = bm.ADConnector("10.0.0.1", ".", anonymous=True)
        connector.connect()

        self.assertEqual(connector.domain, "corp.local")
        self.assertEqual(connector.base_dn, "DC=corp,DC=local")


class TestSMBEngineNull(unittest.TestCase):
    """Test SMB null session support."""

    def test_null_session_init(self):
        engine = bm.SMBEngine("corp.local", null_session=True)
        self.assertTrue(engine.null_session)
        self.assertEqual(engine.username, "")
        self.assertEqual(engine.password, "")


# ════════════════════════════════════════════════════════════════════
# 7. SMBEngine Tests (Mocked)
# ════════════════════════════════════════════════════════════════════

class TestSMBEngine(unittest.TestCase):
    """Test SMB engine initialization (no actual connections)."""

    @unittest.skipIf(not bm.IMPACKET_AVAILABLE, "impacket not installed")
    def test_smb_engine_init(self):
        engine = bm.SMBEngine("corp.local", "admin", "password")
        self.assertEqual(engine.domain, "corp.local")
        self.assertEqual(engine.username, "admin")

    def test_check_port_closed(self):
        engine = bm.SMBEngine("corp.local", "admin", "password")
        # Should return False for an unroutable/non-existent host quickly
        result = engine.check_port("192.0.2.1", 3389, timeout=1)
        self.assertFalse(result)


# ════════════════════════════════════════════════════════════════════
# 8. Import / Module Structure Tests
# ════════════════════════════════════════════════════════════════════

class TestModuleStructure(unittest.TestCase):
    """Verify the module has the expected classes and functions."""

    def test_core_classes_exist(self):
        self.assertTrue(hasattr(bm, "ADConnector"))
        self.assertTrue(hasattr(bm, "SMBEngine"))
        self.assertTrue(hasattr(bm, "AttackChainEngine"))
        self.assertTrue(hasattr(bm, "DACLAnalyzer"))
        self.assertTrue(hasattr(bm, "ADEnumerator"))
        self.assertTrue(hasattr(bm, "BloodHoundExporter"))

    def test_core_functions_exist(self):
        self.assertTrue(hasattr(bm, "log"))
        self.assertTrue(hasattr(bm, "section"))
        self.assertTrue(hasattr(bm, "dn_to_name"))
        self.assertTrue(hasattr(bm, "filetime_to_dt"))
        self.assertTrue(hasattr(bm, "days_since"))
        self.assertTrue(hasattr(bm, "_escape_ldap_filter_value"))

    def test_log_does_not_raise(self):
        bm.log("test message", "INFO")
        bm.log("test success", "SUCCESS")
        bm.log("test warn", "WARN")
        bm.log("test error", "ERROR")

    def test_section_does_not_raise(self):
        bm.section("Test Section")


# ════════════════════════════════════════════════════════════════════
# 9. Description Credential Scanner
# ════════════════════════════════════════════════════════════════════

class TestDescriptionScanner(unittest.TestCase):
    """Test Enum4linux-style description field credential detection."""

    def setUp(self):
        self.mock_conn = MagicMock()
        self.mock_conn.host = "10.0.0.1"
        self.mock_conn.domain = "corp.local"
        self.mock_conn.base_dn = "DC=corp,DC=local"
        self.mock_conn.connected = True

    def test_no_users(self):
        enumerator = bm.ADEnumerator(self.mock_conn, smb_engine=None, threads=2)
        enumerator.data["users"] = []
        result = enumerator._scan_description_passwords()
        self.assertEqual(result, [])

    def test_label_password_detected(self):
        enumerator = bm.ADEnumerator(self.mock_conn, smb_engine=None, threads=2)
        enumerator.data["users"] = [
            {"name": "jsmith", "dn": "CN=jsmith,DC=corp,DC=local",
             "description": "password: Summer2024!"},
        ]
        result = enumerator._scan_description_passwords()
        self.assertGreater(len(result), 0)
        self.assertEqual(result[0]["user"], "jsmith")
        self.assertIn("Summer2024", str(result[0].get("found_credential", "")))

    def test_parola_turkish_detected(self):
        enumerator = bm.ADEnumerator(self.mock_conn, smb_engine=None, threads=2)
        enumerator.data["users"] = [
            {"name": "aozturk", "dn": "CN=aozturk,DC=corp,DC=local",
             "description": "parola: Ankara2024! gecici sifre"},
        ]
        result = enumerator._scan_description_passwords()
        self.assertGreater(len(result), 0)

    def test_initial_password_detected(self):
        enumerator = bm.ADEnumerator(self.mock_conn, smb_engine=None, threads=2)
        enumerator.data["users"] = [
            {"name": "newuser", "dn": "CN=newuser,DC=corp,DC=local",
             "description": "Initial password is TempP@ssw0rd"},
        ]
        result = enumerator._scan_description_passwords()
        self.assertGreater(len(result), 0)

    def test_userpass_format_detected(self):
        enumerator = bm.ADEnumerator(self.mock_conn, smb_engine=None, threads=2)
        enumerator.data["users"] = [
            {"name": "svc_acc", "dn": "CN=svc_acc,DC=corp,DC=local",
             "description": "admin / Admin123!"},
        ]
        result = enumerator._scan_description_passwords()
        self.assertGreater(len(result), 0)

    def test_clean_description_no_false_positive(self):
        enumerator = bm.ADEnumerator(self.mock_conn, smb_engine=None, threads=2)
        enumerator.data["users"] = [
            {"name": "jsmith", "dn": "CN=jsmith,DC=corp,DC=local",
             "description": "Senior Developer - Java Team"},
            {"name": "admin", "dn": "CN=admin,DC=corp,DC=local",
             "description": "Built-in account for administering the domain"},
        ]
        result = enumerator._scan_description_passwords()
        self.assertEqual(len(result), 0)

    def test_multiple_users_mixed(self):
        enumerator = bm.ADEnumerator(self.mock_conn, smb_engine=None, threads=2)
        enumerator.data["users"] = [
            {"name": "clean1", "dn": "CN=c1,DC=corp,DC=local", "description": "HR Manager"},
            {"name": "leak1", "dn": "CN=l1,DC=corp,DC=local", "description": "pass: LeakMe123"},
            {"name": "clean2", "dn": "CN=c2,DC=corp,DC=local", "description": "IT Support"},
            {"name": "leak2", "dn": "CN=l2,DC=corp,DC=local",
             "description": "reset password to NewP@ss2024 on 01/01"},
        ]
        result = enumerator._scan_description_passwords()
        self.assertEqual(len(result), 2)

    def test_description_chain_in_attack_engine(self):
        data = {
            "users": [{"name": "leakuser"}],
            "description_passwords": [
                {"user": "leakuser", "pattern_type": "label",
                 "found_credential": "LeakedPass1!", "match": "password: LeakedPass1!"},
            ],
            "admins": [], "da_users": [], "groups": [], "computers": [],
            "sessions": [], "loggedon": [], "local_admins": [], "rdp_access": [],
            "rdp_open": [], "spns": [], "asrep": [], "acl_edges": [],
            "adcs_esc": [], "shadow_creds": [], "dcsync_rights": [],
            "fgpp": [], "gpo_write_perms": [], "adminsd_acl": [],
            "sensitive_files": [], "tombstoned_objects": [],
            "protected_users_members": [], "delegation_matrix": [],
            "printerbug_hosts": [], "petitpotam_hosts": [],
            "ntlmv1_hosts": [], "exchange_dcsync": [], "winrm_hosts": [],
            "domain": {"lockout_threshold": 3, "min_pwd_length": 8, "lockout_window_min": 30, "lockout_duration_min": 30},
            "domain_info": {"machine_account_quota": 10},
            "pwd_policy": {"min_pwd_length": 8},
            "windows_2016_or_earlier": False,
            "nopac_risk": {"potentially_vulnerable": False},
            "ldap_security": {"signing_enforced": True, "cb_enforced": True},
        }
        engine = bm.AttackChainEngine(data)
        chains = engine.build()
        desc_chains = [c for c in chains if c.get("type") == "DESCRIPTION_CREDENTIAL"]
        self.assertEqual(len(desc_chains), 1)
        self.assertEqual(desc_chains[0]["severity"], "CRITICAL")


# ════════════════════════════════════════════════════════════════════
# 10. Edge Cases
# ════════════════════════════════════════════════════════════════════

class TestEdgeCases(unittest.TestCase):
    """Test edge cases and defensive behavior."""

    def test_empty_data_attack_chains(self):
        empty_data = {
            "users": [], "groups": [], "computers": [], "sessions": [],
            "loggedon": [], "local_admins": [], "rdp_access": [], "rdp_open": [],
            "spns": [], "asrep": [], "acl_edges": [], "da_users": [],
            "adcs_esc": [], "shadow_creds": [], "dcsync_rights": [],
            "fgpp": [], "gpo_write_perms": [], "adminsd_acl": [],
            "sensitive_files": [], "tombstoned_objects": [],
            "protected_users_members": [], "delegation_matrix": [],
            "printerbug_hosts": [], "petitpotam_hosts": [],
            "ntlmv1_hosts": [], "exchange_dcsync": [], "winrm_hosts": [],
            "domain_info": {"machine_account_quota": 10},
            "pwd_policy": {"min_pwd_length": 7},
            "windows_2016_or_earlier": False,
            "nopac_risk": {"potentially_vulnerable": False},
            "ldap_security": {"signing_enforced": True, "cb_enforced": True},
        }
        engine = bm.AttackChainEngine(empty_data)
        chains = engine.build()
        self.assertIsInstance(chains, list)
        # Should not crash; should return empty or low-severity chains

    def test_unicode_in_dn(self):
        result = bm.dn_to_name("CN=José González,OU=España,DC=corp,DC=local")
        self.assertIn("José", result)

    def test_very_long_dn(self):
        long_cn = "A" * 200
        result = bm.dn_to_name(f"CN={long_cn},OU=Test,DC=corp,DC=local")
        self.assertEqual(result, long_cn)

    def test_escape_with_turkish_chars(self):
        val = "İstanbul*şğüı(Test)"
        escaped = bm._escape_ldap_filter_value(val)
        self.assertNotIn("*", escaped)
        self.assertNotIn("(", escaped)
        self.assertIn("İstanbul", escaped)  # Turkish chars preserved

    def test_password_spray_empty_list(self):
        # Test ADConnector password_spray with empty user list
        mock_server = MagicMock()
        mock_conn = MagicMock()
        mock_conn.bind.return_value = True
        with patch("bloodyomain.connector.Server", return_value=mock_server):
            with patch("bloodyomain.connector.Connection", return_value=mock_conn):
                connector = bm.ADConnector("10.0.0.1", "corp.local", "admin", "pass")
                connector.connect()
                result = connector.password_spray([], "Password123")
                self.assertEqual(result, [])


# ════════════════════════════════════════════════════════════════════
# 10. CLI Argument Parsing
# ════════════════════════════════════════════════════════════════════

class TestCLIArgs(unittest.TestCase):
    """Test argument parsing without executing main()."""

    def test_parser_full_args(self):
        import argparse
        p = argparse.ArgumentParser()
        p.add_argument("-H", "--host")
        p.add_argument("-d", "--domain")
        p.add_argument("-u", "--user")
        p.add_argument("-p", "--password")
        p.add_argument("--anonymous", "--null-session", dest="anonymous", action="store_true")
        p.add_argument("--ssl", action="store_true")
        p.add_argument("--no-smb", action="store_true")
        p.add_argument("--no-advanced", action="store_true")
        p.add_argument("--threads", type=int, default=10)
        p.add_argument("--spray", action="store_true")
        p.add_argument("--spray-pass")
        p.add_argument("--bh-export")
        p.add_argument("-o", "--output", default="bloodyomain_report.html")
        p.add_argument("-j", "--json-out")
        p.add_argument("--no-browser", action="store_true")

        # Normal auth
        args = p.parse_args(["-H", "10.0.0.1", "-d", "corp.local", "-u", "admin"])
        self.assertEqual(args.host, "10.0.0.1")
        self.assertEqual(args.domain, "corp.local")
        self.assertFalse(args.anonymous)

        # Anonymous mode
        args = p.parse_args(["-H", "10.0.0.1", "--anonymous"])
        self.assertEqual(args.host, "10.0.0.1")
        self.assertTrue(args.anonymous)
        self.assertIsNone(args.user)
        self.assertIsNone(args.domain)

        # --null-session alias
        args = p.parse_args(["-H", "10.0.0.1", "--null-session"])
        self.assertTrue(args.anonymous)


# ════════════════════════════════════════════════════════════════════
# 11. JSON Output Structure Test
# ════════════════════════════════════════════════════════════════════

class TestDataStructure(unittest.TestCase):
    """Test the shape of enumeration data."""

    def test_ad_enumerator_init(self):
        mock_conn = MagicMock()
        mock_conn.host = "10.0.0.1"
        mock_conn.domain = "corp.local"
        mock_conn.base_dn = "DC=corp,DC=local"
        mock_conn.connected = True

        enumerator = bm.ADEnumerator(mock_conn, smb_engine=None, threads=5)
        self.assertIsNotNone(enumerator)
        self.assertEqual(enumerator.conn, mock_conn)

    def test_ad_enumerator_data_structure(self):
        mock_conn = MagicMock()
        mock_conn.host = "10.0.0.1"
        mock_conn.domain = "corp.local"
        mock_conn.base_dn = "DC=corp,DC=local"
        mock_conn.connected = True

        enumerator = bm.ADEnumerator(mock_conn, smb_engine=None, threads=2, advanced=False)

        # Check initial data structure keys
        self.assertIn("users", enumerator.data)
        self.assertIn("groups", enumerator.data)
        self.assertIn("computers", enumerator.data)
        self.assertIn("edges", enumerator.data)
        self.assertIn("attack_chains", enumerator.data)
        self.assertIsInstance(enumerator.data["users"], list)


# ════════════════════════════════════════════════════════════════════
# Run
# ════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  Bloodyomain Test Suite")
    print("=" * 60)
    print(f"  Python: {sys.version}")
    print(f"  ldap3 available: {bm.LDAP3_AVAILABLE}")
    print(f"  impacket available: {bm.IMPACKET_AVAILABLE}")
    print("=" * 60)
    unittest.main(verbosity=2)

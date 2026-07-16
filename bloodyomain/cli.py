#!/usr/bin/env python3
"""Command-line entry point for Bloodyomain."""
import sys
import json
import argparse
import getpass
from pathlib import Path
from bloodyomain.core import BANNER, log, LDAP3_AVAILABLE, IMPACKET_AVAILABLE
from bloodyomain.connector import ADConnector, SMBEngine
from bloodyomain.enumerator import ADEnumerator
from bloodyomain.exporter import BloodHoundExporter

def main():
    p = argparse.ArgumentParser(description="Bloodyomain - Advanced AD Audit")
    p.add_argument("-H", "--host", help="LDAP server IP or hostname")
    p.add_argument("-d", "--domain", help="Domain name (e.g. corp.local) — optional with --anonymous")
    p.add_argument("-u", "--user", help="Username for authentication — optional with --anonymous")
    p.add_argument("-p", "--password", help="Password (or prompt if omitted)")
    p.add_argument("--anonymous", "--null-session", action="store_true", dest="anonymous",
                   help="Anonymous / null session bind (no credentials needed)")
    p.add_argument("--ssl", action="store_true", help="Use LDAPS (port 636)")
    p.add_argument("--no-smb", action="store_true", help="Skip SMB enumeration")
    p.add_argument("--no-advanced", action="store_true", help="Skip advanced checks (FGPP, Shadow, DCSync, etc.)")
    p.add_argument("--threads", type=int, default=10, help="Number of threads for SMB/LDAP")
    p.add_argument("--spray", action="store_true", help="Perform password spray")
    p.add_argument("--spray-pass", help="Password to spray")
    p.add_argument("--bh-export", help="BloodHound JSON export prefix")
    p.add_argument("-o", "--output", default="bloodyomain_report.html", help="(deprecated) Use viewer/ instead — JSON auto-written to viewer/public/data.json")
    p.add_argument("-j", "--json-out", help="Save raw JSON data")
    p.add_argument("--no-browser", action="store_true", help="Suppress viewer launch hint")
    p.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication (KRB5CCNAME)")
    p.add_argument("--export-netexec", help="Export NetExec target list")
    p.add_argument("--export-impacket", help="Export Impacket command templates")
    p.add_argument("--export-sliver", help="Export Sliver C2 target list")
    args = p.parse_args()

    print(BANNER)

    # Validation: --host is always required
    if not args.host:
        p.error("--host is required")

    # Anonymous mode: domain and user optional
    if args.anonymous:
        args.domain = args.domain or "."
        args.user = args.user or ""
        log("Anonymous/null session mode — limited enumeration", "WARN")
    else:
        if not all([args.domain, args.user]):
            p.error("--domain and --user required (or use --anonymous for null session)")
        if not LDAP3_AVAILABLE:
            log("ldap3 module is required. pip install ldap3", "ERROR"); sys.exit(1)
    if not LDAP3_AVAILABLE:
        log("ldap3 module is required. pip install ldap3", "ERROR"); sys.exit(1)

    if args.anonymous:
        password = ""
    else:
        password = args.password or getpass.getpass(f"  Password for {args.user}: ")

    connector = ADConnector(args.host, args.domain, args.user, password,
                            use_ssl=args.ssl, anonymous=args.anonymous)
    try:
        if args.kerberos:
            connector.connect_kerberos()
        else:
            connector.connect()
        # If domain was auto-detected, update args for downstream use
        if args.anonymous and connector.domain != args.domain:
            args.domain = connector.domain
    except Exception as e:
        log(f"LDAP connection failed: {e}", "ERROR")
        sys.exit(1)

    smb = None
    if not args.no_smb:
        if IMPACKET_AVAILABLE:
            smb = SMBEngine(args.domain, args.user, password, null_session=args.anonymous)
            log("SMB engine initialized" + (" (null session)" if args.anonymous else ""), "SUCCESS")
        else:
            log("impacket not installed, SMB disabled", "WARN")

    enumerator = ADEnumerator(connector, smb, threads=args.threads, advanced=not args.no_advanced)
    data = enumerator.enumerate_all(
        smb_scan=(not args.no_smb),
        spray=args.spray,
        spray_pass=args.spray_pass,
        bh_export=args.bh_export
    )

    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(data, f, indent=2, default=str)
        log(f"JSON saved -> {args.json_out}", "SUCCESS")

    # Viewer integration: write JSON to viewer/public/data.json
    viewer_json = Path(__file__).parent.parent / "viewer" / "public" / "data.json"
    try:
        viewer_json.parent.mkdir(parents=True, exist_ok=True)
        with open(viewer_json, "w") as f:
            json.dump(data, f, indent=2, default=str)
        log(f"Viewer data -> {viewer_json}", "SUCCESS")
    except Exception as e:
        log(f"Viewer data write failed: {e}", "WARN")

    if args.export_netexec:
        BloodHoundExporter.export_netexec_targets(data, args.export_netexec)
    if args.export_impacket:
        BloodHoundExporter.export_impacket_commands(data, args.export_impacket)
    if args.export_sliver:
        BloodHoundExporter.export_sliver_targets(data, args.export_sliver)

    if not args.no_browser:
        log("Viewer data written to viewer/public/data.json", "INFO")
        log("Run: cd viewer && npm run dev   then open http://localhost:3000", "INFO")


if __name__ == "__main__":
    main()

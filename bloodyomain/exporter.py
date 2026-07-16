#!/usr/bin/env python3
"""BloodHound / NetExec / Impacket / Sliver export module."""
import json
from bloodyomain.core import log

class BloodHoundExporter:
    @staticmethod
    def export(data, prefix):
        domain = data["meta"]["domain"]
        # Users
        users = []
        for u in data.get("users", []):
            users.append({
                "ObjectIdentifier": u.get("sid"),
                "Properties": {
                    "name": u["name"],
                    "displayname": u.get("display_name", ""),
                    "enabled": u.get("enabled", False),
                    "admincount": u.get("admin_count", 0),
                    "title": u.get("description", ""),
                    "domain": domain
                }
            })
        # Groups
        groups = []
        for g in data.get("groups", []):
            groups.append({
                "ObjectIdentifier": g.get("sid"),
                "Properties": {
                    "name": g["name"],
                    "description": g.get("description", ""),
                    "admincount": g.get("admin_count", 0),
                    "domain": domain
                }
            })
        # Computers
        comps = []
        for c in data.get("computers", []):
            comps.append({
                "ObjectIdentifier": c.get("sid"),
                "Properties": {
                    "name": c["name"],
                    "dnshostname": c.get("dns", ""),
                    "operatingsystem": c.get("os", ""),
                    "domain": domain
                }
            })
        # Relationships
        rels = []
        for e in data.get("edges", []):
            rels.append({
                "Source": e["source"],
                "Target": e["target"],
                "Type": e["relation"],
                "IsInbound": False if e["relation"] in ["MemberOf", "HasSession"] else True
            })

        with open(f"{prefix}_users.json", "w") as f: json.dump(users, f, indent=2)
        with open(f"{prefix}_groups.json", "w") as f: json.dump(groups, f, indent=2)
        with open(f"{prefix}_computers.json", "w") as f: json.dump(comps, f, indent=2)
        with open(f"{prefix}_relationships.json", "w") as f: json.dump(rels, f, indent=2)
        log(f"BloodHound export -> {prefix}_*.json", "SUCCESS")

    @staticmethod
    def export_netexec_targets(data, filename):
        """Export NetExec-compatible target list."""
        lines = ["# Bloodyomain NetExec Target List", f"# {data.get('meta',{}).get('domain','?')}", ""]
        # DCs
        lines.append("# Domain Controllers (--dc-ip)")
        for c in data.get("computers", []):
            dns = c.get("dns") or c["name"]
            if c.get("is_dc"):
                lines.append(dns)
        # SMB signing off
        lines.append("\n# SMB Signing OFF (--no-sign-check)")
        for h in data.get("vuln_scan", {}).get("signing", []):
            lines.append(h)
        # WinRM
        lines.append("\n# WinRM accessible")
        for h in data.get("winrm_hosts", []):
            lines.append(h)
        # RDP
        lines.append("\n# RDP accessible")
        for h in data.get("rdp_open", []):
            lines.append(h)
        with open(filename, "w") as f:
            f.write("\n".join(lines))
        log(f"NetExec targets -> {filename}", "SUCCESS")

    @staticmethod
    def export_impacket_commands(data, filename):
        """Export Impacket command templates."""
        domain = data.get("meta", {}).get("domain", "DOMAIN")
        dc = (data.get("domain_controllers") or [data.get("meta", {}).get("target", "DC")])[0]
        lines = ["#!/bin/bash", f"# Bloodyomain Impacket Commands for {domain}", ""]
        lines.append(f"DOMAIN={domain}\nDC_IP={dc}\nUSER=USERNAME\nPASS=PASSWORD\n")
        if data.get("spns"):
            lines.append("# === Kerberoast ===")
            lines.append(f"GetUserSPNs.py $DOMAIN/$USER:$PASS -dc-ip $DC_IP -request -outputfile kerb_hashes.txt")
        if data.get("asrep"):
            lines.append(f"\n# === AS-REP Roast ===")
            lines.append(f"GetNPUsers.py $DOMAIN/$USER:$PASS -dc-ip $DC_IP -format hashcat")
        lines.append(f"\n# === DCSync ===")
        lines.append(f"secretsdump.py $DOMAIN/$USER:$PASS@$DC_IP -just-dc")
        if data.get("rdp_open"):
            lines.append(f"\n# === RDP (xfreerdp) ===")
            for h in data.get("rdp_open", [])[:3]:
                lines.append(f"xfreerdp /v:{h} /u:$USER /p:$PASS +clipboard")
        with open(filename, "w") as f:
            f.write("\n".join(lines))
        log(f"Impacket commands -> {filename}", "SUCCESS")

    @staticmethod
    def export_sliver_targets(data, filename):
        """Export Sliver C2 implant target list."""
        lines = ["# Bloodyomain Sliver Target List", ""]
        for c in data.get("computers", []):
            dns = c.get("dns") or c["name"]
            os_ver = c.get("os", "Windows")
            is_dc = c.get("is_dc", False)
            rdp = "RDP" if c.get("rdp_open") else ""
            winrm = "WinRM" if c.get("winrm_open") else ""
            lines.append(f"{dns}  # {'DC ' if is_dc else ''}{os_ver} {rdp} {winrm}")
        with open(filename, "w") as f:
            f.write("\n".join(lines))
        log(f"Sliver targets -> {filename}", "SUCCESS")


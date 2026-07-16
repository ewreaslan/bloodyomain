#!/usr/bin/env python3
"""DACL / Security Descriptor analysis."""
import base64
from bloodyomain.core import (
    log, _escape_ldap_filter_value, _guid_from_ace,
    DANGEROUS_ACCESS, DANGEROUS_GUIDS,
    IMPACKET_LDAP, security_descriptor_control,
)
if IMPACKET_LDAP:
    from impacket.ldap import ldaptypes

class DACLAnalyzer:
    def __init__(self, connector):
        self.conn = connector

    def _parse_sd(self, raw_sd, target_name, target_type):
        edges = []
        if not raw_sd or not IMPACKET_LDAP:
            return edges
        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
            if not sd['Dacl']:
                return edges
            for ace in sd['Dacl']['Data']:
                if ace['AceType'] not in (0x00, 0x05):
                    continue
                sid = ace['Ace']['Sid'].formatCanonical()
                if sid in ("S-1-5-18", "S-1-5-9", "S-1-5-32-544", "S-1-3-0"):
                    continue
                principal = self.conn.resolve_sid(sid)
                mask = int(ace['Ace']['Mask']['Mask'])

                guid = None
                if ace['AceType'] == 0x05:
                    guid = _guid_from_ace(ace['Ace'])

                if guid and guid.lower() in DANGEROUS_GUIDS:
                    right = DANGEROUS_GUIDS[guid.lower()]
                    sev = "CRITICAL" if "Replication" in right else "HIGH"
                    edges.append({"source": principal, "target": target_name,
                                  "right": right, "severity": sev,
                                  "description": f"{principal} has {right} on {target_name}"})
                else:
                    # DÜZELTME: Eski break ile ilk eşleşen haktan sonra duruluyordu.
                    # Aynı ACE'de GenericAll+WriteDACL gibi birden fazla hak varsa
                    # ikincisi raporlanmıyordu (eksik raporlama / FN).
                    # GenericAll varsa diğerlerini kapsadığından sadece o raporlanır;
                    # yoksa eşleşen TÜM haklar ayrı edge olarak eklenir.
                    matched = [right for m, right in DANGEROUS_ACCESS.items() if mask & m == m]
                    if "GenericAll" in matched:
                        matched = ["GenericAll"]
                    for right in matched:
                        sev = "CRITICAL" if right == "GenericAll" else "HIGH"
                        edges.append({"source": principal, "target": target_name,
                                      "right": right, "severity": sev,
                                      "description": f"{principal} has {right} on {target_name} ({target_type})"})
        except Exception:
            pass
        return edges

    def analyze_objects(self, objects):
        edges = []
        if not IMPACKET_LDAP:
            return edges
        sd_control = security_descriptor_control(sdflags=0x04)
        for obj in objects:
            try:
                escaped_dn = _escape_ldap_filter_value(obj['dn'])
                res = self.conn.search(f"(distinguishedName={escaped_dn})",
                                       attrs=["nTSecurityDescriptor"], controls=sd_control)
                if not res: continue
                raw = res[0].get("attributes", {}).get("nTSecurityDescriptor")
                if isinstance(raw, list):
                    raw = raw[0] if raw else None
                if isinstance(raw, str):
                    try:
                        raw = base64.b64decode(raw)
                    except Exception:
                        raw = None
                edges.extend(self._parse_sd(raw, obj["name"], obj["type"]))
            except Exception:
                pass
        seen, uniq = set(), []
        for e in edges:
            k = (e["source"], e["target"], e["right"])
            if k not in seen:
                seen.add(k); uniq.append(e)
        return uniq

#!/usr/bin/env python3
"""
Convert /Users/simon/2026_iOS_Spyware_IOC_List.csv into:
  1. MVT-compatible STIX2 bundle (.stix2)
  2. Nextron THOR YAML IOC file (.yml)
  3. Nextron THOR simple IOC files (.txt) for legacy support
"""

import csv
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

CSV_PATH = Path('/Users/simon/2026_iOS_Spyware_IOC_List.csv')
OUT_DIR = Path('/Users/simon')

# Output files
MVT_STIX2 = OUT_DIR / '2026_iOS_Spyware_IOCs_MVT.stix2'
THOR_YAML = OUT_DIR / '2026_iOS_Spyware_IOCs_THOR.yml'
THOR_SIMPLE_DIR = OUT_DIR / '2026_iOS_Spyware_IOCs_THOR_simple'

REPORT_PATH = Path('/Users/simon/2026_iOS_Spyware_IOC_Report.md')

# Reference URLs to embed in STIX/THOR metadata
REFERENCES = [
    "https://citizenlab.ca",
    "https://docs.mvt.re/en/latest/iocs/",
    "https://www.amnesty.org/en/tech/",
    "https://cloud.google.com/blog/topics/threat-intelligence/",
    "https://www.iverify.com/blog",
    "https://www.lookout.com/threat-intelligence",
    "https://securelist.com",
    "https://report-uri.com/blog",
    "https://socket.dev/blog",
    "https://zimperium.com/blog",
    "https://censys.io",
    "https://www.nextron-systems.com/thor/"
]


def now_utc():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def stix_escape(value: str) -> str:
    # STIX 2.1 single-quoted strings escape ' as ''
    return value.replace("'", "''")


def is_ipv4(value: str) -> bool:
    parts = value.split('.')
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def is_ipv6(value: str) -> bool:
    # Basic IPv6 check: contains : and no dots
    return ':' in value and '.' not in value


def basename_from_path(path: str) -> str:
    # For /private/var/tmp/filename -> filename
    return path.rstrip('/').split('/')[-1] if '/' in path else path


def normalize_domain(value: str) -> str:
    # Strip defanging brackets if present, e.g. example[.]com -> example.com
    return value.replace('[', '').replace(']', '').strip().lower()


def normalize_url(value: str) -> str:
    return value.replace('[', '').replace(']', '').strip()


def sanitize_thor_description(desc: str) -> str:
    # Remove chars that could break YAML/CSV line parsing; keep it ASCII-ish
    desc = desc.replace('\n', ' ').replace('\r', ' ')
    # YAML safe-ish: avoid leading special chars, keep under reasonable length
    if len(desc) > 200:
        desc = desc[:197] + '...'
    return desc.strip()


def safe_csv_field(value: str) -> str:
    # Simple CSV escaping for simple IOC files
    value = value.replace('\n', ' ').replace('\r', ' ').strip()
    if ';' in value:
        value = f'"{value}"'
    return value


def strip_port(host: str) -> str:
    # Remove :port from a host:port string; return host unchanged if no port
    if ':' in host:
        # IPv6 addresses in URLs are wrapped in [] – keep them intact
        if host.startswith('['):
            end = host.find(']')
            if end != -1:
                return host[:end + 1]
        else:
            return host.rsplit(':', 1)[0]
    return host


def read_csv():
    rows = []
    with CSV_PATH.open('r', encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def build_stix2_bundle(rows):
    bundle_id = f"bundle--{uuid.uuid4()}"
    identity_id = f"identity--{uuid.uuid4()}"
    objects = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now_utc(),
            "modified": now_utc(),
            "name": "OpenCode iOS Spyware IOC Feed",
            "description": "iOS-only malware/spyware IOCs compiled from 2026 public/OSINT sources including Citizen Lab, iVerify, Lookout, Google GTIG, Kaspersky, Censys, Socket Security, and SlowMist.",
            "identity_class": "organization"
        }
    ]

    seen_patterns = set()
    skipped = []

    ioc_type_map = {
        'Domain': 'domain',
        'IP': 'ip',
        'URL': 'url',
        'SHA256': 'sha256',
        'MD5': 'md5',
        'FilePath': 'filepath',
        'BundleID': 'bundleid',
        'Process': 'process',
        'CVE': 'cve',
        'C2_URL': 'url',
        'C2': 'domain',
        'C2_Domain': 'domain',
        'C2_IP': 'ip',
    }

    for idx, row in enumerate(rows, start=1):
        malware = row.get('Malware', '').strip()
        ioc_type = row.get('IOC_Type', '').strip()
        indicator = row.get('Indicator', '').strip()
        description = sanitize_thor_description(row.get('Description', ''))
        source = row.get('Source', '').strip()

        if not indicator or not ioc_type:
            continue

        # Skip non-actionable IOC types for STIX
        if ioc_type not in ioc_type_map:
            skipped.append((malware, ioc_type, indicator))
            continue

        pattern = None
        stix_type = ioc_type_map[ioc_type]

        if stix_type == 'domain':
            val = normalize_domain(indicator)
            pattern = f"[domain-name:value = '{stix_escape(val)}']"
        elif stix_type == 'ip':
            if is_ipv4(indicator):
                pattern = f"[ipv4-addr:value = '{stix_escape(indicator)}']"
            elif is_ipv6(indicator):
                pattern = f"[ipv6-addr:value = '{stix_escape(indicator)}']"
            else:
                # Could be a CIDR or hostname masquerading as IP; treat as domain
                pattern = f"[domain-name:value = '{stix_escape(indicator)}']"
        elif stix_type == 'url':
            val = normalize_url(indicator)
            pattern = f"[url:value = '{stix_escape(val)}']"
        elif stix_type == 'sha256':
            pattern = f"[file:hashes.'SHA-256' = '{stix_escape(indicator.lower())}']"
        elif stix_type == 'md5':
            pattern = f"[file:hashes.MD5 = '{stix_escape(indicator.lower())}']"
        elif stix_type == 'filepath':
            # Use file:name for the basename to maximize detection coverage
            name = basename_from_path(indicator)
            if name:
                pattern = f"[file:name = '{stix_escape(name)}']"
        elif stix_type == 'bundleid':
            pattern = f"[software:name = '{stix_escape(indicator)}']"
        elif stix_type == 'process':
            pattern = f"[process:name = '{stix_escape(indicator)}']"
        elif stix_type == 'cve':
            # CVEs are added as Vulnerability objects, not Indicator patterns
            vuln_id = f"vulnerability--{uuid.uuid4()}"
            objects.append({
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": vuln_id,
                "created": now_utc(),
                "modified": now_utc(),
                "name": indicator,
                "description": f"{malware}: {description} (Source: {source})",
                "external_references": [
                    {
                        "source_name": "cve",
                        "external_id": indicator
                    }
                ]
            })
            continue

        if not pattern:
            skipped.append((malware, ioc_type, indicator))
            continue

        # De-duplicate identical patterns
        if pattern in seen_patterns:
            continue
        seen_patterns.add(pattern)

        indicator_id = f"indicator--{uuid.uuid4()}"
        label = f"{malware} {ioc_type}"
        ext_ref = {
            "source_name": source or "OpenCode",
            "description": description,
        }
        if "Citizen Lab" in source:
            ext_ref["url"] = "https://citizenlab.ca"
        elif "MVT" in source:
            ext_ref["url"] = "https://docs.mvt.re"
        elif "Google" in source:
            ext_ref["url"] = "https://cloud.google.com/blog/topics/threat-intelligence/"
        elif "iVerify" in source:
            ext_ref["url"] = "https://www.iverify.com/blog"
        elif "Lookout" in source:
            ext_ref["url"] = "https://www.lookout.com/threat-intelligence"
        elif "Kaspersky" in source:
            ext_ref["url"] = "https://securelist.com"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now_utc(),
            "modified": now_utc(),
            "created_by_ref": identity_id,
            "name": label,
            "description": f"{malware} {ioc_type}: {description} (Source: {source})",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now_utc(),
            "indicator_types": ["malicious-activity"],
            "external_references": [ext_ref]
        })

    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects
    }
    return bundle, skipped


def build_thor_yaml(rows):
    hashes_md5 = []
    hashes_sha256 = []
    c2s = []
    files = []

    for row in rows:
        malware = row.get('Malware', '').strip()
        ioc_type = row.get('IOC_Type', '').strip()
        indicator = row.get('Indicator', '').strip()
        description = sanitize_thor_description(row.get('Description', ''))
        source = row.get('Source', '').strip()

        if not indicator:
            continue

        if ioc_type in ('MD5',):
            hashes_md5.append((indicator.lower(), description, malware, source))
        elif ioc_type in ('SHA256',):
            hashes_sha256.append((indicator.lower(), description, malware, source))
        elif ioc_type in ('Domain', 'C2', 'C2_Domain'):
            val = normalize_domain(indicator)
            if val:
                c2s.append((val, description, malware, source))
        elif ioc_type in ('IP', 'C2_IP'):
            c2s.append((indicator, description, malware, source))
        elif ioc_type in ('URL', 'C2_URL'):
            val = normalize_url(indicator)
            # Extract host for C2 matching if desired, but URL IOCs are not in THOR YAML schema
            # We'll add domain portion to c2s if parseable
            try:
                host = urlparse(val).netloc
                if host:
                    c2s.append((host, f"URL: {description}", malware, source))
            except Exception:
                pass
        elif ioc_type == 'FilePath':
            # For THOR filename IOCs, use the full path as plain string or regex basename
            val = indicator.rstrip('/')
            files.append((val, description, malware, source))
        elif ioc_type == 'BundleID':
            # Bundle IDs aren't a native THOR IOC type; skip in YAML
            pass
        elif ioc_type == 'Process':
            # Process names map to filename IOCs (THOR filename IOCs apply broadly)
            files.append((indicator, description, malware, source))

    def yaml_escape(s: str) -> str:
        # Always quote descriptions for safety; escape backslashes and double quotes
        s = s.replace('\\', '\\\\').replace('"', '\\"')
        return f'"{s}"'

    lines = []
    lines.append(f"title: \"2026 iOS Spyware and Malware IOCs\"")
    lines.append(f"id: {uuid.uuid4()}")
    lines.append(f"description: \"iOS-only malware and spyware IOCs compiled from 2026 public/OSINT sources. Covers Pegasus, Predator, Candiru/AdFection, Coruna, DarkSword/P7, SparkCat/SparkKitty, FakeWallet, Packagist, Graphite, Operation Triangulation, and related CVEs.\"")
    lines.append(f"date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}")
    lines.append(f"modified: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}")
    lines.append(f"version: \"2.0.1\"")
    lines.append(f"tags:")
    lines.append(f"  - ios")
    lines.append(f"  - spyware")
    lines.append(f"  - mobile")
    lines.append(f"  - 2026")
    lines.append(f"references:")
    for ref in REFERENCES:
        lines.append(f"  - {ref}")

    lines.append(f"iocs:")

    # Hashes
    if hashes_md5 or hashes_sha256:
        lines.append(f"  hashes:")
        for h, desc, malware, source in sorted(set(hashes_md5)):
            lines.append(f"    - value: {h}")
            lines.append(f"      score: 80")
            lines.append(f"      description: {yaml_escape(f'{malware} MD5 - {desc} (Source: {source})')}")
        for h, desc, malware, source in sorted(set(hashes_sha256)):
            lines.append(f"    - value: {h}")
            lines.append(f"      score: 80")
            lines.append(f"      description: {yaml_escape(f'{malware} SHA256 - {desc} (Source: {source})')}")

    # C2s (domains + IPs)
    if c2s:
        lines.append(f"  c2s:")
        for val, desc, malware, source in sorted(set(c2s)):
            lines.append(f"    - value: {yaml_escape(val)}")
            lines.append(f"      score: 75")
            lines.append(f"      description: {yaml_escape(f'{malware} C2 - {desc} (Source: {source})')}")

    # Files
    if files:
        lines.append(f"  files:")
        for val, desc, malware, source in sorted(set(files)):
            # Decide if plain or regex: if path contains regex metacharacters or looks like absolute path, use regex
            if re.search(r'[.*?+^$\[\](){}|]', val):
                typ = 'regex'
            else:
                typ = 'plain'
            lines.append(f"    - value: {yaml_escape(val)}")
            lines.append(f"      type: {typ}")
            lines.append(f"      score: 70")
            lines.append(f"      description: {yaml_escape(f'{malware} file/process indicator - {desc} (Source: {source})')}")

    return '\n'.join(lines) + '\n'


def build_thor_simple_files(rows):
    THOR_SIMPLE_DIR.mkdir(parents=True, exist_ok=True)

    domains = set()
    ips = set()
    hashes_md5 = set()
    hashes_sha256 = set()
    filenames = set()

    for row in rows:
        malware = row.get('Malware', '').strip()
        ioc_type = row.get('IOC_Type', '').strip()
        indicator = row.get('Indicator', '').strip()
        description = sanitize_thor_description(row.get('Description', ''))
        source = row.get('Source', '').strip()

        if not indicator:
            continue

        if ioc_type in ('Domain', 'C2', 'C2_Domain'):
            val = normalize_domain(indicator)
            if val:
                domains.add((val, f"{malware}: {description} (Source: {source})"))
        elif ioc_type == 'IP':
            ips.add((indicator, f"{malware}: {description} (Source: {source})"))
        elif ioc_type == 'URL':
            val = normalize_url(indicator)
            try:
                host = strip_port(urlparse(val).netloc)
                if host:
                    domains.add((host, f"{malware} URL host: {description} (Source: {source})"))
            except Exception:
                pass
        elif ioc_type == 'C2_URL':
            val = normalize_url(indicator)
            try:
                host = strip_port(urlparse(val).netloc)
                if host:
                    domains.add((host, f"{malware} C2 URL host: {description} (Source: {source})"))
            except Exception:
                pass
        elif ioc_type == 'MD5':
            hashes_md5.add((indicator.lower(), f"{malware}: {description} (Source: {source})"))
        elif ioc_type == 'SHA256':
            hashes_sha256.add((indicator.lower(), f"{malware}: {description} (Source: {source})"))
        elif ioc_type in ('FilePath', 'Process'):
            filenames.add((indicator, f"{malware}: {description} (Source: {source})"))

    # C2 simple IOC file
    c2_path = THOR_SIMPLE_DIR / 'iOS_Spyware_c2_iocs.txt'
    with c2_path.open('w', encoding='utf-8') as f:
        f.write("# 2026 iOS Spyware C2/Domain IOCs for Nextron THOR\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}\n")
        f.write("# Format: <domain/IP>;score;description\n\n")
        for val, desc in sorted(domains):
            f.write(f"{safe_csv_field(val)};75;{safe_csv_field(desc)}\n")
        for val, desc in sorted(ips):
            f.write(f"{safe_csv_field(val)};75;{safe_csv_field(desc)}\n")

    # Hash simple IOC file
    hash_path = THOR_SIMPLE_DIR / 'iOS_Spyware_hash_iocs.txt'
    with hash_path.open('w', encoding='utf-8') as f:
        f.write("# 2026 iOS Spyware Hash IOCs for Nextron THOR\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}\n")
        f.write("# Format: <hash>;score;description\n\n")
        for h, desc in sorted(hashes_md5):
            f.write(f"{safe_csv_field(h)};80;{safe_csv_field('MD5: ' + desc)}\n")
        for h, desc in sorted(hashes_sha256):
            f.write(f"{safe_csv_field(h)};80;{safe_csv_field('SHA256: ' + desc)}\n")

    # Filename simple IOC file
    fn_path = THOR_SIMPLE_DIR / 'iOS_Spyware_filename_iocs.txt'
    with fn_path.open('w', encoding='utf-8') as f:
        f.write("# 2026 iOS Spyware Filename/Process IOCs for Nextron THOR\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}\n")
        f.write("# Format: <pattern>;score;description\n\n")
        for val, desc in sorted(filenames):
            f.write(f"{safe_csv_field(val)};70;{safe_csv_field(desc)}\n")

    return c2_path, hash_path, fn_path


def update_report():
    if not REPORT_PATH.exists():
        return False

    text = REPORT_PATH.read_text(encoding='utf-8')

    # Add conversion note in Section 15 if not already present
    marker = "The IOCs are also available in the following scanner-ready formats"
    if marker in text:
        return False

    old_block = "A structured CSV version of the full IOC list is available at:\n**`/Users/simon/2026_iOS_Spyware_IOC_List.csv`**"
    new_block = (
        "A structured CSV version of the full IOC list is available at:\n"
        "**`/Users/simon/2026_iOS_Spyware_IOC_List.csv`**\n\n"
        "The IOCs are also available in the following scanner-ready formats:\n"
        "- **MVT (Mobile Verification Toolkit) STIX2 bundle:** `/Users/simon/2026_iOS_Spyware_IOCs_MVT.stix2`\n"
        "  - Use with: `mvt-ios check-backup --iocs ~/iocs/2026_iOS_Spyware_IOCs_MVT.stix2 --output /path/to/output /path/to/backup`\n"
        "- **Nextron THOR YAML IOC file:** `/Users/simon/2026_iOS_Spyware_IOCs_THOR.yml`\n"
        "  - Place in `custom-signatures/iocs/` and run THOR. Covers hashes, C2 domains/IPs, and filename indicators.\n"
        "- **Nextron THOR simple IOC files:** `/Users/simon/2026_iOS_Spyware_IOCs_THOR_simple/`\n"
        "  - `iOS_Spyware_c2_iocs.txt` — domain/IP indicators\n"
        "  - `iOS_Spyware_hash_iocs.txt` — MD5/SHA256 file hashes\n"
        "  - `iOS_Spyware_filename_iocs.txt` — filename/process indicators\n"
    )

    if old_block in text:
        text = text.replace(old_block, new_block)
        REPORT_PATH.write_text(text, encoding='utf-8')
        return True
    return False


def main():
    rows = read_csv()

    # Build STIX2
    bundle, skipped = build_stix2_bundle(rows)
    with MVT_STIX2.open('w', encoding='utf-8') as f:
        json.dump(bundle, f, indent=2, ensure_ascii=False)
        f.write('\n')

    # Build THOR YAML
    yaml_content = build_thor_yaml(rows)
    with THOR_YAML.open('w', encoding='utf-8') as f:
        f.write(yaml_content)

    # Build THOR simple files
    c2_path, hash_path, fn_path = build_thor_simple_files(rows)

    # Update report
    updated = update_report()

    # Summary
    print(f"CSV rows processed: {len(rows)}")
    print(f"MVT STIX2 indicators/objects written: {len(bundle['objects'])}")
    print(f"  Skipped non-actionable IOC types: {len(skipped)}")
    print(f"THOR YAML written to: {THOR_YAML}")
    print(f"THOR simple IOCs written to:")
    print(f"  {c2_path}")
    print(f"  {hash_path}")
    print(f"  {fn_path}")
    print(f"Report updated: {updated}")

    # Print some sample skipped types
    skipped_types = {}
    for malware, ioc_type, indicator in skipped:
        skipped_types[ioc_type] = skipped_types.get(ioc_type, 0) + 1
    print(f"Skipped IOC types: {skipped_types}")


if __name__ == '__main__':
    main()

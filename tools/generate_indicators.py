#!/usr/bin/env python3
"""Regenerate the embedded package indicator array from bundled feed snapshots.

This script does not download files. Feed updates are performed by the Windows
application. Run this only when preparing a new source release with newer
bundled fallback snapshots.
"""

from __future__ import annotations

import csv
import json
import re
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
SRC = ROOT / "src"

FEEDS = {
    "Socket": {
        "file": "socket-chaindrop.csv",
        "mask": 0x1,
        "url": "https://socket.dev/api/public/supply-chain-attacks/keyv-and-cacheable-compromise/packages.csv",
    },
    "SafeDep": {
        "file": "safedep-mini-shai-hulud.csv",
        "mask": 0x2,
        "url": "https://safedep.io/ti/campaigns/mini-shai-hulud.csv",
    },
    "Wiz": {
        "file": "wiz-shai-hulud-2-packages.csv",
        "mask": 0x4,
        "url": "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv",
    },
    "Datadog": {
        "file": "datadog-keyv-malicious-packages.csv",
        "mask": 0x8,
        "url": "https://raw.githubusercontent.com/DataDog/indicators-of-compromise/refs/heads/keyv-campaign/keyv-campaign/malicious-packages.csv",
    },
    "StepSecurity": {
        "file": "chaindrop-compromised-packages.csv",
        "mask": 0x10,
        "url": "https://agent.api.stepsecurity.io/v1/application/oss-packages/npm/ai-scan-results",
    },
    "JFrog": {
        "file": "jfrog-shai-hulud-2-packages.csv",
        "mask": 0x20,
        "url": "https://research.jfrog.com/shai_hulud_2_packages.csv",
    },
    "CommunityAggregate": {
        "file": "community-shai-hulud-aggregate.csv",
        "mask": 0x40,
        "url": "https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt",
    },
}


def split_versions(value: str) -> list[str]:
    value = value.replace("||", "|").replace(",", "|")
    result: list[str] = []
    for item in value.split("|"):
        item = re.sub(r"^\s*={1,2}\s*", "", item).strip()
        item = item.strip("[]\"'").strip()
        if item:
            result.append(item)
    return result


def cpp_w(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", " ")
        .replace("\n", " ")
    )


def canonical_feed_bytes(path: Path) -> bytes:
    """Return feed bytes with platform-specific line endings normalized."""
    data = path.read_bytes()
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


records: dict[tuple[str, str, str], int] = {}
safedep_iocs: list[tuple[str, str, str]] = []

with (DATA / FEEDS["Socket"]["file"]).open(
    encoding="utf-8-sig", newline=""
) as handle:
    for row in csv.DictReader(handle):
        ecosystem = (row.get("Ecosystem") or "").strip().lower()
        namespace = (row.get("Namespace") or "").strip()
        name = (row.get("Name") or "").strip()
        version = (row.get("Version") or "").strip()
        full_name = f"{namespace}/{name}" if namespace else name
        if ecosystem and full_name and version:
            key = (ecosystem, full_name, version)
            records[key] = records.get(key, 0) | 0x1

with (DATA / FEEDS["SafeDep"]["file"]).open(
    encoding="utf-8-sig", newline=""
) as handle:
    for row in csv.DictReader(handle):
        item_type = (row.get("item_type") or "").strip().lower()
        category = (row.get("category") or "").strip().lower()
        identifier = (row.get("identifier") or "").strip()
        detail = (row.get("detail") or "").strip()
        if item_type == "package" and category in {"npm", "pypi", "golang"}:
            match = re.search(r"\bversions:\s*(.+)$", detail, re.I)
            if match:
                for version in split_versions(match.group(1)):
                    key = (category, identifier, version)
                    records[key] = records.get(key, 0) | 0x2
        elif item_type == "indicator" and identifier:
            safedep_iocs.append((category, identifier, detail))

with (DATA / FEEDS["Wiz"]["file"]).open(
    encoding="utf-8-sig", newline=""
) as handle:
    for row in csv.DictReader(handle):
        name = (row.get("Package") or "").strip()
        for version in split_versions(row.get("Version") or ""):
            key = ("npm", name, version)
            records[key] = records.get(key, 0) | 0x4

with (DATA / FEEDS["Datadog"]["file"]).open(
    encoding="utf-8-sig", newline=""
) as handle:
    for row in csv.DictReader(handle):
        ecosystem = (row.get("ecosystem") or "npm").strip().lower()
        name = (row.get("package") or "").strip()
        for version in split_versions(row.get("versions") or ""):
            key = (ecosystem, name, version)
            records[key] = records.get(key, 0) | 0x8

with (DATA / FEEDS["StepSecurity"]["file"]).open(
    encoding="utf-8-sig", newline=""
) as handle:
    for row in csv.DictReader(handle):
        name = (row.get("Package") or "").strip()
        version = (row.get("Version") or "").strip()
        if name and version:
            key = ("npm", name, version)
            records[key] = records.get(key, 0) | 0x10

with (DATA / FEEDS["JFrog"]["file"]).open(
    encoding="utf-8-sig", newline=""
) as handle:
    for row in csv.DictReader(handle):
        ecosystem = (row.get("package_type") or "npm").strip().lower()
        name = (row.get("package_name") or "").strip()
        for version in split_versions(row.get("versions") or ""):
            if name and version:
                key = (ecosystem, name, version)
                records[key] = records.get(key, 0) | 0x20

with (DATA / FEEDS["CommunityAggregate"]["file"]).open(
    encoding="utf-8-sig", newline=""
) as handle:
    for row in csv.DictReader(handle):
        ecosystem = (row.get("Ecosystem") or "npm").strip().lower()
        name = (row.get("Package") or "").strip()
        version = (row.get("Version") or "").strip()
        if ecosystem and name and version:
            key = (ecosystem, name, version)
            records[key] = records.get(key, 0) | 0x40

hashes = [
    ("SHA256", "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668", "ChainDrop setup.mjs npm tarball preinstall loader"),
    ("SHA256", "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb", "ChainDrop setup.mjs repository/IDE loader"),
    ("SHA256", "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc", "ChainDrop Math_*.js / math_init.js Bun stage-two payload"),
    ("SHA256", "927387d0cfac1118df4b383decc2ea6ba49c9d2f98b47098bcbcba1efc026e1f", "ChainDrop .vscode/tasks.json persistence"),
    ("SHA256", "14eb4ce01dd4307759887ff819359b70d7d9ff709ecde039a5abc1aac325b128", "ChainDrop .claude/settings.json persistence"),
    ("SHA1", "d60ec97eea19fffb4809bc35b91033b52490ca11", "Shai-Hulud 2 bun_environment.js variant"),
    ("SHA1", "3d7570d14d34b0ba137d502f042b27b0f37a59fa", "Shai-Hulud 2 bun_environment.js variant"),
    ("SHA1", "d1829b4708126dcc7bea7437c04d1f10eacd4a16", "Shai-Hulud 2 setup_bun.js loader"),
    ("SHA256", "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0", "Shai-Hulud 2 bun_environment.js variant"),
    ("SHA256", "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068", "Shai-Hulud 2 bun_environment.js variant"),
    ("SHA256", "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd", "Shai-Hulud 2 bun_environment.js variant"),
    ("SHA256", "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a", "Shai-Hulud 2 setup_bun.js loader"),
]
seen_hashes = {(algorithm.lower(), digest.lower()) for algorithm, digest, _ in hashes}
for category, value, detail in safedep_iocs:
    expected = 64 if category == "sha256" else 40 if category == "sha1" else 0
    if expected and re.fullmatch(rf"[0-9A-Fa-f]{{{expected}}}", value):
        key = (category, value.lower())
        if key not in seen_hashes:
            if category == "sha1" and not any(
                token in detail.lower()
                for token in ("file", "payload", "malware", "setup", "math", "bun", "script")
            ):
                continue
            seen_hashes.add(key)
            hashes.append((category.upper(), value.lower(), detail or "SafeDep campaign file hash"))

text_indicators = [
    ("domain", "npm-cache.com", "ChainDrop C2 domain", True),
    ("domain", "pypi-get.com", "ChainDrop C2 domain", True),
    ("domain", "js-mirror.com", "ChainDrop C2 domain", True),
    ("wallet", "0xe1f2395ee43e45a1556ec6438a88c31b83493103", "ChainDrop EtherHiding smart contract", True),
    ("marker", "thebeautifulmarchoftime", "ChainDrop signed GitHub fallback marker", True),
    ("marker", "shai-hulud: here we go again", "ChainDrop GitHub exfiltration repository description", True),
    ("marker", "sha1-hulud: the second coming", "Shai-Hulud 2 exfiltration repository description", True),
    ("marker", "sha1-hulud: the continued coming", "Shai-Hulud 2 second-phase repository description", True),
    ("marker", "shai-hulud repository", "Original Shai-Hulud exfiltration repository description", False),
]
seen_text = {(category, value) for category, value, _, _ in text_indicators}
generic = {"1.1.1.1", "8.8.8.8", "169.254.169.254", "169.254.170.2", "www.youtube.com"}
for category, value, detail in safedep_iocs:
    value = value.lower()
    if category not in {"domain", "ipv4", "wallet", "url"}:
        continue
    key = (category, value)
    if key in seen_text:
        continue
    seen_text.add(key)
    high = category in {"domain", "wallet", "url"} and value not in generic
    text_indicators.append((category, value, detail or "SafeDep campaign indicator", high))

lines = [
    '#include "Indicators.h"',
    "",
    "const PackageIndicator kAffectedPackages[] =",
    "{",
]
for (ecosystem, name, version), mask in sorted(
    records.items(), key=lambda item: (item[0][0], item[0][1].lower(), item[0][2])
):
    lines.append(
        f'    {{ L"{cpp_w(ecosystem)}", L"{cpp_w(name)}", '
        f'L"{cpp_w(version)}", 0x{mask:X} }},'
    )
lines.extend(
    [
        "};",
        "",
        "const std::size_t kAffectedPackageCount =",
        "    sizeof(kAffectedPackages) / sizeof(kAffectedPackages[0]);",
        "",
        "const HashIndicator kKnownHashes[] =",
        "{",
    ]
)
for algorithm, digest, description in hashes:
    lines.append(
        f'    {{ L"{algorithm}", L"{digest.lower()}", L"{cpp_w(description)}" }},'
    )
lines.extend(
    [
        "};",
        "",
        "const std::size_t kKnownHashCount =",
        "    sizeof(kKnownHashes) / sizeof(kKnownHashes[0]);",
        "",
        "const TextIndicator kKnownTextIndicators[] =",
        "{",
    ]
)
for category, value, description, high in text_indicators:
    lines.append(
        f'    {{ L"{cpp_w(category)}", L"{cpp_w(value)}", '
        f'L"{cpp_w(description)}", {"true" if high else "false"} }},'
    )
lines.extend(
    [
        "};",
        "",
        "const std::size_t kKnownTextIndicatorCount =",
        "    sizeof(kKnownTextIndicators) / sizeof(kKnownTextIndicators[0]);",
        "",
    ]
)
with (SRC / "AffectedPackages.generated.cpp").open(
    "w", encoding="utf-8", newline="\n"
) as handle:
    handle.write("\n".join(lines))

manifest = {
    "generated_utc": datetime.now(timezone.utc)
    .replace(microsecond=0)
    .isoformat()
    .replace("+00:00", "Z"),
    "feeds": {},
    "package_name_version_pairs": len(records),
    "ecosystem_package_names": len({(ecosystem, name) for ecosystem, name, _ in records}),
    "ecosystems": dict(Counter(ecosystem for ecosystem, _, _ in records)),
    "file_hash_indicators": len(hashes),
    "text_network_indicators": len(text_indicators),
}
for name, feed in FEEDS.items():
    path = DATA / feed["file"]
    manifest["feeds"][name] = {
        "url": feed["url"],
        "file": feed["file"],
        "sha256": sha256(canonical_feed_bytes(path)).hexdigest(),
        "source_mask": feed["mask"],
    }
with (DATA / "feed-manifest.json").open(
    "w", encoding="utf-8", newline="\n"
) as handle:
    handle.write(json.dumps(manifest, indent=2) + "\n")
print(json.dumps(manifest, indent=2))

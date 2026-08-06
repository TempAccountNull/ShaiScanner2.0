#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
SRC = ROOT / "src"

REQUIRED_FEEDS = {
    "socket-chaindrop.csv",
    "safedep-mini-shai-hulud.csv",
    "wiz-shai-hulud-2-packages.csv",
    "datadog-keyv-malicious-packages.csv",
    "chaindrop-compromised-packages.csv",
    "jfrog-shai-hulud-2-packages.csv",
    "community-shai-hulud-aggregate.csv",
}

REQUIRED_URL_FRAGMENTS = {
    "socket.dev/api/public/supply-chain-attacks/keyv-and-cacheable-compromise/packages.csv",
    "safedep.io/ti/campaigns/mini-shai-hulud.csv",
    "wiz-sec-public/wiz-research-iocs",
    "DataDog/indicators-of-compromise",
    "agent.api.stepsecurity.io/v1/application/oss-packages/npm/ai-scan-results",
    "research.jfrog.com/shai_hulud_2_packages.csv",
    "Cobenian/shai-hulud-detect",
}

REQUIRED_DETECTION_MARKERS = {
    "setup.mjs", "Math_Symbol.js", "setup_bun.js", "bun_environment.js",
    "Runner.Worker", "toJSON(secrets)", "SessionStart", "folderOpen",
    "npm-cache.com", "pypi-get.com", "js-mirror.com",
}


def fail(message: str) -> None:
    print(f"[FAIL] {message}", file=sys.stderr)
    raise SystemExit(1)


def require(text: str, markers: tuple[str, ...] | list[str] | set[str], context: str) -> None:
    for marker in markers:
        if marker not in text:
            fail(f"{context} is missing marker: {marker}")


def verify_icon(path: Path) -> None:
    if not path.is_file():
        fail("The custom application icon is missing.")
    data = path.read_bytes()
    if len(data) < 6:
        fail("The custom application icon is truncated.")
    reserved, icon_type, count = struct.unpack_from("<HHH", data, 0)
    if reserved != 0 or icon_type != 1 or count < 8:
        fail("The application icon is not a multi-resolution Windows ICO.")
    expected_header = 6 + count * 16
    if len(data) < expected_header:
        fail("The application icon directory is truncated.")
    sizes: set[int] = set()
    for index in range(count):
        width, height = struct.unpack_from("<BB", data, 6 + index * 16)
        sizes.add(256 if width == 0 else width)
        sizes.add(256 if height == 0 else height)
    for required in (16, 32, 48, 64, 128, 256):
        if required not in sizes:
            fail(f"The application icon is missing the {required} px frame.")


def main() -> None:
    missing = sorted(name for name in REQUIRED_FEEDS if not (DATA / name).is_file())
    if missing:
        fail(f"Missing feed snapshots: {', '.join(missing)}")

    paths = {
        "generated": SRC / "AffectedPackages.generated.cpp",
        "manifest": DATA / "feed-manifest.json",
        "updater": SRC / "FeedUpdater.cpp",
        "updater_h": SRC / "FeedUpdater.h",
        "scanner": SRC / "Scanner.cpp",
        "main": SRC / "Main.cpp",
        "indicators": SRC / "Indicators.h",
        "extractor": SRC / "StepSecurityExtractor.cpp",
        "debug_log": SRC / "DebugLog.cpp",
        "debug_log_h": SRC / "DebugLog.h",
        "cmake": ROOT / "CMakeLists.txt",
        "resource": SRC / "resources.rc",
        "resource_h": SRC / "resource.h",
        "build": ROOT / "build-release.bat",
        "workflow": ROOT / ".github" / "workflows" / "build-windows.yml",
        "app_manifest": SRC / "app.manifest",
        "extractor_test": ROOT / "tests" / "StepSecurityExtractorTests.cpp",
        "hash_loader": SRC / "MaliciousHashLoader.cpp",
        "hash_loader_h": SRC / "MaliciousHashLoader.h",
        "hash_loader_test": ROOT / "tests" / "MaliciousHashLoaderTests.cpp",
        "hash_json": ROOT / "malicious_hashes.json",
        "prepare_imgui": ROOT / "tools" / "prepare_imgui.ps1",
    }
    for label, path in paths.items():
        if not path.is_file():
            fail(f"Required project file is missing: {label} ({path.relative_to(ROOT)})")

    text = {name: path.read_text(encoding="utf-8") for name, path in paths.items()
            if name not in {"manifest"}}
    updater = text["updater"]
    updater_h = text["updater_h"]
    scanner = text["scanner"]
    main_cpp = text["main"]
    extractor = text["extractor"]
    debug_log = text["debug_log"]
    debug_log_h = text["debug_log_h"]
    hash_loader = text["hash_loader"]
    hash_loader_h = text["hash_loader_h"]
    hash_json_text = text["hash_json"]
    cmake = text["cmake"]
    resource = text["resource"]
    build = text["build"]
    workflow = text["workflow"]
    prepare_imgui = text["prepare_imgui"]

    require(workflow,
        ("build/Release/ShaiHulud2Scanner.exe",
         "ShaiHulud2Scanner-Windows-x64-v1.7.6",
         "ctest --test-dir build -C Release --output-on-failure",
         "prepare_imgui.ps1",
         "CMAKE_SUPPRESS_REGENERATION:BOOL=ON"),
        "GitHub Actions workflow")

    step_lines = (DATA / "chaindrop-compromised-packages.csv").read_text(
        encoding="utf-8-sig").splitlines()
    if not step_lines or step_lines[0].strip() != "Package,Version" or len(step_lines) < 1001:
        fail("StepSecurity fallback must use Package,Version and contain at least 1,000 rows.")
    community_lines = (DATA / "community-shai-hulud-aggregate.csv").read_text(
        encoding="utf-8-sig").splitlines()
    if not community_lines or community_lines[0].strip() != "Ecosystem,Package,Version" or len(community_lines) < 3001:
        fail("Community fallback is malformed or unexpectedly small.")

    integration = updater + updater_h + text["indicators"] + extractor + debug_log + debug_log_h + hash_loader + hash_loader_h + cmake
    require(integration, (
        "FeedStateKind", "AdvisoryCurrent", "healthSummary", "FeedPayloadKind::StepSecurityApi",
        "FetchStepSecurityApi", "StepSecurityExtractor::ParseApiPage",
        "BuiltInStepSecurity", "BuiltInJFrog",
        "BuiltInCommunityAggregate", "CommunityTextToCsv",
        "WINHTTP_OPTION_DECOMPRESSION", "WINHTTP_DECOMPRESSION_FLAG_GZIP",
    ), "Seven-feed integration")
    for fragment in REQUIRED_URL_FRAGMENTS:
        if fragment not in updater:
            fail(f"Feed updater is missing URL fragment: {fragment}")
    if updater.count("CoTaskMemFree(localAppData);") != 1:
        fail("LocalAppData memory ownership is incorrect.")
    require(extractor, (
        "download-button package array", "inline package array",
        "embedded JSON package records", "HTML package table",
        "DecodeEscapedScriptSource", "AddRowIfPlausible",
    ), "StepSecurity extraction fallbacks")
    require(text["extractor_test"], (
        "JavaScript package array", "embedded JSON records", "HTML package table",
        "StepSecurity API page and pagination token",
    ), "StepSecurity regression test")
    require(debug_log + debug_log_h, (
        "debug.log", "debug.previous.log", "AllocConsole", "ATTACH_PARENT_PROCESS",
        "WriteBlob", "FormatWin32Error",
    ), "Diagnostic console and persistent log")
    require(updater, (
        "StepSecurity-api-page-latest.json", "StepSecurity-normalized-latest.csv",
        "risk_level=CRITICAL", "next_token=", "UrlEncodeUtf8",
    ), "StepSecurity public API pagination and diagnostic artifacts")
    require(updater + extractor, (
        "Request headers follow", "Raw response headers follow",
        "Complete StepSecurity API response page", "Response body SHA-256",
        "ParseApiPage", "package_name", "has_more", "next_token",
        "Validation result for", "Final source state for",
    ), "StepSecurity request/parser diagnostic trace")
    require(cmake, ("StepSecurityExtractorTests", "MaliciousHashLoaderTests", "enable_testing()", "add_test(",
                    "src/DebugLog.cpp", "src/MaliciousHashLoader.cpp", "malicious_hashes.json",
                    "CMAKE_SUPPRESS_REGENERATION", "third_party/imgui-1.92.9b"),
        "CMake regression-test configuration")
    if "FetchContent" in cmake or "ExternalProject" in cmake:
        fail("CMake must not download Dear ImGui inside the parallel build graph.")
    require(prepare_imgui, (
        "Test-ImGuiTree", "System.Threading.Mutex", "Invoke-WebRequest",
        "Expand-Archive", "imgui-1.92.9b", "codeload.github.com",
    ), "Serialized Dear ImGui preparation")
    require(build, ("[1/6] Preparing pinned Dear ImGui", "prepare_imgui.ps1",
                    "[5/6] Running feed and hash regression tests", "ctest --test-dir build",
                    "CMAKE_SUPPRESS_REGENERATION:BOOL=ON", r"dist\malicious_hashes.json"),
        "Windows build regression tests")

    require(main_cpp, (
        '#include "imgui.h"', '#include "imgui_impl_dx11.h"',
        "ImGui_ImplWin32_WndProcHandler", "ImGui_ImplWin32_GetDpiScaleForHwnd",
        "DrawBackgroundGrid", "DrawShieldMark", "NavigationItem", "Security posture",
        "CautionColor", "FEEDS DEGRADED", "ENGINE IDLE", "SCAN ACTIVE",
        "selectedPackageKey", "package_detail_layout", "COPY FULL PATH",
        "OPEN LOCATION", "COPY PACKAGE@VERSION", "Threat feed details",
        "feed_detail_body", "Already up to date", "Feed rejected - cached snapshot",
        "Caution: a clean scan is not a guarantee",
        "RenderScanCompletionNotification", "verdict_body",
        "drawInsideBorder", "live, style-derived safety inset",
        "SplitNoticeParagraphs", "ImGuiChildFlags_AlwaysUseWindowPadding",
        "ImGuiCond_Always", "bodyNaturalHeight", "bodyContentWidth", "metricColumns",
        "DebugModeRequested", 'L"--debug"', "workspaceFlags",
        "footerReservedHeight", "auditRowHeight", "EllipsizeToWidth",
        "IDI_SHAIHULUD_APP", "WM_SETICON", "roots selected",
        "DebugLog::Initialize", "DebugLog::Shutdown",
        "MergeExternalHashDatabase", "malicious_hashes.json", "activeHashIndicators",
    ), "Professional security-console UI")
    require(main_cpp, (
        "struct ResponsiveLayout", "UpdateResponsiveLayout",
        "g_layout.displaySize = io.DisplaySize", "viewportUnitX", "viewportUnitY",
        "ViewportWidth", "ViewportHeight", "FittedColumnCount", "FittedBalancedColumnCount", "ColumnWidth",
        "NavigationWidth", "FlowSameLine", "RenderCompactNavigation", "MinimumWorkspaceWidth",
        "widthDrivenFont = io.DisplaySize.x", "heightDrivenFont = io.DisplaySize.y",
        "style.FontScaleMain = g_baseStyle.FontScaleMain * g_layout.scale",
        "const float onePhysicalPixel", "const float border",
        "style.WindowPadding = ImVec2(em", "style.ChildBorderSize = border",
        "style.FrameBorderSize = border", "style.SeparatorSize = border",
        "const int cardColumns = FittedBalancedColumnCount",
        "const bool sideBySide = lowerWidth >= telemetryContentWidth",
        "const bool auditSideBySide",
        "const bool sideBySide = availableWidth >= minimumColumn",
        "FooterHeight()", "const ImGuiWindowFlags workspaceFlags = ImGuiWindowFlags_None",
    ), "Fluid viewport-driven ImGui layout")
    if re.search(r"\b(?:style|ImGui::GetStyle\(\))\.ScaleAllSizes\s*\(", main_cpp):
        fail("Main.cpp still uses ImGuiStyle::ScaleAllSizes for live layout. It truncates sub-one-pixel metrics and causes resize breakpoints; assign viewport-derived floating-point style metrics directly.")
    if "ImGuiWindowFlags_NoHorizontalScrollbar" in main_cpp:
        fail("Main.cpp uses nonexistent ImGuiWindowFlags_NoHorizontalScrollbar; horizontal scrollbars are opt-in, so use ImGuiWindowFlags_None or omit ImGuiWindowFlags_HorizontalScrollbar.")
    verdict_start = main_cpp.find("void RenderScanCompletionNotification")
    verdict_end = main_cpp.find("void RenderTopHeader", verdict_start)
    verdict_source = main_cpp[verdict_start:verdict_end] if verdict_start >= 0 and verdict_end > verdict_start else ""
    if "ImGuiCond_Appearing" in verdict_source:
        fail("The scan verdict still retains its first-frame dimensions instead of following the live viewport.")
    if "ImGuiCond_Always" not in verdict_source or "bodyNaturalHeight" not in verdict_source:
        fail("The scan verdict is not recalculating its result-specific geometry every frame.")
    if "CalculateNoticeBoxHeight(cleanCautionHeading" not in verdict_source or "bodyContentWidth" not in verdict_source:
        fail("The clean verdict is not measuring its caution panel against the nested body content width.")
    if ("compromiseSteps" not in verdict_source or
            "actionCellHeight" not in verdict_source or
            "for (const auto& step : compromiseSteps)" not in verdict_source):
        fail("The compromised verdict does not share response-step definitions between measurement and rendering.")
    notice_start = main_cpp.find("void NoticeBox")
    notice_end = main_cpp.find("void AuditRow", notice_start)
    notice_source = main_cpp[notice_start:notice_end] if notice_start >= 0 and notice_end > notice_start else ""
    if ("CalculateNoticeBoxHeight" not in notice_source or
            "ImGuiChildFlags_AlwaysUseWindowPadding" not in notice_source or
            "ImGuiWindowFlags_NoScrollbar" not in notice_source or
            "SplitNoticeParagraphs" not in notice_source):
        fail("NoticeBox does not use its exact wrapped-content measurement and scrollbar-free child layout.")
    navigation_start = main_cpp.find("bool NavigationItem")
    navigation_end = main_cpp.find("void RenderNavigation", navigation_start)
    navigation_source = main_cpp[navigation_start:navigation_end] if navigation_start >= 0 and navigation_end > navigation_start else ""
    if "drawInsideBorder" not in navigation_source or "AddRectFilled(innerMinimum" not in navigation_source:
        fail("Navigation selection still uses a clip-prone stroked outline instead of an inside-only filled border.")
    imgui_header = ROOT / "third_party" / "imgui-1.92.9b" / "imgui.h"
    if imgui_header.is_file():
        imgui_api = imgui_header.read_text(encoding="utf-8", errors="replace")
        used_window_flags = set(re.findall(r"\bImGuiWindowFlags_[A-Za-z0-9_]+\b", main_cpp))
        unknown_window_flags = sorted(flag for flag in used_window_flags
                                      if flag != "ImGuiWindowFlags_None" and flag not in imgui_api)
        if unknown_window_flags:
            fail("Main.cpp uses window flags absent from pinned Dear ImGui v1.92.9b: " +
                 ", ".join(unknown_window_flags))
    if "ptMinTrackSize" in main_cpp or "WM_GETMINMAXINFO" in main_cpp:
        fail("The application still enforces a fixed minimum window size.")
    if "referenceSize" in main_cpp or "normalizedWidth" in main_cpp or "normalizedHeight" in main_cpp:
        fail("The interface still scales from a stored reference canvas instead of the live viewport.")
    if re.search(r"ImGui::PushFont\([^,]+,\s*[0-9]+(?:\.[0-9]+)?f?\s*\)", main_cpp):
        fail("A font role still uses a fixed point size instead of native/relative font metrics.")
    fixed_control_patterns = {
        "fixed child geometry": r"BeginChild\([^\n]*Ui\(",
        "fixed button geometry": r"Button\([^\n]*ImVec2\([^\n]*Ui\(",
        "fixed popup geometry": r"SetNextWindowSize\([^\n]*Ui\(",
        "fixed table geometry": r"TableSetupColumn\([^\n]*Ui\(",
    }
    for label, pattern in fixed_control_patterns.items():
        if re.search(pattern, main_cpp):
            fail(f"The fluid layout still contains {label}.")
    if 'FILES: %llu' in main_cpp or 'QUEUED: %llu' in main_cpp or 'counterRegionWidth' in main_cpp:
        fail("The redundant footer counters are still present.")
    if 'PREVIEW COMPROMISED RESPONSE' in main_cpp or 'QueueCompromisedAlertPreview' in main_cpp or 'completionNotificationIsPreview' in main_cpp:
        fail("Production source still contains the compromised-response preview path.")
    if 'DebugLog::Initialize(executableDirectory, true);' not in main_cpp or 'if (debugMode)' not in main_cpp:
        fail("Diagnostic initialization is not gated behind --debug.")
    require(main_cpp, (
        "CalculateNoticeBoxHeight", "auditChromeHeight",
        "const float auditHeight = auditChromeHeight + auditRowHeight * 8.0f",
        "const bool auditSideBySide", "FittedBalancedColumnCount(cardAreaWidth",
        "ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse",
    ), "Fluid Coverage & Audit layout")
    if 'g_app.activePage == PageCoverage' in main_cpp:
        fail("Coverage still uses a special-case scrolling workspace.")

    if 'StatusPill("READ ONLY"' in main_cpp or '"READ ONLY"' in main_cpp:
        fail("The redundant READ ONLY header pill is still present.")
    if "ImGuiWindowFlags_AlwaysVerticalScrollbar" in main_cpp:
        fail("The UI still forces a scrollbar instead of showing one only when required.")
    if "io.ConfigDpiScaleFonts" in main_cpp or "io.ConfigDpiScaleViewports" in main_cpp:
        fail("Main.cpp uses docking-branch-only DPI members.")
    if re.search(r"ImGui::PushFont\([^,\n]+\);", main_cpp):
        fail("Main.cpp contains a removed single-argument ImGui::PushFont call.")
    require(main_cpp, (
        'ImGui::TableSetupColumn("Ecosystem"', 'ImGui::TableSetupColumn("Package"',
        'ImGui::TableSetupColumn("Version"', 'ImGui::TableSetupColumn("Affected"',
        'ImGui::TableSetupColumn("Manifest / metadata path"',
        "ImGuiTableFlags_Sortable", "ImGuiTableFlags_SortMulti",
    ), "Sortable package inventory")

    branding = main_cpp + cmake + resource + text["app_manifest"] + build
    if "ChainDrop Package Scanner" in branding or "CHAINDROP PACKAGE SCANNER" in branding:
        fail("Legacy product branding remains in executable-facing files.")
    require(branding, ("Shai-Hulud 2.0 Scanner", "SHAI-HULUD 2.0 SCANNER",
                       "ShaiHulud2Scanner.exe", "1.7.6"), "Application branding")

    require(main_cpp, (
        "CONFIRMED MALWARE FILE DETECTED", "NO CRITICALS ARE PRESENT - YOU ARE NOT CURRENTLY AFFECTED!",
        "Isolate the affected environment", "Preserve evidence before cleanup",
        "Remove token-monitor persistence first", "Restore known-good releases",
        "Rotate secrets from a separate clean machine", "ACKNOWLEDGE", "REVIEW FINDINGS",
        "ImGui::SetNextWindowBgAlpha(0.65f)",
    ), "Completion verdict and recovery guidance")

    required_vcvars = (r'call %comspec% /k ""c:\program files\microsoft visual studio\2022\enterprise'
                       r'\vc\auxiliary\build\vcvars64.bat"')
    if required_vcvars not in build.lower():
        fail("build-release.bat is not using the required Enterprise vcvars64 launcher.")
    require(cmake, ("imgui-1.92.9b", "src/app.manifest", "/MANIFESTUAC:NO",
                    "VERSION 1.7.6", "src/shaihulud.ico", "OBJECT_DEPENDS",
                    "CMAKE_SUPPRESS_REGENERATION"),
            "CMake release configuration")
    if "RT_MANIFEST" in resource:
        fail("resources.rc must not embed a second manifest.")
    require(resource, ('IDI_SHAIHULUD_APP ICON "shaihulud.ico"',
                       "FILEVERSION 1,7,6,0", '"1.7.6\\0"'),
            "Windows resources")
    require(text["resource_h"], ("IDI_SHAIHULUD_APP",), "Resource identifiers")
    verify_icon(SRC / "shaihulud.ico")
    try:
        ET.parse(paths["app_manifest"])
    except ET.ParseError as exc:
        fail(f"src/app.manifest is invalid XML: {exc}")
    if "cmake --fresh" not in build.lower():
        fail("build-release.bat must perform a fresh configure.")

    require(hash_loader + hash_loader_h, (
        "LoadMaliciousHashesJson", "SHA256", "SHA1", "filenames",
        "skippedEntries", "unsupported algorithm", "invalid digest",
    ), "Extensible malicious hash JSON loader")
    require(text["hash_loader_test"], (
        "MaliciousHashLoaderTests passed", "SHA-256", "sha1", "md5",
    ), "Malicious hash JSON regression test")
    require(scanner, (
        "MergeMaliciousHashesJson", "ShouldHashFileName", "HashIndicatorCount",
        "jsonHashCandidate", "HASH/JSON",
    ), "Runtime malicious hash merge and filename targeting")

    try:
        hash_database = json.loads(hash_json_text)
    except json.JSONDecodeError as exc:
        fail(f"malicious_hashes.json is invalid JSON: {exc}")
    hash_entries = hash_database.get("hashes")
    if not isinstance(hash_entries, list) or len(hash_entries) < 60:
        fail("malicious_hashes.json must contain at least 60 documented hash entries.")
    declared_count = hash_database.get("entry_count")
    if declared_count != len(hash_entries):
        fail("malicious_hashes.json entry_count does not match the hashes array.")
    seen_hashes: set[tuple[str, str]] = set()
    synthetic_hashes = {
        "86532ed94c5804e1ca32fa67257e1bb9de628e3e48a1f56e67042dc055effb5b",
        "aba1fcbd15c6ba6d9b96e34cec287660fff4a31632bf76f2a766c499f55ca1ee",
    }
    required_test_hash = "92a88981f1594c193bb66040e9c1782a6ce22cf6"
    for index, entry in enumerate(hash_entries, 1):
        if not isinstance(entry, dict):
            fail(f"malicious_hashes.json entry {index} is not an object.")
        algorithm = str(entry.get("algorithm", "")).upper().replace("-", "")
        digest = str(entry.get("digest", entry.get("hash", ""))).lower()
        expected = 40 if algorithm == "SHA1" else 64 if algorithm == "SHA256" else 0
        if expected == 0 or len(digest) != expected or not re.fullmatch(r"[0-9a-f]+", digest):
            fail(f"malicious_hashes.json entry {index} has an invalid algorithm or digest.")
        if digest in synthetic_hashes:
            fail("Synthetic test hashes must never be shipped as malicious IOCs.")
        key = (algorithm, digest)
        if key in seen_hashes:
            fail(f"Duplicate malicious hash entry: {algorithm}:{digest}")
        seen_hashes.add(key)
        if not entry.get("description") or not entry.get("source"):
            fail(f"malicious_hashes.json entry {index} must include description and source.")
        filenames = entry.get("filenames", [])
        if not isinstance(filenames, list) or any(not isinstance(name, str) for name in filenames):
            fail(f"malicious_hashes.json entry {index} has invalid filenames.")

    require(scanner, (
        "class PathQueue", "std::condition_variable", "std::vector<std::thread> workers",
        "std::vector<std::thread> producers", "options.workerThreads", "options.queueCapacity",
    ), "Bounded multithreaded scan engine")
    test_entries = [entry for entry in hash_entries
                    if str(entry.get("digest", entry.get("hash", ""))).lower() == required_test_hash]
    if len(test_entries) != 1 or test_entries[0].get("filenames") != ["testfile.js"]:
        fail("malicious_hashes.json must contain the documented testfile.js hash as its final entry.")
    if str(hash_entries[-1].get("digest", "")).lower() != required_test_hash:
        fail("The manual test hash must remain the final malicious_hashes.json entry.")
    manual_test_content = (
        b"THIS IS A TEST FILE TO TEST DETECTIONS\r\n\r\n"
        b"THERE IS NO CODE HERE"
    )
    if hashlib.sha1(manual_test_content).hexdigest() != required_test_hash:
        fail("The documented testfile.js content does not match the shipped manual test hash.")
    if "PathStartsWith(path, options.selfDirectory)" in scanner:
        fail("The scanner still excludes its own directory and would miss test or incident artifacts beside the executable.")
    if "emptyFileTestHash" in scanner:
        fail("Obsolete zero-byte test-hash special casing remains in Scanner.cpp.")
    require(main_cpp, (
        "const bool bodyNeedsScroll", "verdictBodyFlags",
        "ImGuiChildFlags_AlwaysUseWindowPadding", "measurementTolerance",
        "const float edgeInset",
    ), "Responsive verdict caution and navigation selection layout")

    critical_assignments = scanner.count("finding.severity = Severity::Critical")
    if critical_assignments != 1:
        fail(f"CRITICAL must be assigned only by exact hash matching; found {critical_assignments} assignments.")
    if scanner.find("finding.severity = Severity::Critical") < scanner.find("const auto inspectKnownHashes"):
        fail("The CRITICAL assignment is not inside known-hash inspection.")
    detection_text = (scanner + "\n" + paths["generated"].read_text(encoding="utf-8")).lower()
    for marker in REQUIRED_DETECTION_MARKERS:
        if marker.lower() not in detection_text:
            fail(f"Scanner/database is missing detection marker: {marker}")

    generated = paths["generated"]
    manifest_path = paths["manifest"]
    original_cpp = generated.read_bytes()
    original_cpp_text = original_cpp.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    original_manifest = manifest_path.read_bytes()
    try:
        subprocess.run([sys.executable, str(ROOT / "tools" / "generate_indicators.py")],
                       cwd=ROOT, check=True, capture_output=True, text=True)
        regenerated_cpp = generated.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
        regenerated_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    finally:
        generated.write_bytes(original_cpp)
        manifest_path.write_bytes(original_manifest)
    if original_cpp_text != regenerated_cpp:
        fail("Generated C++ array is not synchronized with the bundled feeds.")
    manifest = json.loads(original_manifest.decode("utf-8"))
    old_cmp = dict(manifest); new_cmp = dict(regenerated_manifest)
    old_cmp.pop("generated_utc", None); new_cmp.pop("generated_utc", None)
    if old_cmp != new_cmp:
        fail("feed-manifest.json is not synchronized with the bundled feeds.")
    if len(manifest.get("feeds", {})) != 7:
        fail("feed-manifest.json must describe exactly seven feeds.")
    if manifest["package_name_version_pairs"] < 5000 or manifest["ecosystem_package_names"] < 2000:
        fail("The embedded package intelligence union is unexpectedly small.")
    package_lines = len(re.findall(
        r'^\s*\{ L"(?:npm|pypi|golang|composer|crates)"', original_cpp_text, re.M))
    if package_lines != manifest["package_name_version_pairs"]:
        fail("Generated package count does not match feed-manifest.json.")

    print("[OK] Seven independent feed snapshots and runtime source URLs are present.")
    print("[OK] StepSecurity uses the public paginated OSS Security Feed API with token-loop protection and diagnostics.")
    print("[OK] The Windows build runs StepSecurity parser regression tests after compilation.")
    print("[OK] Feed states, degradation reporting, caching, decompression, and fallback handling are configured.")
    print("[OK] The black/orange ImGui interface has compact feed status, on-demand details, aligned audits, and no forced scrollbars.")
    print("[OK] Live viewport layout uses ImGuiIO::DisplaySize, viewport-derived typography, content measurements, automatic reflow, and proportional geometry.")
    print("[OK] Package Inventory is sortable and supports row details, full-path copy, and Explorer navigation.")
    print("[OK] Idle/running/feed-health status semantics and the separated-footer verdict modal are present.")
    print("[OK] A multi-resolution shield icon is embedded for the executable, taskbar, and window.")
    print("[OK] Visual Studio 2022 Enterprise vcvars64 launcher and single-manifest resource layout are valid.")
    print("[OK] Bounded multithreading is present and CRITICAL remains exact-hash-only.")
    print("[OK] Diagnostics are production-quiet and enabled only with the explicit --debug switch.")
    print(f"[OK] Extensible malicious_hashes.json database: {len(hash_entries):,} validated SHA1/SHA256 entries.")
    print(f"[OK] Embedded exact package/version pairs: {package_lines:,}")
    print(f"[OK] Ecosystem/package names: {manifest['ecosystem_package_names']:,}")
    print(f"[OK] File-hash indicators: {manifest['file_hash_indicators']:,}")
    print(f"[OK] Text/network indicators: {manifest['text_network_indicators']:,}")


if __name__ == "__main__":
    main()

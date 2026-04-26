from __future__ import annotations

import argparse
import gzip
import io
import json
import re
import ssl
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
import threading
from typing import Any
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET
import zipfile

from .config import (
    KB_AUTOSYNC,
    KB_NVD_YEAR_END,
    KB_NVD_YEARLY_MIRROR,
    KB_NVD_YEAR_START,
    KB_STALE_AFTER_SECONDS,
    KB_SYNC_TIMEOUT_SECONDS,
    KB_WEEKLY_SYNC,
    KB_WEEKLY_SYNC_DAY,
    KB_WEEKLY_SYNC_HOUR,
    KB_WEEKLY_SYNC_MINUTE,
    KNOWLEDGE_BASE_DIR,
    KNOWLEDGE_BASE_INDEX_DIR,
    KNOWLEDGE_BASE_RAW_DIR,
    MAX_TEXT_FILE_SIZE,
)
from .models import Finding


USER_AGENT = "ScanForge/0.2"
FSTEC_HOST = "bdu.fstec.ru"
ID_PATTERNS = {
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "cwe": re.compile(r"\bCWE-\d+\b", re.IGNORECASE),
    "capec": re.compile(r"\bCAPEC-\d+\b", re.IGNORECASE),
    "bdu": re.compile(r"\bBDU:\d{4}-\d{5}\b", re.IGNORECASE),
}
REFERENCE_PRIORITY = {
    "cve": 50,
    "bdu": 45,
    "cwe": 32,
    "capec": 24,
    "fstec-threat": 18,
}
FINDING_CWE_HINTS = [
    (re.compile(r"unsafe input api|gets\s*\(", re.IGNORECASE), ["CWE-242"]),
    (re.compile(r"buffer overflow|strcpy\s*\(|strcat\s*\(|sprintf\s*\(|vsprintf\s*\(", re.IGNORECASE), ["CWE-120"]),
    (re.compile(r"insecure temporary file|mktemp\s*\(", re.IGNORECASE), ["CWE-377"]),
    (re.compile(r"shell execution|pipeline execution|system\s*\(|popen\s*\(", re.IGNORECASE), ["CWE-78"]),
    (re.compile(r"weak randomness|rand\s*\(", re.IGNORECASE), ["CWE-338"]),
    (re.compile(r"hard-coded secret|password|passwd|secret|token", re.IGNORECASE), ["CWE-798"]),
]
BASE_FEED_SPECS = [
    {
        "key": "cisa_kev",
        "label": "CISA KEV",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "filename": "known_exploited_vulnerabilities.json",
        "index_filename": "cisa_kev.json",
        "parser": "parse_cisa_kev_json",
    },
    {
        "key": "cwe",
        "label": "MITRE CWE",
        "url": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        "filename": "cwec_latest.xml.zip",
        "index_filename": "cwe.json",
        "parser": "parse_cwe_xml_zip",
    },
    {
        "key": "capec",
        "label": "MITRE CAPEC",
        "url": "https://capec.mitre.org/data/xml/capec_latest.xml",
        "filename": "capec_latest.xml",
        "index_filename": "capec.json",
        "parser": "parse_capec_xml",
    },
    {
        "key": "fstec_vulns",
        "label": "FSTEC BDU Vulnerabilities",
        "url": "https://bdu.fstec.ru/files/documents/vulxml.zip",
        "filename": "vulxml.zip",
        "index_filename": "fstec_vulns.json",
        "parser": "parse_fstec_vuln_xml_zip",
    },
    {
        "key": "fstec_threats",
        "label": "FSTEC BDU Threats",
        "url": "https://bdu.fstec.ru/files/documents/thrlist.xlsx",
        "filename": "thrlist.xlsx",
        "index_filename": "fstec_threats.json",
        "parser": "parse_fstec_threats_xlsx",
    },
]
_KB_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_KB_SCHEDULER_LOCK = threading.Lock()
_KB_SCHEDULER_STOP: threading.Event | None = None
_KB_SCHEDULER_THREAD: threading.Thread | None = None
_KB_SYNC_RUN_LOCK = threading.Lock()
_KB_SYNC_STATE_LOCK = threading.Lock()
_KB_SYNC_THREAD: threading.Thread | None = None
_KB_SYNC_STATE: dict[str, Any] = {
    "running": False,
    "trigger": None,
    "started_at": None,
    "finished_at": None,
    "last_error": "",
}
WEEKDAY_LABELS = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _update_sync_state(**changes: Any) -> dict[str, Any]:
    with _KB_SYNC_STATE_LOCK:
        _KB_SYNC_STATE.update(changes)
        return dict(_KB_SYNC_STATE)


def knowledge_base_sync_state() -> dict[str, Any]:
    with _KB_SYNC_STATE_LOCK:
        payload = dict(_KB_SYNC_STATE)
        thread = _KB_SYNC_THREAD
    payload["thread_alive"] = bool(thread and thread.is_alive())
    return payload


def _weekly_schedule_payload() -> dict[str, Any]:
    return {
        "enabled": KB_WEEKLY_SYNC,
        "day": KB_WEEKLY_SYNC_DAY,
        "day_label": WEEKDAY_LABELS[KB_WEEKLY_SYNC_DAY],
        "hour": KB_WEEKLY_SYNC_HOUR,
        "minute": KB_WEEKLY_SYNC_MINUTE,
        "next_run_at": next_weekly_sync_at().isoformat() if KB_WEEKLY_SYNC else None,
    }


def _nvd_years() -> list[int]:
    return list(range(KB_NVD_YEAR_START, KB_NVD_YEAR_END + 1))


def _nvd_modified_spec() -> dict[str, Any]:
    return {
        "key": "nvd_modified",
        "label": "NVD Modified Feed",
        "url": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz",
        "filename": "nvdcve-2.0-modified.json.gz",
        "index_filename": "nvd_modified.json",
        "parser": "parse_nvd_feed",
        "logical_group": "nvd",
        "status_visible": True,
    }


def _nvd_year_spec(year: int) -> dict[str, Any]:
    return {
        "key": f"nvd_year_{year}",
        "label": f"NVD {year}",
        "url": f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz",
        "filename": f"nvdcve-2.0-{year}.json.gz",
        "index_filename": f"nvd_{year}.json",
        "parser": "parse_nvd_feed",
        "logical_group": "nvd",
        "status_visible": False,
        "year": year,
    }


def build_feed_specs() -> list[dict[str, Any]]:
    specs = [dict(spec) for spec in BASE_FEED_SPECS]
    specs.insert(3, _nvd_modified_spec())
    if KB_NVD_YEARLY_MIRROR:
        yearly_specs = [_nvd_year_spec(year) for year in _nvd_years()]
        specs[3:3] = yearly_specs
    return specs


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _normalize_text(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").replace("_x000D_", " ")).strip()


def _excerpt(value: str | None, limit: int = 320) -> str:
    text = _normalize_text(value)
    if len(text) <= limit:
        return text
    return f"{text[: limit - 1].rstrip()}..."


def _paths(base_dir: Path | None = None) -> dict[str, Path]:
    root = base_dir or KNOWLEDGE_BASE_DIR
    raw_dir = root / "raw"
    index_dir = root / "indexes"
    raw_dir.mkdir(parents=True, exist_ok=True)
    index_dir.mkdir(parents=True, exist_ok=True)
    return {
        "root": root,
        "raw_dir": raw_dir,
        "index_dir": index_dir,
        "status": index_dir / "status.json",
        "lookup": index_dir / "lookup.json",
    }


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", delete=False, dir=str(path.parent), encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        temp_name = handle.name
    Path(temp_name).replace(path)


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _is_stale(path: Path) -> bool:
    if not path.exists():
        return True
    age = datetime.now(timezone.utc) - datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    return age.total_seconds() > KB_STALE_AFTER_SECONDS


def _load_cached_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    cache_key = str(path.resolve())
    mtime = path.stat().st_mtime
    cached = _KB_CACHE.get(cache_key)
    if cached and cached[0] == mtime:
        return cached[1]
    payload = _read_json(path)
    _KB_CACHE[cache_key] = (mtime, payload)
    return payload


def _request_url(url: str) -> tuple[bytes, bool]:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=KB_SYNC_TIMEOUT_SECONDS) as response:
            return response.read(), False
    except URLError as exc:
        hostname = urlparse(url).hostname or ""
        if hostname != FSTEC_HOST or "CERTIFICATE_VERIFY_FAILED" not in repr(exc):
            raise
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with urlopen(request, timeout=KB_SYNC_TIMEOUT_SECONDS, context=context) as response:
            return response.read(), True


def _download_feed(url: str, destination: Path) -> dict[str, Any]:
    payload, insecure_retry = _request_url(url)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)
    return {
        "bytes": len(payload),
        "ssl_fallback_used": insecure_retry,
    }


def _find_first_xml_in_zip(path: Path) -> bytes:
    with zipfile.ZipFile(path) as archive:
        xml_names = [name for name in archive.namelist() if name.endswith(".xml")]
        if not xml_names:
            raise RuntimeError(f"No XML file found in archive: {path}")
        return archive.read(xml_names[0])


def _child_text(element: ET.Element, name: str) -> str:
    child = element.find(name)
    if child is None:
        return ""
    return _normalize_text("".join(child.itertext()))


def _descendant_texts(element: ET.Element, name: str) -> list[str]:
    values: list[str] = []
    for child in element.iter():
        if _local_name(child.tag) != name:
            continue
        text = _normalize_text("".join(child.itertext()))
        if text:
            values.append(text)
    return values


def _english_description(items: list[dict[str, Any]] | None) -> str:
    for item in items or []:
        if item.get("lang") == "en":
            return _excerpt(item.get("value", ""))
    return _excerpt((items or [{}])[0].get("value", "")) if items else ""


def _severity_from_nvd(metrics: dict[str, Any]) -> str:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key) or []
        if not metric_list:
            continue
        metric = metric_list[0]
        cvss_data = metric.get("cvssData", {})
        severity = metric.get("baseSeverity") or cvss_data.get("baseSeverity")
        score = cvss_data.get("baseScore")
        parts = [str(score)] if score is not None else []
        if severity:
            parts.append(str(severity))
        return " ".join(parts).strip()
    return ""


def _collect_nvd_cpes(node: Any) -> list[str]:
    values: set[str] = set()
    if isinstance(node, dict):
        criteria = _normalize_text(node.get("criteria"))
        if criteria.startswith("cpe:2.3:"):
            values.add(criteria)
        match_criteria = _normalize_text(node.get("matchCriteriaId"))
        if match_criteria.startswith("cpe:2.3:"):
            values.add(match_criteria)
        for value in node.values():
            values.update(_collect_nvd_cpes(value))
    elif isinstance(node, list):
        for item in node:
            values.update(_collect_nvd_cpes(item))
    return sorted(values)


def _nvd_product_index(cpes: list[str]) -> tuple[list[str], list[str]]:
    vendors: set[str] = set()
    products: set[str] = set()
    for cpe in cpes:
        parts = cpe.split(":")
        if len(parts) < 6:
            continue
        vendor = _normalize_text(parts[3]).casefold()
        product = _normalize_text(parts[4]).casefold()
        if vendor and vendor not in {"*", "-"}:
            vendors.add(vendor)
        if product and product not in {"*", "-"}:
            products.add(product)
    return sorted(vendors), sorted(products)


def _excel_serial_to_iso(value: str) -> str:
    try:
        serial = float(value)
    except ValueError:
        return _normalize_text(value)
    base = datetime(1899, 12, 30, tzinfo=timezone.utc)
    return (base + timedelta(days=serial)).date().isoformat()


def _load_xlsx_shared_strings(archive: zipfile.ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in archive.namelist():
        return []
    namespace = {"a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
    values: list[str] = []
    for item in root.findall("a:si", namespace):
        parts = [text.text or "" for text in item.iterfind(".//a:t", namespace)]
        values.append("".join(parts))
    return values


def _xlsx_rows(path: Path) -> list[dict[str, str]]:
    namespace = {"a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    with zipfile.ZipFile(path) as archive:
        shared = _load_xlsx_shared_strings(archive)
        sheet_name = "xl/worksheets/sheet1.xml"
        root = ET.fromstring(archive.read(sheet_name))
        sheet_data = root.find("a:sheetData", namespace)
        if sheet_data is None:
            return []
        rows: list[dict[str, str]] = []
        for row in sheet_data.findall("a:row", namespace):
            cells: dict[str, str] = {}
            for cell in row.findall("a:c", namespace):
                reference = cell.attrib.get("r", "")
                column = "".join(char for char in reference if char.isalpha())
                cell_type = cell.attrib.get("t")
                if cell_type == "inlineStr":
                    text = _normalize_text("".join(cell.itertext()))
                else:
                    value_node = cell.find("a:v", namespace)
                    raw_value = value_node.text if value_node is not None else ""
                    text = shared[int(raw_value)] if cell_type == "s" and raw_value.isdigit() else raw_value
                cells[column] = _normalize_text(text)
            rows.append(cells)
        return rows


def parse_cisa_kev_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    entries: dict[str, dict[str, Any]] = {}
    for item in payload.get("vulnerabilities", []):
        cve_id = _normalize_text(item.get("cveID"))
        if not cve_id:
            continue
        entries[cve_id] = {
            "id": cve_id,
            "name": _normalize_text(item.get("vulnerabilityName")),
            "summary": _excerpt(item.get("shortDescription") or item.get("requiredAction")),
            "vendor": _normalize_text(item.get("vendorProject")),
            "product": _normalize_text(item.get("product")),
            "date_added": _normalize_text(item.get("dateAdded")),
            "required_action": _excerpt(item.get("requiredAction")),
            "due_date": _normalize_text(item.get("dueDate")),
            "ransomware_use": _normalize_text(item.get("knownRansomwareCampaignUse")),
        }
    return {
        "count": len(entries),
        "entries": entries,
        "catalog_version": _normalize_text(payload.get("catalogVersion")),
        "generated_at": _normalize_text(payload.get("dateReleased")),
    }


def parse_cwe_xml_zip(path: Path) -> dict[str, Any]:
    xml_bytes = _find_first_xml_in_zip(path)
    root = ET.fromstring(xml_bytes)
    entries: dict[str, dict[str, Any]] = {}
    for weakness in root.iter():
        if _local_name(weakness.tag) != "Weakness":
            continue
        cwe_number = weakness.attrib.get("ID")
        if not cwe_number:
            continue
        cwe_id = f"CWE-{cwe_number}"
        description = ""
        for child in list(weakness):
            if _local_name(child.tag) == "Description":
                description = _excerpt("".join(child.itertext()), 420)
                break
        entries[cwe_id] = {
            "id": cwe_id,
            "name": _normalize_text(weakness.attrib.get("Name")),
            "status": _normalize_text(weakness.attrib.get("Status")),
            "abstraction": _normalize_text(weakness.attrib.get("Abstraction")),
            "summary": description,
            "url": f"https://cwe.mitre.org/data/definitions/{cwe_number}.html",
        }
    return {
        "count": len(entries),
        "entries": entries,
    }


def parse_capec_xml(path: Path) -> dict[str, Any]:
    root = ET.fromstring(path.read_bytes())
    entries: dict[str, dict[str, Any]] = {}
    by_cwe: dict[str, list[str]] = {}
    for pattern in root.iter():
        if _local_name(pattern.tag) != "Attack_Pattern":
            continue
        capec_number = pattern.attrib.get("ID")
        if not capec_number:
            continue
        capec_id = f"CAPEC-{capec_number}"
        summary = ""
        for child in list(pattern):
            if _local_name(child.tag) == "Description":
                summary = _excerpt("".join(child.itertext()), 420)
                break
        weaknesses: list[str] = []
        for child in pattern.iter():
            if _local_name(child.tag) != "Related_Weakness":
                continue
            cwe_id = child.attrib.get("CWE_ID")
            if not cwe_id:
                continue
            weakness_id = f"CWE-{cwe_id}"
            weaknesses.append(weakness_id)
            by_cwe.setdefault(weakness_id, []).append(capec_id)
        entries[capec_id] = {
            "id": capec_id,
            "name": _normalize_text(pattern.attrib.get("Name")),
            "summary": summary,
            "cwes": sorted(set(weaknesses)),
            "url": f"https://capec.mitre.org/data/definitions/{capec_number}.html",
        }
    return {
        "count": len(entries),
        "entries": entries,
        "by_cwe": {key: sorted(set(value)) for key, value in by_cwe.items()},
    }


def parse_nvd_feed(path: Path) -> dict[str, Any]:
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        payload = json.load(handle)
    entries: dict[str, dict[str, Any]] = {}
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = _normalize_text(cve.get("id"))
        if not cve_id:
            continue
        cpes = _collect_nvd_cpes(cve.get("configurations", {}))
        vendors, products = _nvd_product_index(cpes)
        weaknesses: set[str] = set()
        for weakness in cve.get("weaknesses", []):
            for description in weakness.get("description", []):
                value = _normalize_text(description.get("value"))
                if value.startswith("CWE-"):
                    weaknesses.add(value)
        entries[cve_id] = {
            "id": cve_id,
            "summary": _english_description(cve.get("descriptions")),
            "severity": _severity_from_nvd(cve.get("metrics", {})),
            "cwes": sorted(weaknesses),
            "published": _normalize_text(cve.get("published")),
            "last_modified": _normalize_text(cve.get("lastModified")),
            "cpes": cpes[:24],
            "vendors": vendors[:12],
            "products": products[:12],
        }
    return {
        "count": len(entries),
        "entries": entries,
        "generated_at": _normalize_text(payload.get("timestamp")),
    }


def parse_nvd_modified_feed(path: Path) -> dict[str, Any]:
    return parse_nvd_feed(path)


def parse_fstec_vuln_xml_zip(path: Path) -> dict[str, Any]:
    entries: dict[str, dict[str, Any]] = {}
    by_cve: dict[str, list[str]] = {}
    by_cwe: dict[str, list[str]] = {}
    with zipfile.ZipFile(path) as archive:
        xml_names = [name for name in archive.namelist() if name.endswith(".xml")]
        if not xml_names:
            raise RuntimeError("FSTEC vulnerability archive does not contain XML data.")
        with archive.open(xml_names[0]) as handle:
            for event, element in ET.iterparse(handle, events=("end",)):
                if _local_name(element.tag) != "vul":
                    continue
                bdu_id = _child_text(element, "identifier")
                if not bdu_id:
                    element.clear()
                    continue
                cves: set[str] = set()
                for identifier in element.findall("identifiers/identifier"):
                    value = _normalize_text(identifier.text)
                    if value.startswith("CVE-"):
                        cves.add(value)
                cwes: set[str] = set()
                for cwe in element.findall("cwes/cwe"):
                    cwe_id = _child_text(cwe, "identifier")
                    if cwe_id:
                        cwes.add(cwe_id)
                entry = {
                    "id": bdu_id,
                    "name": _excerpt(_child_text(element, "name"), 220),
                    "summary": _excerpt(_child_text(element, "description"), 420),
                    "severity": _excerpt(_child_text(element, "severity"), 120),
                    "status": _excerpt(_child_text(element, "vul_state"), 120),
                    "cves": sorted(cves),
                    "cwes": sorted(cwes),
                    "publication_date": _child_text(element, "publication_date"),
                    "last_updated": _child_text(element, "last_upd_date"),
                    "url": f"https://bdu.fstec.ru/vul/{bdu_id.replace('BDU:', '')}",
                }
                entries[bdu_id] = entry
                for cve_id in cves:
                    by_cve.setdefault(cve_id, []).append(bdu_id)
                for cwe_id in cwes:
                    by_cwe.setdefault(cwe_id, []).append(bdu_id)
                element.clear()
    return {
        "count": len(entries),
        "entries": entries,
        "by_cve": {key: sorted(set(value)) for key, value in by_cve.items()},
        "by_cwe": {key: sorted(set(value)) for key, value in by_cwe.items()},
    }


def parse_fstec_threats_xlsx(path: Path) -> dict[str, Any]:
    rows = _xlsx_rows(path)
    if len(rows) < 3:
        return {"count": 0, "entries": {}}
    header_map = rows[1]
    entries: dict[str, dict[str, Any]] = {}
    for row in rows[2:]:
        raw_id = row.get("A", "").strip()
        if not raw_id:
            continue
        threat_id = f"UBI-{raw_id}"
        url = ""
        if raw_id.isdigit():
            url = f"https://bdu.fstec.ru/threat/ubi.{int(raw_id):03d}"
        entries[threat_id] = {
            "id": threat_id,
            "name": _excerpt(row.get("B", ""), 220),
            "summary": _excerpt(row.get("C", ""), 420),
            "source_actor": _excerpt(row.get("D", ""), 180),
            "target": _excerpt(row.get("E", ""), 180),
            "confidentiality": row.get("F", "") == "1",
            "integrity": row.get("G", "") == "1",
            "availability": row.get("H", "") == "1",
            "published_at": _excel_serial_to_iso(row.get("I", "")),
            "last_updated": _excel_serial_to_iso(row.get("J", "")),
            "status": _excerpt(row.get("K", ""), 80),
            "notes": _excerpt(row.get("L", ""), 180),
            "url": url,
        }
    return {
        "count": len(entries),
        "entries": entries,
        "columns": {column: label for column, label in header_map.items() if label},
    }


def aggregate_nvd_indexes(indexes: dict[str, dict[str, Any]]) -> dict[str, Any]:
    entries: dict[str, dict[str, Any]] = {}
    mirrored_years: list[int] = []
    missing_years: list[int] = []

    for year in _nvd_years():
        key = f"nvd_year_{year}"
        yearly = indexes.get(key)
        if not yearly:
            missing_years.append(year)
            continue
        mirrored_years.append(year)
        for cve_id, item in (yearly.get("entries") or {}).items():
            entries[cve_id] = item

    modified = indexes.get("nvd_modified", {})
    for cve_id, item in (modified.get("entries") or {}).items():
        entries[cve_id] = item

    return {
        "count": len(entries),
        "entries": entries,
        "mirrored_years": mirrored_years,
        "missing_years": missing_years,
        "year_start": mirrored_years[0] if mirrored_years else None,
        "year_end": mirrored_years[-1] if mirrored_years else None,
        "year_count": len(mirrored_years),
        "modified_count": int(modified.get("count", 0)),
        "generated_at": _utc_now(),
    }


def _merge_lookup(indexes: dict[str, dict[str, Any]]) -> dict[str, Any]:
    cisa = indexes.get("cisa_kev", {})
    cwe = indexes.get("cwe", {})
    capec = indexes.get("capec", {})
    nvd = aggregate_nvd_indexes(indexes)
    fstec_vulns = indexes.get("fstec_vulns", {})
    fstec_threats = indexes.get("fstec_threats", {})

    merged_cves: dict[str, dict[str, Any]] = {}
    for cve_id, item in (nvd.get("entries") or {}).items():
        merged_cves[cve_id] = {
            "id": cve_id,
            "summary": item.get("summary", ""),
            "severity": item.get("severity", ""),
            "cwes": sorted(set(item.get("cwes", []))),
            "cpes": list(item.get("cpes", [])),
            "vendors": list(item.get("vendors", [])),
            "products": list(item.get("products", [])),
            "bdu_ids": [],
            "kev": False,
            "kev_name": "",
            "kev_required_action": "",
            "sources": ["NVD"],
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }

    for cve_id, item in (cisa.get("entries") or {}).items():
        current = merged_cves.setdefault(
            cve_id,
            {
                "id": cve_id,
                "summary": item.get("summary", ""),
                "severity": "",
                "cwes": [],
                "cpes": [],
                "vendors": [],
                "products": [],
                "bdu_ids": [],
                "kev": False,
                "kev_name": "",
                "kev_required_action": "",
                "sources": [],
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            },
        )
        current["kev"] = True
        current["kev_name"] = item.get("name", "")
        current["kev_required_action"] = item.get("required_action", "")
        if item.get("summary") and not current.get("summary"):
            current["summary"] = item["summary"]
        current["sources"] = sorted(set(current.get("sources", []) + ["CISA KEV"]))

    for bdu_id, item in (fstec_vulns.get("entries") or {}).items():
        for cve_id in item.get("cves", []):
            current = merged_cves.setdefault(
                cve_id,
                {
                    "id": cve_id,
                    "summary": item.get("summary", ""),
                    "severity": item.get("severity", ""),
                    "cwes": [],
                    "cpes": [],
                    "vendors": [],
                    "products": [],
                    "bdu_ids": [],
                    "kev": False,
                    "kev_name": "",
                    "kev_required_action": "",
                    "sources": [],
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                },
            )
            if item.get("summary") and not current.get("summary"):
                current["summary"] = item["summary"]
            if item.get("severity") and not current.get("severity"):
                current["severity"] = item["severity"]
            current["cwes"] = sorted(set(current.get("cwes", [])) | set(item.get("cwes", [])))
            current["bdu_ids"] = sorted(set(current.get("bdu_ids", [])) | {bdu_id})
            current["sources"] = sorted(set(current.get("sources", []) + ["FSTEC"]))

    return {
        "generated_at": _utc_now(),
        "cwe": cwe.get("entries", {}),
        "capec": capec.get("entries", {}),
        "capec_by_cwe": capec.get("by_cwe", {}),
        "cve": merged_cves,
        "bdu": fstec_vulns.get("entries", {}),
        "fstec_threats": fstec_threats.get("entries", {}),
    }


def sync_knowledge_base(
    *,
    force: bool = False,
    base_dir: Path | None = None,
    trigger: str = "manual",
) -> dict[str, Any]:
    with _KB_SYNC_RUN_LOCK:
        _update_sync_state(
            running=True,
            trigger=trigger,
            started_at=_utc_now(),
            finished_at=None,
            last_error="",
        )
        try:
            paths = _paths(base_dir)
            index_dir = paths["index_dir"]
            raw_dir = paths["raw_dir"]
            indexes: dict[str, dict[str, Any]] = {}
            visible_sources: dict[str, dict[str, Any]] = {}
            feed_runs: dict[str, dict[str, Any]] = {}
            totals: dict[str, int] = {}

            for spec in build_feed_specs():
                parser = globals()[spec["parser"]]
                raw_path = raw_dir / spec["filename"]
                index_path = index_dir / spec["index_filename"]
                source_status = {
                    "key": spec["key"],
                    "label": spec["label"],
                    "url": spec["url"],
                    "raw_path": str(raw_path),
                    "index_path": str(index_path),
                    "status": "ready",
                    "count": 0,
                    "synced_at": _utc_now(),
                    "ssl_fallback_used": False,
                    "error": "",
                }
                try:
                    if force or not raw_path.exists() or _is_stale(raw_path):
                        download_meta = _download_feed(spec["url"], raw_path)
                        source_status["bytes"] = download_meta["bytes"]
                        source_status["ssl_fallback_used"] = download_meta["ssl_fallback_used"]
                    parsed = parser(raw_path)
                    indexes[spec["key"]] = parsed
                    source_status["count"] = int(parsed.get("count", 0))
                    totals[spec["key"]] = int(parsed.get("count", 0))
                    _write_json(index_path, parsed)
                except Exception as exc:  # pragma: no cover - exercised through live sync
                    source_status["status"] = "failed"
                    source_status["error"] = str(exc)
                    if index_path.exists():
                        cached = _read_json(index_path)
                        indexes[spec["key"]] = cached
                        source_status["status"] = "cached"
                        source_status["count"] = int(cached.get("count", 0))
                        totals[spec["key"]] = int(cached.get("count", 0))
                feed_runs[spec["key"]] = source_status
                if spec.get("status_visible", True):
                    visible_sources[spec["key"]] = source_status

            lookup = _merge_lookup(indexes)
            _write_json(paths["lookup"], lookup)
            nvd_yearly = aggregate_nvd_indexes(indexes)
            if KB_NVD_YEARLY_MIRROR:
                nvd_status_values = [
                    feed_runs.get(f"nvd_year_{year}", {}).get("status", "missing")
                    for year in _nvd_years()
                ]
                yearly_status = "ready"
                if any(status == "failed" for status in nvd_status_values):
                    yearly_status = "failed"
                elif any(status == "cached" for status in nvd_status_values):
                    yearly_status = "cached"
                visible_sources["nvd_yearly"] = {
                    "key": "nvd_yearly",
                    "label": "NVD Yearly Mirror",
                    "url": "https://nvd.nist.gov/vuln/data-feeds",
                    "raw_path": str(raw_dir),
                    "index_path": str(index_dir / "lookup.json"),
                    "status": yearly_status,
                    "count": int(nvd_yearly.get("count", 0)),
                    "synced_at": _utc_now(),
                    "ssl_fallback_used": False,
                    "error": "",
                    "year_start": nvd_yearly.get("year_start"),
                    "year_end": nvd_yearly.get("year_end"),
                    "year_count": nvd_yearly.get("year_count", 0),
                    "mirrored_years": nvd_yearly.get("mirrored_years", []),
                    "missing_years": nvd_yearly.get("missing_years", []),
                    "modified_count": nvd_yearly.get("modified_count", 0),
                }
                totals["nvd_yearly"] = int(nvd_yearly.get("count", 0))
            status = {
                "available": bool(lookup.get("cve") or lookup.get("cwe") or lookup.get("bdu")),
                "updated_at": _utc_now(),
                "source_count": len(visible_sources),
                "successful_sources": sum(1 for item in visible_sources.values() if item["status"] in {"ready", "cached"}),
                "failed_sources": sum(1 for item in visible_sources.values() if item["status"] == "failed"),
                "sources": visible_sources,
                "sources_list": sorted(visible_sources.values(), key=lambda item: item["label"]),
                "feed_runs": feed_runs,
                "totals": totals,
                "nvd_yearly": {
                    "enabled": KB_NVD_YEARLY_MIRROR,
                    "year_start": nvd_yearly.get("year_start"),
                    "year_end": nvd_yearly.get("year_end"),
                    "year_count": nvd_yearly.get("year_count", 0),
                    "mirrored_years": nvd_yearly.get("mirrored_years", []),
                    "missing_years": nvd_yearly.get("missing_years", []),
                    "count": nvd_yearly.get("count", 0),
                    "modified_count": nvd_yearly.get("modified_count", 0),
                },
                "weekly_schedule": _weekly_schedule_payload(),
            }
            _write_json(paths["status"], status)
            _update_sync_state(
                running=False,
                trigger=trigger,
                finished_at=_utc_now(),
                last_error="",
            )
            return status
        except Exception as exc:
            _update_sync_state(
                running=False,
                trigger=trigger,
                finished_at=_utc_now(),
                last_error=str(exc),
            )
            raise


def _background_sync_runner(*, force: bool, base_dir: Path | None, trigger: str) -> None:
    global _KB_SYNC_THREAD
    try:
        sync_knowledge_base(force=force, base_dir=base_dir, trigger=trigger)
    finally:
        with _KB_SYNC_STATE_LOCK:
            if _KB_SYNC_THREAD is threading.current_thread():
                _KB_SYNC_THREAD = None


def start_background_knowledge_base_sync(*, force: bool = True, base_dir: Path | None = None) -> bool:
    global _KB_SYNC_THREAD
    with _KB_SYNC_STATE_LOCK:
        if _KB_SYNC_STATE.get("running"):
            return False
        if _KB_SYNC_THREAD and _KB_SYNC_THREAD.is_alive():
            return False
        _KB_SYNC_STATE.update(
            {
                "running": True,
                "trigger": "manual",
                "started_at": _utc_now(),
                "finished_at": None,
                "last_error": "",
            }
        )
        thread = threading.Thread(
            target=_background_sync_runner,
            kwargs={"force": force, "base_dir": base_dir, "trigger": "manual"},
            name="qa-kb-manual-sync",
            daemon=True,
        )
        _KB_SYNC_THREAD = thread
        thread.start()
        return True


def knowledge_base_status(base_dir: Path | None = None) -> dict[str, Any]:
    status_path = _paths(base_dir)["status"]
    live_sync = knowledge_base_sync_state()
    if KB_AUTOSYNC and (not status_path.exists() or _is_stale(status_path)) and not live_sync.get("running"):
        payload = sync_knowledge_base(
            force=not status_path.exists(),
            base_dir=base_dir,
            trigger="autosync",
        )
        payload["sync"] = knowledge_base_sync_state()
        return payload
    if not status_path.exists():
        payload = {
            "available": False,
            "updated_at": None,
            "stale": True,
            "source_count": 0,
            "successful_sources": 0,
            "failed_sources": 0,
            "sources": {},
            "sources_list": [],
            "feed_runs": {},
            "totals": {},
            "nvd_yearly": {
                "enabled": KB_NVD_YEARLY_MIRROR,
                "year_start": KB_NVD_YEAR_START if KB_NVD_YEARLY_MIRROR else None,
                "year_end": KB_NVD_YEAR_END if KB_NVD_YEARLY_MIRROR else None,
                "year_count": len(_nvd_years()) if KB_NVD_YEARLY_MIRROR else 0,
                "mirrored_years": [],
                "missing_years": _nvd_years() if KB_NVD_YEARLY_MIRROR else [],
                "count": 0,
                "modified_count": 0,
            },
            "weekly_schedule": _weekly_schedule_payload(),
            "message": "Local intelligence mirror has not been synced yet.",
        }
        payload["sync"] = live_sync
        return payload
    payload = _load_cached_json(status_path)
    updated_at = payload.get("updated_at")
    stale = True
    if updated_at:
        try:
            moment = datetime.fromisoformat(updated_at)
            stale = (datetime.now(timezone.utc) - moment).total_seconds() > KB_STALE_AFTER_SECONDS
        except ValueError:
            stale = True
    payload["stale"] = stale
    payload["message"] = (
        "Local intelligence mirror is available."
        if payload.get("available")
        else "Local intelligence mirror is only partially available."
    )
    payload["sources_list"] = sorted(payload.get("sources", {}).values(), key=lambda item: item["label"])
    payload.setdefault("feed_runs", {})
    payload.setdefault(
        "nvd_yearly",
        {
            "enabled": KB_NVD_YEARLY_MIRROR,
            "year_start": KB_NVD_YEAR_START if KB_NVD_YEARLY_MIRROR else None,
            "year_end": KB_NVD_YEAR_END if KB_NVD_YEARLY_MIRROR else None,
            "year_count": len(_nvd_years()) if KB_NVD_YEARLY_MIRROR else 0,
            "mirrored_years": [],
            "missing_years": _nvd_years() if KB_NVD_YEARLY_MIRROR else [],
            "count": 0,
            "modified_count": 0,
        },
    )
    if "weekly_schedule" not in payload and "nightly_schedule" in payload:
        legacy = payload.get("nightly_schedule") or {}
        payload["weekly_schedule"] = {
            "enabled": legacy.get("enabled", False),
            "day": KB_WEEKLY_SYNC_DAY,
            "day_label": WEEKDAY_LABELS[KB_WEEKLY_SYNC_DAY],
            "hour": legacy.get("hour", KB_WEEKLY_SYNC_HOUR),
            "minute": legacy.get("minute", KB_WEEKLY_SYNC_MINUTE),
            "next_run_at": legacy.get("next_run_at"),
        }
    payload.setdefault("weekly_schedule", _weekly_schedule_payload())
    payload["sync"] = live_sync
    return payload


def load_knowledge_base(base_dir: Path | None = None) -> dict[str, Any]:
    lookup_path = _paths(base_dir)["lookup"]
    if not lookup_path.exists():
        return {}
    return _load_cached_json(lookup_path)


def _safe_read_text(path: Path) -> str:
    if not path.exists() or path.stat().st_size > MAX_TEXT_FILE_SIZE:
        return ""
    for encoding in ("utf-8", "cp1251", "latin-1"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
    return ""


def extract_reference_ids(*chunks: str) -> dict[str, list[str]]:
    found: dict[str, set[str]] = {key: set() for key in ID_PATTERNS}
    for chunk in chunks:
        if not chunk:
            continue
        for key, pattern in ID_PATTERNS.items():
            for match in pattern.findall(chunk):
                found[key].add(match.upper())
    return {key: sorted(values) for key, values in found.items()}


def _reference_payload(kind: str, identifier: str, lookup: dict[str, Any]) -> dict[str, Any] | None:
    if kind == "cwe":
        item = (lookup.get("cwe") or {}).get(identifier)
        if not item:
            return None
        return {
            "id": identifier,
            "kind": "cwe",
            "title": item.get("name") or identifier,
            "source": "MITRE CWE",
            "summary": item.get("summary", ""),
            "url": item.get("url", ""),
            "flags": [],
        }
    if kind == "capec":
        item = (lookup.get("capec") or {}).get(identifier)
        if not item:
            return None
        return {
            "id": identifier,
            "kind": "capec",
            "title": item.get("name") or identifier,
            "source": "MITRE CAPEC",
            "summary": item.get("summary", ""),
            "url": item.get("url", ""),
            "flags": [],
        }
    if kind == "cve":
        item = (lookup.get("cve") or {}).get(identifier)
        if not item:
            return None
        flags: list[str] = []
        if item.get("kev"):
            flags.append("KEV")
        if item.get("bdu_ids"):
            flags.append("FSTEC")
        return {
            "id": identifier,
            "kind": "cve",
            "title": identifier,
            "source": ", ".join(item.get("sources", [])) or "Local CVE mirror",
            "summary": item.get("summary", ""),
            "url": item.get("url", ""),
            "flags": flags,
            "severity": item.get("severity", ""),
            "related_bdu_ids": item.get("bdu_ids", []),
        }
    if kind == "bdu":
        item = (lookup.get("bdu") or {}).get(identifier)
        if not item:
            return None
        return {
            "id": identifier,
            "kind": "bdu",
            "title": item.get("name") or identifier,
            "source": "FSTEC BDU",
            "summary": item.get("summary", ""),
            "url": item.get("url", ""),
            "flags": [flag for flag in [item.get("severity"), item.get("status")] if flag],
        }
    if kind == "fstec-threat":
        item = (lookup.get("fstec_threats") or {}).get(identifier)
        if not item:
            return None
        return {
            "id": identifier,
            "kind": "fstec-threat",
            "title": item.get("name") or identifier,
            "source": "FSTEC Threat Catalog",
            "summary": item.get("summary", ""),
            "url": item.get("url", ""),
            "flags": [flag for flag in [item.get("status")] if flag],
        }
    return None


def _finding_hints(finding: Finding) -> list[str]:
    haystack = " ".join(
        [
            finding.title,
            finding.description,
            finding.source,
            finding.recommendation,
        ]
    )
    hints: set[str] = set()
    for pattern, cwes in FINDING_CWE_HINTS:
        if pattern.search(haystack):
            hints.update(cwes)
    return sorted(hints)


def _reference_score(item: dict[str, Any]) -> tuple[int, str]:
    score = REFERENCE_PRIORITY.get(item.get("kind", ""), 0)
    if "KEV" in item.get("flags", []):
        score += 8
    if "FSTEC" in item.get("flags", []):
        score += 4
    return (score, item.get("id", ""))


def _expand_related_references(references: list[dict[str, Any]], lookup: dict[str, Any]) -> list[dict[str, Any]]:
    expanded: dict[str, dict[str, Any]] = {item["id"]: item for item in references}
    capec_by_cwe = lookup.get("capec_by_cwe") or {}
    for item in list(references):
        if item.get("kind") != "cwe":
            continue
        for capec_id in capec_by_cwe.get(item["id"], [])[:2]:
            reference = _reference_payload("capec", capec_id, lookup)
            if reference:
                expanded.setdefault(reference["id"], reference)
    for item in list(references):
        if item.get("kind") != "cve":
            continue
        for bdu_id in item.get("related_bdu_ids", [])[:2]:
            reference = _reference_payload("bdu", bdu_id, lookup)
            if reference:
                expanded.setdefault(reference["id"], reference)
    return sorted(expanded.values(), key=_reference_score, reverse=True)


def _resolve_ids(found: dict[str, list[str]], lookup: dict[str, Any]) -> list[dict[str, Any]]:
    references: dict[str, dict[str, Any]] = {}
    for kind, identifiers in found.items():
        for identifier in identifiers:
            payload = _reference_payload(kind, identifier, lookup)
            if payload:
                references[payload["id"]] = payload
    return sorted(references.values(), key=_reference_score, reverse=True)


def _project_reference_matches(root: Path, files: list[Path], lookup: dict[str, Any]) -> list[dict[str, Any]]:
    found: dict[str, set[str]] = {key: set() for key in ID_PATTERNS}
    for path in files:
        if len(found["cve"]) + len(found["cwe"]) + len(found["capec"]) + len(found["bdu"]) > 60:
            break
        text = _safe_read_text(path)
        if not text:
            continue
        matched = extract_reference_ids(text)
        for key, values in matched.items():
            found[key].update(values)
    resolved = _resolve_ids({key: sorted(values) for key, values in found.items()}, lookup)
    return resolved[:12]


def enrich_findings_with_knowledge_base(
    findings: list[Finding],
    *,
    root: Path,
    files: list[Path],
    base_dir: Path | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    status = knowledge_base_status(base_dir)
    lookup = load_knowledge_base(base_dir)
    if not lookup:
        for finding in findings:
            finding.references = []
        return findings, {
            "available": False,
            "updated_at": status.get("updated_at"),
            "stale": status.get("stale", True),
            "source_count": status.get("successful_sources", 0),
            "matched_reference_count": 0,
            "findings_with_references": 0,
            "project_reference_count": 0,
            "matched_reference_breakdown": {},
            "top_references": [],
            "project_references": [],
            "sources": status.get("sources_list", []),
            "totals": status.get("totals", {}),
        }

    unique_refs: dict[str, dict[str, Any]] = {}
    breakdown: dict[str, int] = {}
    findings_with_references = 0
    for finding in findings:
        explicit = extract_reference_ids(
            finding.title,
            finding.description,
            finding.source,
            finding.recommendation,
        )
        hinted = {"cwe": _finding_hints(finding), "cve": [], "capec": [], "bdu": []}
        resolved = _resolve_ids(explicit, lookup)
        resolved.extend(_resolve_ids(hinted, lookup))
        references = _expand_related_references(resolved, lookup)
        deduped: dict[str, dict[str, Any]] = {}
        for reference in references:
            deduped.setdefault(reference["id"], reference)
        finding.references = sorted(deduped.values(), key=_reference_score, reverse=True)
        if finding.references:
            findings_with_references += 1
        for reference in finding.references:
            unique_refs.setdefault(reference["id"], reference)
            breakdown[reference["kind"]] = breakdown.get(reference["kind"], 0) + 1

    project_references = _project_reference_matches(root, files, lookup)
    for reference in project_references:
        unique_refs.setdefault(reference["id"], reference)
        breakdown[reference["kind"]] = breakdown.get(reference["kind"], 0) + 1

    top_references = sorted(unique_refs.values(), key=_reference_score, reverse=True)[:12]
    return findings, {
        "available": True,
        "updated_at": status.get("updated_at"),
        "stale": status.get("stale", True),
        "source_count": status.get("successful_sources", 0),
        "matched_reference_count": len(unique_refs),
        "findings_with_references": findings_with_references,
        "project_reference_count": len(project_references),
        "matched_reference_breakdown": breakdown,
        "top_references": top_references,
        "project_references": project_references,
        "sources": status.get("sources_list", []),
        "totals": status.get("totals", {}),
    }


def next_weekly_sync_at(now: datetime | None = None) -> datetime:
    current = now or datetime.now().astimezone()
    scheduled = current.replace(
        hour=KB_WEEKLY_SYNC_HOUR,
        minute=KB_WEEKLY_SYNC_MINUTE,
        second=0,
        microsecond=0,
    )
    days_ahead = (KB_WEEKLY_SYNC_DAY - current.weekday()) % 7
    scheduled += timedelta(days=days_ahead)
    if scheduled <= current:
        scheduled += timedelta(days=7)
    return scheduled


def seconds_until_next_weekly_sync(now: datetime | None = None) -> float:
    current = now or datetime.now().astimezone()
    return max(1.0, (next_weekly_sync_at(current) - current).total_seconds())


def _weekly_sync_loop(base_dir: Path | None, stop_event: threading.Event) -> None:
    # Фоновый цикл спит до ближайшего недельного окна и затем запускает синхронизацию зеркала.
    while not stop_event.is_set():
        if stop_event.wait(seconds_until_next_weekly_sync()):
            return
        try:
            sync_knowledge_base(force=False, base_dir=base_dir, trigger="weekly")
        except Exception:
            continue


def start_knowledge_base_scheduler(base_dir: Path | None = None) -> None:
    global _KB_SCHEDULER_STOP, _KB_SCHEDULER_THREAD
    if not KB_WEEKLY_SYNC:
        return
    with _KB_SCHEDULER_LOCK:
        if _KB_SCHEDULER_THREAD and _KB_SCHEDULER_THREAD.is_alive():
            return
        stop_event = threading.Event()
        thread = threading.Thread(
            target=_weekly_sync_loop,
            args=(base_dir, stop_event),
            name="qa-kb-weekly-sync",
            daemon=True,
        )
        _KB_SCHEDULER_STOP = stop_event
        _KB_SCHEDULER_THREAD = thread
        thread.start()


def stop_knowledge_base_scheduler() -> None:
    global _KB_SCHEDULER_STOP, _KB_SCHEDULER_THREAD
    with _KB_SCHEDULER_LOCK:
        if _KB_SCHEDULER_STOP is not None:
            _KB_SCHEDULER_STOP.set()
        if _KB_SCHEDULER_THREAD is not None:
            _KB_SCHEDULER_THREAD.join(timeout=1.0)
        _KB_SCHEDULER_STOP = None
        _KB_SCHEDULER_THREAD = None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sync the local vulnerability intelligence mirror.")
    parser.add_argument("--force", action="store_true", help="Re-download feeds even when cached copies exist.")
    parser.add_argument("--base-dir", default="", help="Optional knowledge-base directory override.")
    args = parser.parse_args(argv)
    base_dir = Path(args.base_dir) if args.base_dir else None
    status = sync_knowledge_base(force=args.force, base_dir=base_dir, trigger="cli")
    print(json.dumps(status, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())

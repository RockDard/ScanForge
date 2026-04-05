import json
import tempfile
import unittest
import zipfile
from datetime import datetime
from pathlib import Path

from qa_portal.knowledge_base import (
    aggregate_nvd_indexes,
    enrich_findings_with_knowledge_base,
    extract_reference_ids,
    next_weekly_sync_at,
    parse_fstec_threats_xlsx,
    seconds_until_next_weekly_sync,
)
from qa_portal.models import Finding


class KnowledgeBaseTests(unittest.TestCase):
    def test_extract_reference_ids_recognizes_common_identifiers(self):
        found = extract_reference_ids(
            "Refs: CVE-2026-1234 CWE-120 CAPEC-100 BDU:2024-02967"
        )
        self.assertEqual(found["cve"], ["CVE-2026-1234"])
        self.assertEqual(found["cwe"], ["CWE-120"])
        self.assertEqual(found["capec"], ["CAPEC-100"])
        self.assertEqual(found["bdu"], ["BDU:2024-02967"])

    def test_enrich_findings_uses_lookup_and_project_references(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            kb_dir = root / "kb"
            index_dir = kb_dir / "indexes"
            project_dir = root / "project"
            source_file = project_dir / "main.cpp"
            index_dir.mkdir(parents=True, exist_ok=True)
            project_dir.mkdir(parents=True, exist_ok=True)
            source_file.write_text(
                "// CVE-2026-1234\nint main() { return 0; }\n",
                encoding="utf-8",
            )

            lookup = {
                "generated_at": "2026-04-05T10:00:00+00:00",
                "cwe": {
                    "CWE-120": {
                        "id": "CWE-120",
                        "name": "Buffer Copy without Checking Size of Input",
                        "summary": "Copies input without verifying length.",
                        "url": "https://cwe.mitre.org/data/definitions/120.html",
                    }
                },
                "capec": {
                    "CAPEC-100": {
                        "id": "CAPEC-100",
                        "name": "Overflow Buffers",
                        "summary": "Attacker feeds oversized input.",
                        "url": "https://capec.mitre.org/data/definitions/100.html",
                    }
                },
                "capec_by_cwe": {
                    "CWE-120": ["CAPEC-100"],
                },
                "cve": {
                    "CVE-2026-1234": {
                        "id": "CVE-2026-1234",
                        "summary": "Critical overflow in parser.",
                        "severity": "9.8 CRITICAL",
                        "cwes": ["CWE-120"],
                        "bdu_ids": ["BDU:2024-02967"],
                        "kev": True,
                        "sources": ["NVD", "CISA KEV", "FSTEC"],
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
                    }
                },
                "bdu": {
                    "BDU:2024-02967": {
                        "id": "BDU:2024-02967",
                        "name": "Локальная запись ФСТЭК",
                        "summary": "Описание из локального зеркала.",
                        "severity": "Высокий",
                        "status": "Опубликована",
                        "url": "https://bdu.fstec.ru/vul/2024-02967",
                    }
                },
                "fstec_threats": {},
            }
            status = {
                "available": True,
                "updated_at": "2026-04-05T10:10:00+00:00",
                "source_count": 5,
                "successful_sources": 5,
                "failed_sources": 0,
                "sources": {
                    "cwe": {"key": "cwe", "label": "MITRE CWE", "status": "ready", "count": 1},
                    "capec": {"key": "capec", "label": "MITRE CAPEC", "status": "ready", "count": 1},
                    "cisa_kev": {"key": "cisa_kev", "label": "CISA KEV", "status": "ready", "count": 1},
                    "nvd_modified": {"key": "nvd_modified", "label": "NVD Modified Feed", "status": "ready", "count": 1},
                    "fstec_vulns": {"key": "fstec_vulns", "label": "FSTEC BDU Vulnerabilities", "status": "ready", "count": 1},
                },
                "totals": {"cwe": 1, "capec": 1, "cisa_kev": 1, "nvd_modified": 1, "fstec_vulns": 1},
            }
            (index_dir / "lookup.json").write_text(json.dumps(lookup, ensure_ascii=False), encoding="utf-8")
            (index_dir / "status.json").write_text(json.dumps(status, ensure_ascii=False), encoding="utf-8")

            finding = Finding(
                category="security",
                severity="high",
                title="Potential buffer overflow",
                description="Matched parser path similar to CVE-2026-1234.",
                source="built-in-security-rules",
                recommendation="Replace unsafe copy logic.",
            )

            findings, summary = enrich_findings_with_knowledge_base(
                [finding],
                root=project_dir,
                files=[source_file],
                base_dir=kb_dir,
            )

            reference_ids = {item["id"] for item in findings[0].references}
            self.assertIn("CWE-120", reference_ids)
            self.assertIn("CAPEC-100", reference_ids)
            self.assertIn("CVE-2026-1234", reference_ids)
            self.assertIn("BDU:2024-02967", reference_ids)
            self.assertEqual(summary["matched_reference_count"], 4)
            self.assertEqual(summary["project_reference_count"], 1)

    def test_parse_fstec_threats_xlsx_reads_rows(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            xlsx_path = Path(temp_dir) / "thrlist.xlsx"
            with zipfile.ZipFile(xlsx_path, "w") as archive:
                archive.writestr(
                    "xl/sharedStrings.xml",
                    """<?xml version="1.0" encoding="UTF-8"?>
                    <sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="6" uniqueCount="6">
                      <si><t>Идентификатор УБИ</t></si>
                      <si><t>Наименование УБИ</t></si>
                      <si><t>Описание</t></si>
                      <si><t>Дата включения угрозы в БнД УБИ</t></si>
                      <si><t>Дата последнего изменения данных</t></si>
                      <si><t>Статус угрозы</t></si>
                    </sst>""",
                )
                archive.writestr(
                    "xl/worksheets/sheet1.xml",
                    """<?xml version="1.0" encoding="UTF-8"?>
                    <worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
                      <sheetData>
                        <row r="1"><c r="A1" t="s"><v>0</v></c></row>
                        <row r="2">
                          <c r="A2" t="s"><v>0</v></c>
                          <c r="B2" t="s"><v>1</v></c>
                          <c r="C2" t="s"><v>2</v></c>
                          <c r="I2" t="s"><v>3</v></c>
                          <c r="J2" t="s"><v>4</v></c>
                          <c r="K2" t="s"><v>5</v></c>
                        </row>
                        <row r="3">
                          <c r="A3"><v>7</v></c>
                          <c r="B3" t="inlineStr"><is><t>Тестовая угроза</t></is></c>
                          <c r="C3" t="inlineStr"><is><t>Описание угрозы</t></is></c>
                          <c r="I3"><v>42083</v></c>
                          <c r="J3"><v>43504</v></c>
                          <c r="K3" t="inlineStr"><is><t>Опубликована</t></is></c>
                        </row>
                      </sheetData>
                    </worksheet>""",
                )

            parsed = parse_fstec_threats_xlsx(xlsx_path)
            self.assertEqual(parsed["count"], 1)
            threat = parsed["entries"]["UBI-7"]
            self.assertEqual(threat["name"], "Тестовая угроза")
            self.assertEqual(threat["status"], "Опубликована")
            self.assertEqual(threat["published_at"], "2015-03-20")

    def test_aggregate_nvd_indexes_prefers_modified_feed_for_same_cve(self):
        aggregated = aggregate_nvd_indexes(
            {
                "nvd_year_2025": {
                    "count": 1,
                    "entries": {
                        "CVE-2025-0001": {
                            "id": "CVE-2025-0001",
                            "summary": "Yearly feed value",
                            "severity": "5.0 MEDIUM",
                            "cwes": ["CWE-120"],
                        }
                    },
                },
                "nvd_modified": {
                    "count": 2,
                    "entries": {
                        "CVE-2025-0001": {
                            "id": "CVE-2025-0001",
                            "summary": "Modified feed value",
                            "severity": "9.8 CRITICAL",
                            "cwes": ["CWE-120"],
                        },
                        "CVE-2026-0002": {
                            "id": "CVE-2026-0002",
                            "summary": "Fresh modified CVE",
                            "severity": "7.5 HIGH",
                            "cwes": ["CWE-78"],
                        },
                    },
                },
            }
        )

        self.assertEqual(aggregated["count"], 2)
        self.assertEqual(aggregated["entries"]["CVE-2025-0001"]["summary"], "Modified feed value")
        self.assertEqual(aggregated["entries"]["CVE-2026-0002"]["severity"], "7.5 HIGH")

    def test_weekly_schedule_helpers_roll_to_next_window(self):
        now = datetime.fromisoformat("2026-04-05T23:59:30+03:00")
        scheduled = next_weekly_sync_at(now)
        seconds = seconds_until_next_weekly_sync(now)

        self.assertGreater(seconds, 0)
        self.assertGreater(scheduled, now)
        self.assertIn(scheduled.hour, range(24))
        self.assertIn(scheduled.minute, range(60))
        self.assertIn(scheduled.weekday(), range(7))


if __name__ == "__main__":
    unittest.main()

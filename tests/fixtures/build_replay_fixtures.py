"""Regenerates tests/fixtures/replay/: a tiny CISA KEV catalog and two EPSS daily score files.

CVSS for the rebuild comes from tests/fixtures/oebc/mini.json.gz.
"""

import gzip
import json
from pathlib import Path

HERE = Path(__file__).parent / "replay"

KEV = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.11.13",
    "dateReleased": "2026-11-13T17:49:24.9532Z",
    "count": 2,
    "vulnerabilities": [
        {"cveID": "CVE-2020-0001", "vendorProject": "Django", "product": "Django",
         "dateAdded": "2022-03-01", "dueDate": "2022-03-15",
         "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2024-0010", "vendorProject": "BerriAI", "product": "litellm",
         "dateAdded": "2026-11-12", "dueDate": "2026-12-03",
         "knownRansomwareCampaignUse": "Unknown"},
    ],
}

# score_date -> {cve: epss}
EPSS = {
    "2026-11-01": {"CVE-2024-0010": 0.05, "CVE-2024-0002": 0.2, "CVE-2099-0001": 0.5},
    "2026-11-08": {"CVE-2024-0010": 0.07, "CVE-2024-0002": 0.005, "CVE-2099-0001": 0.0001},
}

if __name__ == "__main__":
    (HERE / "epss").mkdir(parents=True, exist_ok=True)
    (HERE / "kev.json").write_text(json.dumps(KEV, indent=1) + "\n")
    for day, scores in EPSS.items():
        lines = [f"#model_version:v2025.03.14,score_date:{day}T00:00:00Z", "cve,epss,percentile"]
        lines += [f"{c},{s},0.5" for c, s in sorted(scores.items())]
        with gzip.GzipFile(HERE / "epss" / f"epss_scores-{day}.csv.gz", "wb", mtime=0) as f:
            f.write(("\n".join(lines) + "\n").encode())

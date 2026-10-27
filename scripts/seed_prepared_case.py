"""CLI script to seed the RansomEye competition prepared ransomware case.

Usage:
    python scripts/seed_prepared_case.py [--database data/ransomeye.db]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add src to python path if run directly
project_root = Path(__file__).resolve().parent.parent
src_dir = project_root / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from ransomeye.prepared_case import PREPARED_CASE_ID, PREPARED_CASE_NAME, seed_prepared_case


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Seed the RansomEye competition demonstration ransomware case."
    )
    parser.add_argument(
        "--database",
        "-d",
        type=Path,
        default=Path("data") / "ransomeye.db",
        help="Path to target RansomEye SQLite database (default: data/ransomeye.db)",
    )
    parser.add_argument(
        "--artifacts-dir",
        "-a",
        type=Path,
        default=Path("samples") / "prepared_case",
        help="Directory to store synthetic evidence artifacts (default: samples/prepared_case)",
    )

    args = parser.parse_args()
    db_path = args.database.resolve()
    art_dir = args.artifacts_dir.resolve()

    print("=" * 60)
    print("RANSOMEYE — SEEDING PREPARED INVESTIGATION CASE")
    print("=" * 60)
    print(f"Target Database : {db_path}")
    print(f"Artifacts Dir   : {art_dir}")
    print(f"Case ID         : {PREPARED_CASE_ID}")
    print(f"Case Name       : {PREPARED_CASE_NAME}")
    print("=" * 60)

    try:
        summary = seed_prepared_case(db_path, art_dir)
        print("\nCase seeded successfully:")
        print(f"  - Case ID           : {summary['case_id']}")
        print(f"  - Host              : {summary['host']}")
        print(f"  - Events Count      : {summary['events_count']}")
        print(f"  - Findings Count    : {summary['findings_count']}")
        print(f"  - Threat Score      : {summary['score']} ({summary['severity']})")
        print(f"  - Confidence        : {summary['confidence']:.2f}")
        print(f"  - Correlated Incidents: {summary['correlations_count']}")
        print(f"  - Custody Entries   : {summary['custody_count']}")
        print(f"  - MITRE Techniques  : {', '.join(summary['techniques'])}")
        print("\nInvestigation case is ready for analyst inspection and live demonstration.")
        return 0
    except Exception as exc:
        print(f"\n[ERROR] Failed to seed prepared case: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

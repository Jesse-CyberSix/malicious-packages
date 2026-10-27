import csv
import json
import argparse

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Set, Tuple

# ============================================================================
# Configuration
# ============================================================================

RECENT_DAYS = 365   # lookback period for malicious packages to keep feed from blowing up
# TODO: Add support for custom full record date limit

# this is passed into build_feed(<source_ecosystem>, <output_ecosystem>)
# future support for package managers like PyPI may be added
# the output ecosystem can be customized if the source name isn't preferred
SUPPORTED_ECOSYSTEMS = {
    "npm": "npm"
}
# TODO: Add support for other ecosystems

SOURCE_ROOT = Path("upstream/osv/malicious")
OUTPUT_ROOT = Path("feeds")

# ============================================================================
# Helpers
# ============================================================================

# the source timestamp format needs to be corrected for Python use
def parse_timestamp(value):

    if not value:
        return None

    value = value.strip()

    # remove fractional seconds and convert to UTC offset for Python
    if "." in value:
        value = value.split(".", 1)[0] + "+00:00"
    # convert Zulu time without fractional seconds to UTC offset for Python
    elif value.endswith("Z"):
        value = value[:-1] + "+00:00"

    return datetime.fromisoformat(value)


def write_csv(
    path: Path,
    rows: Set[Tuple[str, str, str]]
):
    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        path,
        "w",
        encoding="utf-8",
        newline=""
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "Package",
            "Version",
            "MalId"
        ])

        writer.writerows(
            sorted(
                rows,
                key=lambda x: (
                    x[0].lower(),
                    x[1],
                    x[2]
                )
            )
        )

# ============================================================================
# Feed Builder
# ============================================================================

def build_feed(source_ecosystem, output_ecosystem, dry_run=False):

    source_dir = SOURCE_ROOT / source_ecosystem

    # set() automatically deduplicates rows
    full_rows = set()   # all entries, regardless of when modified
    recent_rows = set() # only recent entries for lighter queries, based on RECENT_DAYS value

    cutoff = (
        datetime.now(timezone.utc)
        - timedelta(days=RECENT_DAYS)
    )

    for file in source_dir.rglob("*.json"):

        try:
            report = json.loads(
                file.read_text(
                    encoding="utf-8"
                )
            )

        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            print(
                f"Failed to parse {file}: {error}"
            )
            continue

        # Skip withdrawn reports
        if report.get("withdrawn"):
            continue

        mal_id = (
            str(
                report.get("id", "")
            ).strip()
        )

        # skip empty ID/malformed reports
        if not mal_id:
            continue

        # modified date is the priority, otherwise use published date
        modified = (
            parse_timestamp(
                report.get("modified")
            )
            or
            parse_timestamp(
                report.get("published")
            )
        )

        for affected in report.get(
            "affected",
            []
        ):

            if not isinstance(
                affected,
                dict
            ):
                continue

            package_info = affected.get(
                "package",
                {}
            )

            ecosystem = package_info.get(
                "ecosystem",
                ""
            )

            if (
                ecosystem.lower() != source_ecosystem.lower()
            ):
                continue

            package = (
                str(
                    package_info.get(
                        "name",
                        ""
                    )
                ).strip()
            )

            if not package:
                continue

            versions = affected.get(
                "versions"
            )

            # creates empty list if no versions specified, to simplify row generation logic
            if not versions:
                versions = [""]

            for version in versions:

                version = str(version).strip()

                row = (
                    package,
                    version,
                    mal_id
                )

                full_rows.add(row)

                if (
                    modified
                    and modified >= cutoff
                ):
                    recent_rows.add(row)

    # Safety check so a repo/parser change doesn't wipe out the feed.
    if not full_rows:
        raise RuntimeError(
            f"No rows generated for "
            f"{source_ecosystem}"
        )

    output_dir = (
        OUTPUT_ROOT
        / output_ecosystem
    )

    if not dry_run:
        write_csv(
            output_dir /
            "malicious-packages.csv",
            full_rows
        )

        write_csv(
            output_dir /
            "malicious-packages-recent.csv",
            recent_rows
        )

    mode = "DRY RUN" if dry_run else "GENERATED"

    print(
        f"{source_ecosystem} [{mode}]: "
        f"{len(full_rows)} full rows, "
        f"{len(recent_rows)} recent rows"
    )

# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Build malicious package feeds from OpenSSF data."
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Calculate feed contents without writing to CSV files."
    )

    args = parser.parse_args()


    for source_ecosystem, output_ecosystem in SUPPORTED_ECOSYSTEMS.items():
        build_feed(
            source_ecosystem,
            output_ecosystem,
            dry_run=args.dry_run
        )


if __name__ == "__main__":
    main()

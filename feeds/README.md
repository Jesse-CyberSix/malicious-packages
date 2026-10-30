# Malicious Package Feeds
The files in this directory are transformed from malicious-package reports published by the OpenSSF malicious-packages project.

Source: https://github.com/ossf/malicious-packages

The upstream data is provided under the Apache License, Version 2.0. See LICENSE in this directory.

## Modifications
These feeds are modified representations of the upstream OpenSSF data.

The generation process:

- selects reports for individual package ecosystems;
- excludes withdrawn reports;
- extracts package names, affected versions, and MAL IDs;
- represents reports without enumerated versions using a blank Version field;
- deduplicates Package, Version, and MalId combinations;
- converts the source OSV JSON reports into CSV format; and
- produces a complete and a recent feed containing reports modified within the configured lookback period.

The Apache License applies to the OpenSSF-derived feed data in this directory. No license is granted here for other files in this repository unless explicitly stated otherwise.
# Third-Party Notices

RansomEye is a standalone product. It does not import, vendor, or execute code
from the projects listed below at runtime. Some RansomEye modules are
independent re-implementations whose design was adapted from, or informed by,
the 12X Ransomware Analysis project. This file records that provenance and
reproduces the license notices those projects require.

## 12X Ransomware Analysis

Reference project: `12X-RANSOWARE-ANALYSIS` (local reference copy, not shipped
with RansomEye). Its sub-projects carry the MIT License reproduced below with
the copyright line `Copyright (c) 2026 Judson1214`. The repository root (which
contains `engine_12x/`) has no LICENSE file; its README declares "MIT License".
RansomEye applies the same MIT notice to material derived from `engine_12x/`.

| RansomEye module | 12X source used as reference | 12X sub-project license |
|---|---|---|
| `src/ransomeye/entropy.py` | `NEXUS-SCAN/nexus_scan/analysis/entropy.py` | MIT (`NEXUS-SCAN/LICENSE`) |
| `src/ransomeye/collectors/live_file.py` | `SentinelGuard/sentinelguard/monitors/file_monitor.py` | MIT (`SentinelGuard/LICENSE`) |
| `src/ransomeye/collectors/live_network.py` | `SentinelGuard/sentinelguard/monitors/network_monitor.py` | MIT (`SentinelGuard/LICENSE`) |
| `src/ransomeye/collectors/live_process.py` | `SentinelGuard/sentinelguard/monitors/process_monitor.py` | MIT (`SentinelGuard/LICENSE`) |
| `src/ransomeye/collectors/canary_collector.py` | `engine_12x/core/system_guard.py` | MIT (declared in root README) |
| Script analysis (`src/ransomeye/script_analyzer.py`) | `ExtenderRem/backend/analyzers/doc_js_analyzer.py` | MIT (`ExtenderRem/LICENSE`) |

The script analysis capability is an independent RansomEye implementation. Its
design (script category taxonomy and the names of well-known Windows scripting
objects and auto-execution entry points) was informed by ExtenderRem's
`doc_js_analyzer.py`. No ExtenderRem code is copied; decoding, rules, scoring
and MITRE ATT&CK mapping are RansomEye's own.

```
MIT License

Copyright (c) 2026 Judson1214

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Optional runtime packages

RansomEye declares no third-party runtime dependencies. The live collectors
import the following packages only if they are already installed; if a build
environment bundles them into a distribution, their licenses apply to that
distribution:

| Package | Used by | License |
|---|---|---|
| `watchdog` | `collectors/live_file.py`, `collectors/canary_collector.py` | Apache License 2.0 |
| `psutil` | `collectors/live_process.py`, `collectors/live_network.py` | BSD 3-Clause |

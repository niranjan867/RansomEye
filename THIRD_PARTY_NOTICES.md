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
| Script analysis (`src/ransomeye/script_analyzer.py`) | `ExtenderRem/backend/analyzers/doc_js_analyzer.py`, `ExtenderRem/backend/analyzers/ioc_extractor.py` | MIT (`ExtenderRem/LICENSE`) |

The script analysis capability is predominantly an independent RansomEye
implementation. Small portions were adapted from ExtenderRem under the MIT
License above; the rest is new. For clarity:

Adapted from ExtenderRem (reimplemented, not copied verbatim):
- The idea of folding quoted string concatenation (`"a" + "b"`) and the
  40-plus-character standalone Base64 candidate pattern, from
  `doc_js_analyzer.py::deobfuscate_js`. RansomEye corrects that routine's
  defects: UTF-16LE is decoded correctly, decoding is bounded (depth, decoded
  size, candidate count and a SHA-256 seen-set) and deterministic.
- Auto-execution entry-point names (AutoOpen, Document_Open, Workbook_Open,
  Auto_Open) and scripting-object names (WScript.Shell, Shell.Application,
  MSXML2.XMLHTTP, WinHttp.WinHttpRequest, ADODB.Stream), from
  `doc_js_analyzer.py::SCRIPT_PATTERNS`. These are public Windows API facts.
- The octet-validated IPv4 pattern, the reserved/loopback address filter and
  the LOLBin command list, from `ioc_extractor.py`.

Newly implemented by RansomEye (no ExtenderRem counterpart):
- All bounded, deterministic multi-layer decoding: PowerShell -EncodedCommand
  with UTF-16LE, FromBase64String extraction, in-memory gzip/deflate with a
  hard output cap, literal char-code reconstruction, PowerShell backtick
  normalization, recursive rescanning with depth/size/candidate limits and
  cycle detection.
- The entire rule catalog, its per-rule weights, severities, confidences and
  MITRE ATT&CK techniques, and the additive (non-flat) scoring model.
- Language detection, the never-"Safe" verdict model, Office-container and
  PE rejection, path-safety checks, and the `ScriptAnalysisResult` surface.

ExtenderRem code that was reviewed and rejected: the `deobfuscate_js` decoder
itself (UTF-8-only, unbounded), the flat +30 scoring and blanket MITRE
mapping in `ai_explainer.py`, the FastAPI upload route, and all
network/threat-intelligence calls.

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

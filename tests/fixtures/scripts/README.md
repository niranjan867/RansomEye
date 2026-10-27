# Script Analyzer test fixtures

Inert, hand-written samples read only as *text* by `tests/test_script_analyzer.py`.
They are never executed. Network locations use the reserved `.invalid` TLD or
documentation address ranges, and nothing here performs encryption or deletion.

High-signal samples (encoded download cradles, AMSI tampering, shadow-copy
deletion, compressed loaders) are deliberately **not** stored here: endpoint
antivirus quarantines such files on developer machines and CI runners. Those
inputs are assembled in memory inside the tests and are never written to disk.

# Normalized Benchmark Findings

**Path:** `product/benchmark/tools/normalized_outputs/`

This directory stores parser outputs converted from `raw_outputs/` into the standardized ECDAT evidence schema (`product/benchmark/schemas/evidence_schema.json` and `benchmark_finding_schema.json`).

## Transformation Policy
1. Normalization must preserve exact raw finding references.
2. Normalization parsers must not invent missing metadata or inject ground truth assumptions.
3. If an external scanner does not report key length or curve name, normalized output must record `null` rather than guessing.

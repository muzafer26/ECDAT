"""
ECDAT CycloneDX 1.7 CBOM Serializer.

Orchestrates the assembly and deterministic serialization of CycloneDX 1.7
Cryptographic Bill of Materials documents from canonical ECDAT assets.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional, Sequence
import uuid

from product.core.domain.asset import AssetType, CryptoAsset
from product.core.domain.finding import Finding
from product.core.evidence.evidence import EvidenceRecord

from .constants import CYCLONEDX_BOM_FORMAT, CYCLONEDX_SPEC_VERSION
from .projection import CBOMProjector


class CBOMSerializer:
    """
    Emits deterministic, schema-compliant CycloneDX 1.7 CBOM JSON documents.
    """

    def __init__(self, projector: Optional[CBOMProjector] = None) -> None:
        self.projector = projector or CBOMProjector()

    def serialize_to_dict(
        self,
        assets: Sequence[CryptoAsset],
        run_id: Optional[str] = None,
        target_name: Optional[str] = None,
        target_hash: Optional[str] = None,
        timestamp: Optional[str] = None,
        scanner_executions: Sequence[Dict[str, str]] = (),
        evidence_records: Sequence[EvidenceRecord] = (),
        dependencies: Sequence[Dict[str, Any]] = (),
        findings: Optional[Sequence[Finding]] = None,
    ) -> Dict[str, Any]:
        """
        Assembles a full CycloneDX 1.7 CBOM dictionary from canonical assets.
        """
        effective_run_id = run_id or str(uuid.uuid4())
        serial_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"urn:ecdat:run:{effective_run_id}"))
        serial_number = f"urn:uuid:{serial_uuid}"

        effective_timestamp = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        effective_target = target_name or "scanned-codebase"

        # 1. Metadata Tools Components
        tools_components: List[Dict[str, Any]] = [
            {
                "type": "application",
                "name": "ECDAT",
                "version": "1.0.0",
                "vendor": "Enterprise Cryptographic Discovery & Analysis Tool",
            }
        ]

        # Add registered scanner tools from executions or evidence
        recorded_scanners = set()
        for se in scanner_executions:
            name = se.get("scanner_name") or se.get("name", "scanner")
            ver = se.get("scanner_version") or se.get("version", "1.0.0")
            key = (name, ver)
            if key not in recorded_scanners:
                recorded_scanners.add(key)
                tools_components.append({
                    "type": "application",
                    "name": name,
                    "version": ver,
                })

        for ev in evidence_records:
            if ev.scanner_name:
                key = (ev.scanner_name, ev.scanner_version or "unknown")
                if key not in recorded_scanners:
                    recorded_scanners.add(key)
                    tools_components.append({
                        "type": "application",
                        "name": ev.scanner_name,
                        "version": ev.scanner_version or "unknown",
                    })

        # 2. Metadata Component
        meta_component: Dict[str, Any] = {
            "type": "application",
            "name": effective_target,
        }
        if target_hash:
            meta_component["hashes"] = [
                {"alg": "SHA-256", "content": target_hash}
            ]

        metadata: Dict[str, Any] = {
            "timestamp": effective_timestamp,
            "lifecycles": [{"phase": "discovery"}],
            "tools": {
                "components": tools_components
            },
            "component": meta_component,
        }

        # 3. Project Assets to Components
        # Build lookup tables for precise evidence isolation
        evidence_by_id: Dict[str, EvidenceRecord] = {
            ev.evidence_id: ev for ev in evidence_records if ev.evidence_id
        }
        finding_map: Dict[str, Finding] = {
            f.finding_id: f for f in findings
        } if findings else {}

        components: List[Dict[str, Any]] = []
        for asset in assets:
            # Determine the exact evidence records supporting this canonical asset
            asset_ev_ids: set = set()
            for fid in asset.finding_ids:
                if fid in finding_map:
                    asset_ev_ids.update(finding_map[fid].evidence_ids)
                elif fid in evidence_by_id:
                    # Direct match if finding_id mirrors evidence_id
                    asset_ev_ids.add(fid)

            if asset_ev_ids:
                asset_evidence = [
                    evidence_by_id[eid] for eid in sorted(asset_ev_ids) if eid in evidence_by_id
                ]
            elif not findings and evidence_records and len(assets) == 1:
                # Single-asset fallback when findings sequence was omitted
                asset_evidence = list(evidence_records)
            else:
                asset_evidence = []

            comp = self.projector.project_component(asset, asset_evidence)
            components.append(comp)

        # Deterministic component ordering by bom-ref
        components.sort(key=lambda c: str(c.get("bom-ref", "")))

        # 4. Assemble Root Document
        bom: Dict[str, Any] = {
            "bomFormat": CYCLONEDX_BOM_FORMAT,
            "specVersion": CYCLONEDX_SPEC_VERSION,
            "serialNumber": serial_number,
            "version": 1,
            "metadata": metadata,
            "components": components,
        }

        if dependencies:
            sorted_deps = sorted(list(dependencies), key=lambda d: str(d.get("ref", "")))
            bom["dependencies"] = sorted_deps

        return bom

    def serialize_to_json(
        self,
        assets: Sequence[CryptoAsset],
        run_id: Optional[str] = None,
        target_name: Optional[str] = None,
        target_hash: Optional[str] = None,
        timestamp: Optional[str] = None,
        scanner_executions: Sequence[Dict[str, str]] = (),
        evidence_records: Sequence[EvidenceRecord] = (),
        dependencies: Sequence[Dict[str, Any]] = (),
        findings: Optional[Sequence[Finding]] = None,
        indent: int = 2,
    ) -> str:
        """
        Emits deterministic, sorted-key CycloneDX 1.7 JSON string.
        """
        data = self.serialize_to_dict(
            assets=assets,
            run_id=run_id,
            target_name=target_name,
            target_hash=target_hash,
            timestamp=timestamp,
            scanner_executions=scanner_executions,
            evidence_records=evidence_records,
            dependencies=dependencies,
            findings=findings,
        )
        return json.dumps(data, indent=indent, sort_keys=True)

    def serialize_to_file(
        self,
        file_path: str,
        assets: Sequence[CryptoAsset],
        run_id: Optional[str] = None,
        target_name: Optional[str] = None,
        target_hash: Optional[str] = None,
        timestamp: Optional[str] = None,
        scanner_executions: Sequence[Dict[str, str]] = (),
        evidence_records: Sequence[EvidenceRecord] = (),
        dependencies: Sequence[Dict[str, Any]] = (),
        findings: Optional[Sequence[Finding]] = None,
    ) -> None:
        """
        Writes deterministic CycloneDX 1.7 JSON to the specified file path.
        """
        json_content = self.serialize_to_json(
            assets=assets,
            run_id=run_id,
            target_name=target_name,
            target_hash=target_hash,
            timestamp=timestamp,
            scanner_executions=scanner_executions,
            evidence_records=evidence_records,
            dependencies=dependencies,
            findings=findings,
        )
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(json_content)


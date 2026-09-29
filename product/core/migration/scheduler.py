"""
ECDAT Migration Scheduling Engine — Phase 4B.

Produces deterministic, dependency-aware, explainable cryptographic migration schedules
based on:
- Discovered asset relationships and library package dependencies
- Phase 3C-B Harvest-Now-Decrypt-Later (HNDL) risk and quantum exposure
- Phase 3C-C contextual priorities and operational boundaries
- Phase 4A target mappings and implementation agility blockers
- Phase 4B candidate hybrid transition options

CRITICAL ARCHITECTURAL INVARIANTS:
1. True Graph-Based Scheduling:
   - Builds an explicit Directed Acyclic Graph (DAG) before assigning advisory milestones.
   - Independent assets are never artificially chained into sequential lockstep.
2. Cycle Detection:
   - Preserves circular dependencies, marks affected assets as BLOCKED_DEPENDENCY_CYCLE,
     and generates explicit Review Gates. Never silently breaks cycles.
3. Explicit Review Gating:
   - Assets with NEEDS_REVIEW, CONDITIONAL, dynamic ciphers, or unverified parameters
     are gated behind explicit ReviewGate items detailing missing information.
4. Hardcoded Agility Blocker:
   - AgilityLevel.HARDCODED generates a CODE_REFACTOR_REQUIRED blocker.
5. No Fabricated Constraints:
   - Never fabricates operational calendar dates, regulatory deadlines, or arbitrary scores.
   - Missing data retention or protocol evidence remains explicitly UNRESOLVED_INPUT.
"""

from collections import defaultdict, deque
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from product.core.domain.algorithm import AlgorithmFamily
from product.core.domain.asset import AssetType, CryptoAsset
from product.core.domain.confidence import ConfidenceLevel
from product.core.domain.role import CryptographicRole
from .agility import assess_cryptographic_agility
from .hybrid import evaluate_hybrid_options
from .models import (
    AgilityLevel,
    MigrationMilestone,
    MigrationPhase,
    MigrationSchedule,
    PqcTargetMapping,
    ReviewGate,
    TargetMappingStatus,
)
from .target_mapper import PqcTargetMapper


class MigrationScheduler:
    """
    Deterministic decision-support scheduler producing dependency-aware migration plans.
    """

    def __init__(self, target_mapper: Optional[PqcTargetMapper] = None) -> None:
        self._mapper = target_mapper or PqcTargetMapper()

    def schedule_migration(
        self,
        assets: Sequence[CryptoAsset],
        target_mappings: Optional[Sequence[PqcTargetMapping]] = None,
        risk_assessments: Optional[Sequence[Any]] = None,
        explicit_dependencies: Optional[Mapping[str, Sequence[str]]] = None,
    ) -> MigrationSchedule:
        """
        Synthesizes a deterministic MigrationSchedule from a collection of assets.

        Args:
            assets: Sequence of CryptoAsset instances.
            target_mappings: Optional pre-computed PqcTargetMapping records.
            risk_assessments: Optional Phase 3C RiskAssessment records.
            explicit_dependencies: Optional mapping of asset_id -> prerequisite_asset_ids.

        Returns:
            Immutable MigrationSchedule decision-support record.
        """
        if not isinstance(assets, (list, tuple)):
            raise TypeError(f"Expected Sequence[CryptoAsset], got {type(assets).__name__}")

        if not assets:
            return MigrationSchedule(
                milestones=(),
                dependency_graph={},
                review_gates=(),
                blocked_assets=(),
                dependency_cycles=(),
                hndl_prioritized_assets=(),
                summary="No cryptographic assets provided for migration scheduling.",
                assumptions=(),
                schedule_status="ACTIONABLE",
            )

        # 1. Index Assets and Mappings
        asset_map: Dict[str, CryptoAsset] = {a.asset_id: a for a in assets}

        if target_mappings:
            mapping_map: Dict[str, PqcTargetMapping] = {m.source_asset_id: m for m in target_mappings}
        else:
            mapping_map = {a.asset_id: self._mapper.map_asset(a) for a in assets}

        risk_map: Dict[str, Any] = {}
        if risk_assessments:
            for r in risk_assessments:
                aid = getattr(r, "asset_id", None)
                if aid:
                    risk_map[aid] = r

        # 2. Build Dependency Graph (asset_id -> set of prerequisite asset_ids)
        # Prerequisite means: prerequisite must be addressed BEFORE dependent asset.
        dep_graph: Dict[str, Set[str]] = {aid: set() for aid in asset_map}

        # 2A. Library Dependency Discovery:
        # Code assets located in the same codebase depend on observed library dependencies.
        library_asset_ids = [
            aid for aid, a in asset_map.items()
            if a.asset_type == AssetType.LIBRARY_DEPENDENCY
        ]

        for aid, a in asset_map.items():
            if a.asset_type != AssetType.LIBRARY_DEPENDENCY:
                # If code asset has matching package coordinate or provider usage
                for lib_id in library_asset_ids:
                    lib_asset = asset_map[lib_id]
                    lib_name = (lib_asset.algorithm_identity.algorithm or "").lower()
                    code_loc = getattr(a.primary_location, "code_snippet", "") or ""
                    file_p = getattr(a.primary_location, "file_path", "") or ""

                    # Link dependency if library name appears in code path or snippet
                    if lib_name and (lib_name in file_p.lower() or lib_name in code_loc.lower()):
                        dep_graph[aid].add(lib_id)

        # 2B. Explicit or Contextual Dependencies
        if explicit_dependencies:
            for aid, prereqs in explicit_dependencies.items():
                if aid in dep_graph:
                    for p in prereqs:
                        if p in asset_map:
                            dep_graph[aid].add(p)

        # 3. Detect Dependency Cycles
        cycles: List[Tuple[str, ...]] = []
        visited: Dict[str, int] = {}  # 0=unvisited, 1=visiting, 2=visited
        path: List[str] = []

        def _dfs_cycle(node: str) -> None:
            visited[node] = 1
            path.append(node)

            # Look at assets that depend on this node (reverse of prereq)
            # Or traverse prerequisite graph
            for prereq in dep_graph.get(node, ()):
                if visited.get(prereq, 0) == 1:
                    # Cycle detected: extract cycle slice
                    try:
                        idx = path.index(prereq)
                        cycle_slice = tuple(path[idx:] + [prereq])
                        if cycle_slice not in cycles:
                            cycles.append(cycle_slice)
                    except ValueError:
                        pass
                elif visited.get(prereq, 0) == 0:
                    _dfs_cycle(prereq)

            path.pop()
            visited[node] = 2

        for aid in sorted(asset_map.keys()):
            if visited.get(aid, 0) == 0:
                _dfs_cycle(aid)

        cycle_nodes: Set[str] = set()
        for c in cycles:
            cycle_nodes.update(c)

        # 4. Synthesize Review Gates and Blockers
        review_gates: List[ReviewGate] = []
        blocked_assets: Set[str] = set()
        hndl_prioritized: List[str] = []
        blockers_by_asset: Dict[str, List[str]] = defaultdict(list)
        unresolved_by_asset: Dict[str, List[str]] = defaultdict(list)

        # Process cycle blockers
        for c in cycles:
            gate_id = f"GATE-CYCLE-{c[0][:8]}"
            review_gates.append(
                ReviewGate(
                    gate_id=gate_id,
                    asset_id=c[0],
                    reason="Circular cryptographic dependency detected in migration graph.",
                    evidence_summary=f"Dependency cycle: {' -> '.join(c)}",
                    missing_information="Architectural decoupling of mutually dependent cryptographic assets.",
                    consequence_if_unresolved="Automated migration scheduling is blocked for assets in the dependency cycle.",
                )
            )
            for node in c:
                blocked_assets.add(node)
                blockers_by_asset[node].append(f"BLOCKED_BY_CYCLE: Participates in dependency cycle {' -> '.join(c)}")

        # Process individual asset attributes
        for aid, a in asset_map.items():
            mapping = mapping_map.get(aid)
            agility = assess_cryptographic_agility(a)
            risk = risk_map.get(aid)

            # Agility Blocker: Hardcoded algorithm literals
            if agility.level == AgilityLevel.HARDCODED:
                floc = getattr(a.primary_location, "file_path", "unknown")
                lstart = getattr(a.primary_location, "line_start", 0)
                blocker_msg = f"CODE_REFACTOR_REQUIRED: Hardcoded algorithm literal in {floc}:{lstart} requires code refactoring."
                blockers_by_asset[aid].append(blocker_msg)
                blocked_assets.add(aid)

            # HNDL Identification (from Phase 3C-B risk cause or quantum exposure)
            is_hndl = False
            if risk:
                pcause = getattr(risk, "primary_cause", None)
                if pcause and "HNDL" in str(pcause):
                    is_hndl = True

            # Also identify asymmetric key agreement in network role
            if a.role in (CryptographicRole.KEY_AGREEMENT, CryptographicRole.PROTOCOL_HANDSHAKE):
                if is_hndl or a.confidence == ConfidenceLevel.CONFIRMED:
                    hndl_prioritized.append(aid)

            # Review Gates for Uncertain, Ambiguous, or Conditional assets
            if mapping:
                if mapping.mapping_status in (TargetMappingStatus.NEEDS_REVIEW, TargetMappingStatus.CONDITIONAL):
                    gate_id = f"GATE-REVIEW-{aid[:8]}"
                    review_gates.append(
                        ReviewGate(
                            gate_id=gate_id,
                            asset_id=aid,
                            reason=mapping.mapping_rationale,
                            evidence_summary=f"Algorithm: {a.algorithm_identity.algorithm}, Role: {a.role.value}, Status: {mapping.mapping_status.value}",
                            missing_information="Verified cryptographic parameters, key length, or operational role required.",
                            consequence_if_unresolved="Migration is blocked until architectural review confirms primitive identity.",
                        )
                    )
                    blocked_assets.add(aid)

            if a.confidence == ConfidenceLevel.NEEDS_REVIEW or a.role == CryptographicRole.UNKNOWN:
                unresolved_by_asset[aid].append("Operational cryptographic role or detection confidence requires human validation.")

        # 5. Advisory Milestone Partitioning
        # Bucket assets into logical, evidence-driven milestone phases
        prep_assets: List[str] = []
        hndl_assets: List[str] = []
        sig_assets: List[str] = []
        storage_assets: List[str] = []
        pure_pqc_assets: List[str] = []

        for aid, a in sorted(asset_map.items()):
            mapping = mapping_map.get(aid)

            # Phase 1: Preparation (Libraries & Providers)
            if a.asset_type == AssetType.LIBRARY_DEPENDENCY:
                prep_assets.append(aid)
                continue

            # Phase 2: Key Exchange & HNDL Data-in-Transit
            if a.role in (CryptographicRole.KEY_AGREEMENT, CryptographicRole.PROTOCOL_HANDSHAKE):
                hndl_assets.append(aid)
                continue

            # Phase 3: Digital Signatures, PKI, Authentication
            if a.role in (CryptographicRole.DIGITAL_SIGNATURE, CryptographicRole.CERTIFICATE_OPERATIONS):
                sig_assets.append(aid)
                continue

            # Phase 4: Data-at-Rest & Key Storage
            if a.role in (CryptographicRole.ENCRYPTION_DECRYPTION, CryptographicRole.KEY_GENERATION):
                if a.algorithm_identity.family in (AlgorithmFamily.AES, AlgorithmFamily.DES):
                    storage_assets.append(aid)
                else:
                    # Asymmetric encryption/decryption (e.g. RSA payload or transport)
                    hndl_assets.append(aid)
                continue

            # Fallback bucket
            sig_assets.append(aid)

        milestones: List[MigrationMilestone] = []

        # Helper to assemble milestone
        def _build_milestone(
            mid: str,
            phase: MigrationPhase,
            title: str,
            t_aids: List[str],
            base_prereqs: List[str],
            rationale: str,
        ) -> Optional[MigrationMilestone]:
            if not t_aids:
                return None

            m_prereqs = list(base_prereqs)
            # Add observed dependencies for these assets
            for aid in t_aids:
                m_prereqs.extend([p for p in dep_graph.get(aid, ()) if p not in t_aids])

            m_gates = [g for g in review_gates if g.asset_id in t_aids]
            m_blockers: List[str] = []
            m_unresolved: List[str] = []

            for aid in t_aids:
                m_blockers.extend(blockers_by_asset.get(aid, []))
                m_unresolved.extend(unresolved_by_asset.get(aid, []))

            return MigrationMilestone(
                milestone_id=mid,
                phase=phase,
                title=title,
                target_asset_ids=tuple(sorted(set(t_aids))),
                prerequisites=tuple(sorted(set(m_prereqs))),
                review_gates=tuple(sorted(m_gates, key=lambda g: g.gate_id)),
                blockers=tuple(sorted(set(m_blockers))),
                rationale=rationale,
                unresolved_items=tuple(sorted(set(m_unresolved))),
            )

        # Milestone 1: Preparation (Libraries)
        m1 = _build_milestone(
            mid="M1-PREPARATION",
            phase=MigrationPhase.PREPARATION,
            title="Cryptographic Provider & Dependency Readiness",
            t_aids=prep_assets,
            base_prereqs=[],
            rationale="Upgrade software package dependencies to PQC-enabled provider releases before application code refactoring.",
        )
        if m1:
            milestones.append(m1)

        # Milestone 2: Key Exchange & HNDL
        m2_prereqs = ["M1-PREPARATION"] if m1 else []
        m2 = _build_milestone(
            mid="M2-KEY-EXCHANGE-HNDL",
            phase=MigrationPhase.KEY_EXCHANGE_HNDL,
            title="Urgent Key Exchange & HNDL Protection",
            t_aids=hndl_assets,
            base_prereqs=m2_prereqs,
            rationale="Migrate data-in-transit session key exchange to candidate hybrid KEMs (e.g. X25519MLKEM768) to protect against Harvest-Now-Decrypt-Later adversaries.",
        )
        if m2:
            milestones.append(m2)

        # Milestone 3: Authentication & Signatures
        m3_prereqs = ["M1-PREPARATION"] if m1 else []
        m3 = _build_milestone(
            mid="M3-AUTHENTICATION-SIGNATURES",
            phase=MigrationPhase.AUTHENTICATION_SIGNATURES,
            title="Authentication, Signatures & PKI Transition",
            t_aids=sig_assets,
            base_prereqs=m3_prereqs,
            rationale="Transition digital signatures and certificate operations to candidate composite signatures (e.g. MLDSA65-ECDSA-P256) or dual-certificate PKI.",
        )
        if m3:
            milestones.append(m3)

        # Milestone 4: Data-at-Rest & Storage
        m4_prereqs = ["M1-PREPARATION"] if m1 else []
        m4 = _build_milestone(
            mid="M4-DATA-AT-REST",
            phase=MigrationPhase.DATA_AT_REST,
            title="Data-at-Rest & Symmetric Storage Keys",
            t_aids=storage_assets,
            base_prereqs=m4_prereqs,
            rationale="Verify 256-bit symmetric key expansion for Grover mitigation and transition envelope key-wrapping infrastructure.",
        )
        if m4:
            milestones.append(m4)

        # 6. Overall Schedule Status Determination
        if cycles:
            schedule_status = "BLOCKED_DEPENDENCY_CYCLE"
            summary = (
                f"Migration schedule is BLOCKED by {len(cycles)} circular cryptographic dependency cycle(s). "
                f"Total assets: {len(assets)}. Blocked assets: {len(blocked_assets)}."
            )
        elif review_gates or blocked_assets:
            schedule_status = "ADVISORY_PENDING_REVIEW"
            summary = (
                f"Advisory migration schedule generated across {len(milestones)} milestone(s). "
                f"{len(review_gates)} human-review gate(s) and {len(blocked_assets)} blocked asset(s) require resolution before migration execution."
            )
        else:
            schedule_status = "ACTIONABLE"
            summary = (
                f"Actionable migration schedule generated across {len(milestones)} milestone(s) with zero blocking review gates."
            )

        assumptions = (
            "Milestone phases represent logical, evidence-driven categorization buckets, not compulsory calendar schedules.",
            "Candidate hybrid transition schemes are advisory proposals subject to protocol and client capability negotiation.",
            "Operational deployment constraints and production change windows must be confirmed by enterprise architecture.",
        )

        return MigrationSchedule(
            milestones=tuple(milestones),
            dependency_graph={k: tuple(sorted(v)) for k, v in dep_graph.items()},
            review_gates=tuple(sorted(review_gates, key=lambda g: g.gate_id)),
            blocked_assets=tuple(sorted(blocked_assets)),
            dependency_cycles=tuple(cycles),
            hndl_prioritized_assets=tuple(sorted(set(hndl_prioritized))),
            summary=summary,
            assumptions=assumptions,
            schedule_status=schedule_status,
        )

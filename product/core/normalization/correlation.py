"""
ECDAT Conservative Asset Correlation Engine.

Groups related canonical Finding instances into underlying CryptoAsset entities.

Core Directive:
Correlation is conservative and designed to minimize false merging.
Phase 1D correlation is strictly restricted to same source statement deduplication
(multiple scanner observations of the identical source-level cryptographic statement).
Cross-statement object lifecycles, variable reaching definitions, and dataflow are deferred to Phase 4.

NON-NEGOTIABLE SAFETY PRINCIPLE:
FALSE MERGING IS STRICTLY WORSE THAN FALSE SPLITTING.
If identity cannot be established safely: DO NOT CORRELATE.
"""

from enum import Enum
import re
from typing import List, Optional, Sequence, Tuple
import uuid

from product.core.evidence.evidence import LocationType, EvidenceLocation
from product.core.domain.finding import Finding, FrozenIdTuple
from product.core.domain.asset import CryptoAsset, AssetType, CanonicalAssetKey
from product.core.domain.algorithm import AlgorithmFamily, AlgorithmIdentity
from product.core.domain.role import CryptographicRole
from product.core.domain.parameters import AlgorithmParameters
from product.core.domain.observation import ObservationType
from product.core.domain.confidence import DispositionStatus, ConfidenceLevel


class CorrelationDecision(str, Enum):
    """Explicit correlation evaluation outcome."""
    CORRELATED = "correlated"              # Conclusive evidence of equivalent source-level statement
    NOT_CORRELATED = "not_correlated"      # Incompatible location, algorithm, role, or parameters
    AMBIGUOUS = "ambiguous"                # Insufficient evidence to prove statement identity


def check_parameter_compatibility(
    p1: AlgorithmParameters, p2: AlgorithmParameters
) -> Tuple[bool, Optional[str], AlgorithmParameters]:
    """
    Checks for parameter contradictions.
    Rejects explicit contradictions (e.g. GCM vs CBC, 2048 vs 3072).
    Allows unknown/omitted parameters to be refined by known parameters.
    Returns (is_compatible, rejection_reason, merged_parameters).
    """
    # 1. Mode contradiction
    if p1.cipher_mode and p2.cipher_mode and p1.cipher_mode.upper() != p2.cipher_mode.upper():
        return False, f"conflicting_cipher_modes({p1.cipher_mode}!={p2.cipher_mode})", p1

    # 2. Key size contradiction
    if p1.key_size_bits and p2.key_size_bits and p1.key_size_bits != p2.key_size_bits:
        return False, f"conflicting_key_sizes({p1.key_size_bits}!={p2.key_size_bits})", p1

    # 3. Curve contradiction
    if p1.curve_name and p2.curve_name and p1.curve_name.lower() != p2.curve_name.lower():
        return False, f"conflicting_curves({p1.curve_name}!={p2.curve_name})", p1

    # 4. Digest algorithm contradiction
    if p1.digest_algorithm and p2.digest_algorithm and p1.digest_algorithm.upper() != p2.digest_algorithm.upper():
        return False, f"conflicting_digest_algorithms({p1.digest_algorithm}!={p2.digest_algorithm})", p1

    # Merge: known values refine unknown/None values
    merged = AlgorithmParameters(
        key_size_bits=p1.key_size_bits or p2.key_size_bits,
        cipher_mode=p1.cipher_mode or p2.cipher_mode,
        padding_scheme=p1.padding_scheme or p2.padding_scheme,
        curve_name=p1.curve_name or p2.curve_name,
        digest_algorithm=p1.digest_algorithm or p2.digest_algorithm,
        effective_key_bits=p1.effective_key_bits or p2.effective_key_bits,
    )
    return True, None, merged


def normalize_source_expression(text: Optional[str]) -> str:
    """Normalizes whitespace and formatting from a source expression for equivalence comparison."""
    if not text:
        return ""
    return re.sub(r"\s+", " ", text).strip()


class AssetCorrelationEngine:
    """
    Conservative, deterministic asset correlator.
    
    Invariants:
    1. Minimizes false merging. When evidence is insufficient, findings remain separate.
    2. False merging is strictly more dangerous than duplicate asset retention.
    3. Correlation in Phase 1D is limited to equivalent source-level statement observations.
    4. Proximity alone, variable name alone, and line alone are NOT proof of identity.
    5. AMBIGUOUS decisions MUST NEVER merge.
    6. Deterministic asset identity derived strictly from CanonicalAssetKey (zero dependency on finding_ids).
    """

    def correlate(self, findings: List[Finding]) -> List[CryptoAsset]:
        """
        Correlates a list of Finding objects into a list of CryptoAsset objects.
        Returns a list of CryptoAssets with explicit correlation_basis strings.
        Input ordering does not affect the output clustering or asset IDs.
        """
        assets: List[CryptoAsset] = []

        # Only consider active cryptographic findings for genuine crypto asset creation
        # Decoys and comment-only findings with FALSE_POSITIVE disposition do not create genuine assets
        actionable_findings = [
            f for f in findings
            if f.disposition != DispositionStatus.FALSE_POSITIVE
            and f.observation_type not in (ObservationType.NON_CRYPTOGRAPHIC_DECOY, ObservationType.COMMENT_ONLY)
        ]

        # Deterministic canonical ordering before grouping
        actionable_findings.sort(
            key=lambda f: (
                getattr(f.primary_location, "file_path", "") or getattr(f.primary_location, "endpoint", "") or "",
                getattr(f.primary_location, "line_start", 0) or 0,
                getattr(f.primary_location, "line_end", 0) or 0,
                getattr(f.primary_location, "column_start", 0) or 0,
                getattr(f.primary_location, "column_end", 0) or 0,
                f.finding_id,
            )
        )

        unassigned_findings = list(actionable_findings)

        while unassigned_findings:
            base_finding = unassigned_findings.pop(0)
            correlated_group = [base_finding]
            merged_params = base_finding.parameters
            group_basis: Optional[str] = None

            # Compare against remaining unassigned findings
            remaining_to_check = list(unassigned_findings)
            for candidate in remaining_to_check:
                decision, reason, cand_params = self.evaluate_correlation(base_finding, candidate)
                # AMBIGUOUS or NOT_CORRELATED findings MUST NEVER merge
                if decision == CorrelationDecision.CORRELATED:
                    correlated_group.append(candidate)
                    unassigned_findings.remove(candidate)
                    if not group_basis:
                        group_basis = reason
                    if cand_params:
                        merged_params = cand_params

            # Build CryptoAsset from correlated group
            asset = self._build_asset_from_group(correlated_group, group_basis, merged_params)
            assets.append(asset)

        return assets

    def evaluate_correlation(
        self, f1: Finding, f2: Finding
    ) -> Tuple[CorrelationDecision, str, Optional[AlgorithmParameters]]:
        """
        Strict conservative correlation evaluation.
        Returns (CorrelationDecision, explanation, merged_parameters).
        """
        loc1 = f1.primary_location
        loc2 = f2.primary_location

        # 1. Location type must match
        if loc1.location_type != loc2.location_type:
            return CorrelationDecision.NOT_CORRELATED, "different_location_types", None

        # 2. Location comparison
        if loc1.location_type == LocationType.SOURCE or loc1.file_path:
            # File paths must be identical
            if loc1.file_path != loc2.file_path or not loc1.file_path:
                return CorrelationDecision.NOT_CORRELATED, "different_file_paths", None

            # Line coordinates must be identical
            if loc1.line_start != loc2.line_start or loc1.line_end != loc2.line_end:
                return (
                    CorrelationDecision.NOT_CORRELATED,
                    f"different_lines({loc1.line_start}-{loc1.line_end}!={loc2.line_start}-{loc2.line_end})",
                    None,
                )

            # Sub-line / statement disambiguation on the same line
            col1 = (loc1.column_start, loc1.column_end)
            col2 = (loc2.column_start, loc2.column_end)
            has_cols1 = col1[0] is not None and col1[1] is not None
            has_cols2 = col2[0] is not None and col2[1] is not None

            if has_cols1 and has_cols2:
                # Both have column boundaries: verify overlap
                overlap = not (col1[1] < col2[0] or col2[1] < col1[0])
                if not overlap:
                    return CorrelationDecision.NOT_CORRELATED, f"non_overlapping_columns({col1}!={col2})", None
            else:
                # Columns missing on one or both: evaluate source expression
                expr1 = normalize_source_expression(loc1.matched_text or loc1.code_snippet)
                expr2 = normalize_source_expression(loc2.matched_text or loc2.code_snippet)

                # Check if text reveals distinct variable assignments on the same line (e.g. c1 = ... vs c2 = ...)
                var1_match = re.search(r"\b([a-zA-Z0-9_$]+)\s*=", expr1)
                var2_match = re.search(r"\b([a-zA-Z0-9_$]+)\s*=", expr2)
                if var1_match and var2_match and var1_match.group(1) != var2_match.group(1):
                    return (
                        CorrelationDecision.NOT_CORRELATED,
                        f"distinct_statements_on_same_line({var1_match.group(1)}!={var2_match.group(1)})",
                        None,
                    )

                m1 = (loc1.matched_text or "").strip()
                m2 = (loc2.matched_text or "").strip()
                if m1 and m2 and m1 != m2:
                    if m1 not in m2 and m2 not in m1:
                        return CorrelationDecision.AMBIGUOUS, f"ambiguous_same_line_expressions('{m1}'!='{m2}')", None
        else:
            # Non-source location comparison
            key1 = CanonicalAssetKey._build_location_anchor(loc1)
            key2 = CanonicalAssetKey._build_location_anchor(loc2)
            if key1 != key2:
                return CorrelationDecision.NOT_CORRELATED, "different_non_source_locators", None

        # 3. Algorithm family compatibility
        if f1.algorithm_identity.family != f2.algorithm_identity.family:
            return (
                CorrelationDecision.NOT_CORRELATED,
                f"conflicting_families({f1.algorithm_identity.family}!={f2.algorithm_identity.family})",
                None,
            )

        # 4. Specific algorithm compatibility
        algo1 = f1.algorithm_identity.algorithm
        algo2 = f2.algorithm_identity.algorithm
        if algo1 != "UNKNOWN" and algo2 != "UNKNOWN" and algo1 != algo2:
            return CorrelationDecision.NOT_CORRELATED, f"conflicting_algorithms({algo1}!={algo2})", None

        # 5. Role compatibility
        if f1.role != CryptographicRole.UNKNOWN and f2.role != CryptographicRole.UNKNOWN and f1.role != f2.role:
            return CorrelationDecision.NOT_CORRELATED, f"conflicting_roles({f1.role.value}!={f2.role.value})", None

        # 6. Parameter compatibility (rejection of explicit contradictions)
        is_compat, reason, merged_params = check_parameter_compatibility(f1.parameters, f2.parameters)
        if not is_compat:
            return CorrelationDecision.NOT_CORRELATED, reason or "parameter_contradiction", None

        # All criteria satisfied: exact statement-level observation equivalence established
        algo_name = algo1 if algo1 != "UNKNOWN" else algo2
        basis = f"same_statement_deduplication(loc='{loc1.file_path or 'loc'}:{loc1.line_start or 0}', algo='{algo_name}')"
        return CorrelationDecision.CORRELATED, basis, merged_params

    def _can_correlate(self, f1: Finding, f2: Finding) -> bool:
        """Backward-compatible boolean correlation check."""
        decision, _, _ = self.evaluate_correlation(f1, f2)
        return decision == CorrelationDecision.CORRELATED

    def _build_asset_from_group(
        self,
        group: List[Finding],
        group_basis: Optional[str] = None,
        merged_params: Optional[AlgorithmParameters] = None,
    ) -> CryptoAsset:
        """Constructs a CryptoAsset from a correlated group of findings with deterministic identity."""
        base = group[0]
        finding_ids = [f.finding_id for f in group]

        # Determine asset type
        if base.observation_type == ObservationType.LIBRARY_DEPENDENCY:
            asset_type = AssetType.LIBRARY_DEPENDENCY
        else:
            asset_type = AssetType.ALGORITHM

        # Specific algorithm takes precedence over UNKNOWN
        merged_algo = base.algorithm_identity.algorithm
        merged_family = base.algorithm_identity.family
        merged_variant = base.algorithm_identity.variant
        for f in group:
            if merged_algo == "UNKNOWN" and f.algorithm_identity.algorithm != "UNKNOWN":
                merged_algo = f.algorithm_identity.algorithm
                merged_family = f.algorithm_identity.family
                merged_variant = f.algorithm_identity.variant
            if not merged_variant and f.algorithm_identity.variant:
                merged_variant = f.algorithm_identity.variant

        algorithm_identity = AlgorithmIdentity(
            family=merged_family,
            algorithm=merged_algo,
            variant=merged_variant,
        )

        # Specific role takes precedence over UNKNOWN
        merged_role = base.role
        for f in group:
            if merged_role == CryptographicRole.UNKNOWN and f.role != CryptographicRole.UNKNOWN:
                merged_role = f.role

        # Use merged parameters
        parameters = merged_params or base.parameters

        # Highest confidence in group
        confidence = base.confidence
        for f in group:
            if f.confidence == ConfidenceLevel.CONFIRMED:
                confidence = ConfidenceLevel.CONFIRMED
                break

        if len(group) == 1:
            basis = "single_source_observation"
        else:
            basis = group_basis or f"multi_scanner_equivalent_observation(findings={len(group)})"

        # Build CanonicalAssetKey (zero finding_id / evidence_id dependence)
        canonical_key = CanonicalAssetKey.build(
            asset_type=asset_type,
            location=base.primary_location,
            algorithm_identity=algorithm_identity,
            role=merged_role,
            parameters=parameters,
        )

        return CryptoAsset(
            asset_id=canonical_key.derive_asset_id(),
            asset_type=asset_type,
            algorithm_identity=algorithm_identity,
            role=merged_role,
            parameters=parameters,
            finding_ids=finding_ids,
            primary_location=base.primary_location,
            confidence=confidence,
            correlation_basis=basis,
            asset_key=canonical_key,
        )

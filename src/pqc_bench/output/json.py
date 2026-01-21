"""
JSON output formatting for CI/CD integration.

Provides machine-readable output with full recommendation details.
"""

import json
from typing import Any

from ..core.engine import RecommendationResult


class JsonOutput:
    """Formats recommendation results as JSON."""

    def __init__(self, pretty: bool = True) -> None:
        self.pretty = pretty

    def format(self, result: RecommendationResult) -> str:
        """Format recommendation result as JSON string."""
        data = self._serialize_result(result)

        if self.pretty:
            return json.dumps(data, indent=2, default=str)
        else:
            return json.dumps(data, default=str)

    def _serialize_result(self, result: RecommendationResult) -> dict[str, Any]:
        """Serialize result to JSON-compatible dict."""
        from .. import __version__

        recommendations = []
        for rec in result.recommendations:
            recommendations.append(
                {
                    "rank": rec.rank,
                    "algorithm_id": rec.algorithm.id,
                    "algorithm_name": rec.algorithm.names.nist_name,
                    "fips": rec.algorithm.names.nist_fips,
                    "score": round(rec.score, 1),
                    "confidence": rec.confidence,
                    "type": rec.algorithm.algorithm_type,
                    "security": {
                        "nist_level": rec.algorithm.security.nist_level,
                        "classical_bits": rec.algorithm.security.classical_bits,
                        "quantum_bits": rec.algorithm.security.quantum_bits,
                        "constant_time": rec.algorithm.security.constant_time,
                    },
                    "sizes": {
                        "public_key": rec.algorithm.sizes.public_key,
                        "private_key": rec.algorithm.sizes.private_key,
                        "signature": rec.algorithm.sizes.signature,
                        "ciphertext": rec.algorithm.sizes.ciphertext,
                    },
                    "reasons": rec.reasons,
                    "warnings": rec.warnings,
                }
            )

        constraints = {
            "use_case": result.constraints.use_case.value if result.constraints.use_case else None,
            "platform": (
                result.constraints.platform.value if result.constraints.platform else None
            ),
            "needs_kem": result.constraints.needs_kem,
            "needs_signature": result.constraints.needs_signature,
            "min_security_level": result.constraints.min_security_level.value,
            "compliance_frameworks": [
                f.value for f in result.constraints.compliance_frameworks
            ],
        }

        return {
            "version": __version__,
            "query": result.query,
            "constraints": constraints,
            "recommendations": recommendations,
            "notes": result.notes,
        }

from src.verifiers.base import Verifier, VerificationResult
from src.types import Finding
from src.scanners.base import CheckContext


class VerifierRunner:
    def __init__(self, verifiers: list[Verifier]):
        self._verifiers = verifiers

    def verify_findings(self, ctx: CheckContext, findings: list[Finding]) -> list[Finding]:
        verified: list[Finding] = []
        for finding in findings:
            verified_finding = finding
            for verifier in self._verifiers:
                if verifier.can_verify(finding):
                    result = verifier.verify(ctx, finding)
                    updated = result.finding
                    updated.details["verified"] = result.confirmed
                    updated.details["verification_confidence"] = result.confidence
                    updated.details["verification_evidence"] = result.evidence
                    updated.details["verifier"] = verifier.name

                    if not result.confirmed:
                        updated.description += f" [DISMISSED: {result.evidence}]"
                        verified_finding = updated
                    elif result.confidence == 0.0:
                        updated.description += f" [CANNOT VERIFY: {result.evidence}]"
                        verified_finding = updated
                    elif result.confidence < 0.5:
                        updated.description += f" [FLAGGED: {result.evidence}]"
                        verified_finding = updated
                    else:
                        updated.description += f" [CONFIRMED: {result.evidence}]"
                        verified_finding = updated
                    break
            verified.append(verified_finding)

        for verifier in self._verifiers:
            verified = verifier.verify_chain(ctx, verified)

        return verified

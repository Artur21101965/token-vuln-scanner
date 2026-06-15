import json
import os
from src.types import ScanReport


class JsonReporter:
    def __init__(self, output_dir: str = "reports"):
        self._output_dir = output_dir

    def write(self, report: ScanReport) -> str:
        chain_dir = report.token.chain.name.lower()
        token_dir = os.path.join(self._output_dir, chain_dir, report.token.address)
        os.makedirs(token_dir, exist_ok=True)

        data = {
            "token": {
                "address": report.token.address,
                "symbol": report.token.symbol,
                "name": report.token.name,
                "chain": report.token.chain.name.lower(),
                "decimals": report.token.decimals,
            },
            "pool": {
                "address": report.pool.address,
                "dex": report.pool.dex,
                "liquidity_usd": float(report.pool.liquidity_usd),
            },
            "scanned_at": report.scanned_at.isoformat(),
            "summary": report.summary,
            "findings": [
                {
                    "check_name": f.check_name,
                    "severity": f.severity.name,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "details": f.details,
                }
                for f in report.findings
            ],
        }

        json_path = os.path.join(token_dir, "report.json")
        with open(json_path, "w") as f:
            json.dump(data, f, indent=2)

        txt_path = os.path.join(token_dir, "report.txt")
        with open(txt_path, "w") as f:
            f.write(self._format_text(report))

        return json_path

    def _format_text(self, report: ScanReport) -> str:
        lines = [
            f"Token: {report.token.symbol} ({report.token.address[:12]}...)",
            f"Chain: {report.token.chain.name}",
            f"DEX: {report.pool.dex}",
            f"Liquidity: ${float(report.pool.liquidity_usd):,.0f}",
            f"Scan: {report.scanned_at.isoformat()}",
            f"Summary: {report.summary}",
            "",
            "Findings:",
        ]
        if not report.findings:
            lines.append("  ✅ No vulnerabilities detected")
        else:
            for f in sorted(report.findings, key=lambda x: x.severity, reverse=True):
                lines.append(f"  [{f.severity.name}] {f.check_name}")
                lines.append(f"    {f.description}")
                lines.append(f"    → {f.recommendation}")
                lines.append("")
        return "\n".join(lines)

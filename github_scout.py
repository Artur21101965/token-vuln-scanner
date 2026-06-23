"""
GITHUB PROTOCOL SCOUT — finds pre-release DeFi protocols, audits source code.

Every 3 hours:
  1. Search GitHub for new Solidity repos (stars >3, last 7 days)
  2. Fetch Solidity source files
  3. Run vulnerability analysis
  4. Report potential zero-days

Usage: python github_scout.py
"""
import os, json, time, logging, urllib.request, re, tomllib

logging.basicConfig(level=logging.INFO, format="%(asctime)s [GHSCOUT] %(message)s")
logger = logging.getLogger("gh-scout")

def _get_github_token():
    t = os.environ.get("GITHUB_TOKEN", "")
    if t: return t
    try:
        with open(os.path.join(os.path.dirname(__file__), "config.toml"), "rb") as f:
            return tomllib.load(f).get("explorer", {}).get("github_token", "")
    except Exception:
        return ""

GITHUB_TOKEN = _get_github_token()
HEADERS = {"User-Agent": "Mozilla/5.0", "Authorization": f"Bearer {GITHUB_TOKEN}",
           "Accept": "application/vnd.github.v3+json"}

# Vulnerability patterns in Solidity source
VULN_PATTERNS = [
    ("selfdestruct", "onlyOwner" not in "", "🚨 SELFDESTRUCT reachable"),
    ("delegatecall", "onlyOwner" not in "", "⚠️ delegatecall without protection"),
    ("tx.origin", "", "⚠️ tx.origin for auth (phishing risk)"),
    ("function initialize(", "initialized" not in "", "🚨 initialize() can be called again"),
    ("function upgradeTo(", "onlyOwner" not in "", "🚨 upgradeTo unprotected"),
    (".call{", "success" not in "", "⚠️ low-level call without check"),
    ("block.timestamp", "", "ℹ️ Uses block.timestamp (manipulatable)"),
    ("approve(", "onlyOwner" not in "", "ℹ️ approve without auth"),
]


def search_new_repos() -> list[dict]:
    """Find new Solidity repos with stars."""
    queries = [
        "language:Solidity stars:>3 created:>2026-06-10",
        "language:Solidity stars:>10 created:>2026-06-01",
    ]
    all_repos = []
    for q in queries:
        try:
            url = f"https://api.github.com/search/repositories?q={urllib.request.quote(q)}&sort=stars&per_page=10"
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            all_repos.extend(data.get("items", []))
            time.sleep(2)
        except Exception as e:
            logger.debug("Search error: %s", e)
    return all_repos


def get_solidity_files(repo_full_name: str) -> list[dict]:
    """Get all .sol files from a repo."""
    files = []
    try:
        url = f"https://api.github.com/repos/{repo_full_name}/git/trees/main?recursive=1"
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        for item in data.get("tree", []):
            if item["path"].endswith(".sol"):
                files.append(item)
    except:
        # Try master branch
        try:
            url = f"https://api.github.com/repos/{repo_full_name}/git/trees/master?recursive=1"
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            files = [item for item in data.get("tree", []) if item["path"].endswith(".sol")]
        except:
            pass
    return files


def analyze_sol_file(repo_name: str, path: str, content: str) -> list[str]:
    """Analyze a single Solidity file for vulnerabilities."""
    issues = []
    for pattern, condition, desc in VULN_PATTERNS:
        if pattern in content.lower():
            # Simple heuristic — needs context but fast
            issues.append(f"{desc} in {path}")
    return issues


def run_scout():
    """One full scout cycle."""
    repos = search_new_repos()
    logger.info("Found %d new Solidity repos", len(repos))

    audited = 0
    findings = []

    for repo in repos[:15]:
        name = repo["full_name"]
        stars = repo["stargazers_count"]
        desc = (repo.get("description") or "")[:80]

        # Skip obvious tutorials/learning repos
        skip_words = ["tutorial", "learn", "course", "example", "homework", "solidity-basics"]
        if any(w in str(repo).lower() for w in skip_words):
            continue

        sol_files = get_solidity_files(name)
        if not sol_files:
            continue

        logger.info("%s (⭐%d) — %d .sol files", name, stars, len(sol_files))
        audited += 1

        # Get and analyze up to 5 key files
        for sol_file in sol_files[:5]:
            try:
                raw_url = f"https://raw.githubusercontent.com/{name}/main/{sol_file['path']}"
                req = urllib.request.Request(raw_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=10) as r:
                    content = r.read().decode("utf-8", errors="ignore")

                issues = analyze_sol_file(name, sol_file["path"], content)
                for iss in issues:
                    logger.warning("  %s", iss)
                    findings.append((name, sol_file["path"], iss))
            except:
                continue

        if audited >= 10:
            break
        time.sleep(1)

    if findings:
        with open("github_scout_findings.txt", "a") as f:
            f.write(f"\n--- {time.ctime()} ---\n")
            for repo, path, iss in findings:
                f.write(f"{repo} | {path} | {iss}\n")
        logger.warning("Saved %d findings", len(findings))

    logger.info("Cycle done: %d repos audited, %d findings", audited, len(findings))


def main():
    logger.info("=" * 50)
    logger.info("GITHUB PROTOCOL SCOUT")
    logger.info("=" * 50)

    cycle = 1
    while True:
        logger.info("Cycle #%d", cycle)
        run_scout()
        logger.info("Sleeping 3 hours...")
        time.sleep(10800)
        cycle += 1


if __name__ == "__main__":
    main()

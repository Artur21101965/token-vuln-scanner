"""
IMMUNEFI AUTO-SCRAPER — headless browser extracts all contract addresses.

Every 6 hours:
  1. Opens each Immunefi bounty page in headless Chromium
  2. Waits for JavaScript to load all assets
  3. Extracts all 0x addresses
  4. Feeds them to the auditor

Fully autonomous. No manual copy-paste needed.
"""
import os, re, time, logging
from playwright.sync_api import sync_playwright

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SCRAPE] %(message)s")
logger = logging.getLogger("immunefi-scrape")

OUTPUT_DIR = "immunefi_pages"
BOUNTY_SLUGS = [
    "ssv-network", "ethena", "morpho-blue", "ens", "the-graph",
    "lombard-finance", "dexe", "eigenlayer", "lido", "aave",
    "compound", "rocket-pool", "stakewise", "silo-finance",
    "puffer-stake", "euler-finance", "chainlink", "uniswap",
]

os.makedirs(OUTPUT_DIR, exist_ok=True)

def scrape_bounty(page, slug: str):
    """Open bounty page, extract all 0x addresses."""
    url = f"https://immunefi.com/bounty/{slug}/"
    logger.info("Scraping %s...", slug)
    
    try:
        page.goto(url, timeout=30000, wait_until="networkidle")
        page.wait_for_timeout(3000)  # extra wait for JS rendering
        
        # Get full page text
        content = page.content()
        text = page.inner_text("body")
        
        # Extract all 0x addresses
        addrs = set(re.findall(r'0x[a-fA-F0-9]{40}', text))
        
        if addrs:
            fpath = os.path.join(OUTPUT_DIR, f"{slug}.txt")
            with open(fpath, "w") as f:
                for a in sorted(addrs):
                    f.write(f"{a}\n")
            logger.info("  %s: %d addresses → %s", slug, len(addrs), fpath)
        else:
            logger.warning("  %s: 0 addresses found", slug)
        
        return len(addrs)
    except Exception as e:
        logger.error("  %s: %s", slug, str(e)[:80])
        return 0

def main():
    logger.info("=" * 50)
    logger.info("IMMUNEFI AUTO-SCRAPER (headless Chrome)")
    logger.info("=" * 50)
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        
        total = 0
        for slug in BOUNTY_SLUGS:
            n = scrape_bounty(page, slug)
            total += n
            time.sleep(2)  # rate limit
        
        browser.close()
    
    logger.info("Done: %d total addresses from %d bounties", total, len(BOUNTY_SLUGS))

if __name__ == "__main__":
    main()

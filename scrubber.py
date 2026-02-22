"""Output redaction engine for fix v2.

Scrubs sensitive data from text before it leaves the machine.
Runs on every outbound message: investigation results, error output, contracts.

Each category can be independently toggled. False positives are safer than leaks.
This is a best-effort seatbelt, not a security boundary. The real protection
is the overlay sandbox hiding sensitive files from the command in the first place.
"""

import re
import os
import math

# --- Pattern categories ---

# Environment variable assignments: KEY=value
_RE_ENV_ASSIGN = re.compile(
    r'''(?:^|(?<=\s))([A-Z_][A-Z0-9_]{2,})=(["']?)(.+?)\2(?:\s|$)''',
    re.MULTILINE
)

# PHP define() style: define('KEY', 'value') — WordPress wp-config.php etc
_RE_PHP_DEFINE = re.compile(
    r"""define\s*\(\s*['"]([A-Z_][A-Z0-9_]*)['"]\s*,\s*(['"])(.+?)\2\s*\)""",
)

# Known secret prefixes: API keys, tokens, passwords
_RE_TOKENS = re.compile(
    r'(?:'
    # Cloud provider keys
    r'sk-[A-Za-z0-9_-]{20,}'            # Anthropic/OpenAI
    r'|sk_live_[A-Za-z0-9]{20,}'        # Stripe secret
    r'|pk_live_[A-Za-z0-9]{20,}'        # Stripe publishable
    r'|rk_live_[A-Za-z0-9]{20,}'        # Stripe restricted
    r'|AKIA[A-Z0-9]{16}(?:/[A-Za-z0-9/+]{20,})?' # AWS access key (+ optional secret)
    r'|AIza[A-Za-z0-9_-]{35}'           # Google API key
    r'|ya29\.[A-Za-z0-9_-]+'            # Google OAuth token
    r'|SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'  # SendGrid
    r'|sk-ant-[A-Za-z0-9_-]{20,}'       # Anthropic specific
    # Git forges
    r'|ghp_[A-Za-z0-9]{30,}'            # GitHub PAT
    r'|gho_[A-Za-z0-9]{30,}'            # GitHub OAuth
    r'|ghu_[A-Za-z0-9]{30,}'            # GitHub user token
    r'|ghs_[A-Za-z0-9]{30,}'            # GitHub server token
    r'|github_pat_[A-Za-z0-9_]{30,}'    # GitHub fine-grained PAT
    r'|glpat-[A-Za-z0-9_-]{20,}'        # GitLab PAT
    # Messaging/SaaS
    r'|xox[bsapr]-[A-Za-z0-9-]+'        # Slack tokens
    r'|SK[a-f0-9]{32}'                   # Twilio API key
    r'|AC[a-f0-9]{32}'                   # Twilio account SID
    r'|sq0[a-z]{3}-[A-Za-z0-9_-]{22,}'  # Square
    r'|whsec_[A-Za-z0-9+/=]{20,}'       # Webhook secrets (Stripe/Coinbase/etc)
    # Package registries
    r'|npm_[A-Za-z0-9]{20,}'            # npm tokens
    r'|pypi-[A-Za-z0-9]{20,}'           # PyPI tokens
    # Cloud platforms
    r'|dop_v1_[A-Za-z0-9]{20,}'         # DigitalOcean
    r'|key-[A-Za-z0-9]{20,}'            # Mailgun
    r'|heroku_[A-Za-z0-9_-]{20,}'       # Heroku (non-env format)
    # Chat/social
    r'|Bot\s+[A-Za-z0-9]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' # Discord bot tokens
    r'|\b\d{8,10}:[A-Za-z0-9_-]{35}\b'  # Telegram bot tokens
    r'|oauth:[A-Za-z0-9]{20,}'           # Twitch OAuth
    # Cloud/infra
    r'|cf_[A-Za-z0-9_-]{20,}'           # Cloudflare API tokens
    r'|hvs\.[A-Za-z0-9_-]{20,}'         # HashiCorp Vault tokens
    r'|atlassian_[A-Za-z0-9_-]{20,}'    # Atlassian API tokens
    # CI/CD
    r'|circle-token\s*[=:]\s*[A-Za-z0-9_-]{20,}'  # CircleCI
    r'|travis_[A-Za-z0-9_-]{20,}'       # Travis CI
    # Generic patterns
    r'|Bearer\s+[A-Za-z0-9._~+/=-]{20,}'  # Bearer tokens
    r'|token=[A-Za-z0-9._~+/=-]{10,}'
    r'|password=[^\s&]{3,}'
    r'|passwd=[^\s&]{3,}'
    r'|secret=[^\s&]{3,}'
    r'|api[_-]?key=[^\s&]{3,}'
    r'|client[_-]?secret=[^\s&]{3,}'
    r'|-passin\s+pass:[^\s]+'           # OpenSSL password on CLI
    r'|_auth=[A-Za-z0-9+/=]{10,}'       # .npmrc / pypirc auth tokens
    r')'
)

# Private key blocks (PEM format)
_RE_PRIVATE_KEY = re.compile(
    r'-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----'
)

# JWTs: three base64url segments separated by dots
_RE_JWT = re.compile(
    r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'
)

# Connection strings with credentials
_RE_CONN_STRING = re.compile(
    r'(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql)'
    r'://[^\s]*:[^\s]*@[^\s]+'
)

# Git remote URLs with embedded credentials
_RE_GIT_CRED_URL = re.compile(
    r'https?://[A-Za-z0-9._%-]+:[A-Za-z0-9._%-]+@[^\s]+'
)

# HTTP auth headers in output
_RE_HTTP_AUTH = re.compile(
    r'(?:Authorization|Cookie|X-API-Key|X-Auth-Token|X-Secret)'
    r'\s*[:=]\s*.+',
    re.IGNORECASE
)

# Credit card numbers (4 groups of 4 digits, with optional separators)
_RE_CREDIT_CARD = re.compile(
    r'\b(?:\d{4}[\s-]?){3}\d{4}\b'
)

# SSN
_RE_SSN = re.compile(
    r'\b\d{3}-\d{2}-\d{4}\b'
)

# Phone numbers (US and international)
_RE_PHONE = re.compile(
    r'(?:'
    r'\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{1,4}[\s.-]?\d{1,9}'  # international
    r'|\b\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b'                       # US format
    r')'
)

# TOTP/OTP URIs
_RE_TOTP = re.compile(
    r'otpauth://[^\s]+'
)

# Home directory paths: /home/username/ -> /home/[USER]/
_RE_HOME_PATH = None  # compiled lazily with actual username

# IPv4 addresses
_RE_IPV4 = re.compile(
    r'\b(?:'
    r'(?:10\.(?:\d{1,3}\.){2}\d{1,3})'
    r'|(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})'
    r'|(?:192\.168\.\d{1,3}\.\d{1,3})'
    r'|(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    r')\b'
)

# Email addresses
_RE_EMAIL = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
)

# High-entropy hex strings (likely keys/hashes -- 64+ hex chars)
_RE_HEX_SECRET = re.compile(
    r'\b[0-9a-fA-F]{64,}\b'
)

# Unix shadow password hashes ($6$, $y$, $2b$, $5$, etc)
_RE_SHADOW_HASH = re.compile(
    r'\$(?:6|5|y|2[aby]?)\$[^\s:]{8,}\$[A-Za-z0-9./+]{20,}'
)

# Passwords on command lines (sshpass, sudo, mysql, etc)
_RE_CLI_PASSWORD = re.compile(
    r'(?:'
    r'sshpass\s+-p\s*[^\s]+'
    r'|echo\s+["\']?[^\s|"\']+["\']?\s*\|\s*sudo'
    r'|mysql\s+.*-p[^\s]+'
    r'|mongosh?\s+.*--password\s+[^\s]+'
    r')',
    re.IGNORECASE
)

# .netrc file contents (machine/login/password lines)
_RE_NETRC = re.compile(
    r'machine\s+\S+\s+login\s+\S+\s+password\s+\S+',
    re.IGNORECASE
)

# htpasswd entries (user:$apr1$... or user:{SHA}...)
_RE_HTPASSWD = re.compile(
    r'\b\w+:(?:\$apr1\$|\{SHA\}|\$2[aby]?\$)[^\s]+'
)

# SQL credential statements
_RE_SQL_CREDS = re.compile(
    r'(?:'
    r"IDENTIFIED\s+BY\s+['\"][^'\"]+['\"]"
    r"|ALTER\s+(?:USER|ROLE)\s+\S+\s+.*PASSWORD\s+['\"][^'\"]+['\"]"
    r"|PRAGMA\s+key\s*=\s*['\"][^'\"]+['\"]"
    r')',
    re.IGNORECASE
)

# DSN connection strings (ODBC style)
_RE_DSN = re.compile(
    r'(?:DSN|Driver)\s*=[^;]*(?:;[^;]*)*;(?:UID|User\s*ID)\s*=[^;]*;(?:PWD|Password)\s*=[^;]+',
    re.IGNORECASE
)

# SMTP/protocol URLs with credentials
_RE_SMTP_CREDS = re.compile(
    r'smtps?://[^\s]*:[^\s]*@[^\s]+'
)

# Docker config auth blobs (base64 encoded user:pass)
_RE_DOCKER_AUTH = re.compile(
    r'"auth"\s*:\s*"[A-Za-z0-9+/=]{10,}"'
)

# YAML/JSON secret value patterns (colon-separated only, = handled by env_vars)
_RE_STRUCTURED_SECRETS = re.compile(
    r'(?:'
    r'(?:password|passwd|secret|secret_key|api_key|apikey|private_key|access_token|auth_token)'
    r'''\s*:\s*['"]?[^\s'"#,}{:]{3,}'''
    r')',
    re.IGNORECASE
)

# BIP-39 mnemonic seed phrases (12+ known words in sequence)
_BIP39_COMMON = {
    "abandon", "ability", "able", "about", "above", "absent", "absorb",
    "abstract", "absurd", "abuse", "access", "accident", "account",
    "acoustic", "acquire", "across", "action", "actor", "actual", "adapt",
    "addict", "address", "adjust", "admit", "adult", "advance", "advice",
    "aerobic", "afford", "agree", "album", "alcohol", "alert", "alien",
    "alpha", "already", "also", "alter", "amazing", "among", "amount",
    "anchor", "ancient", "anger", "animal", "ankle", "announce", "annual",
    "antenna", "apple", "arena", "armor", "army", "artwork", "aspect",
    "atom", "aunt", "avocado", "avoid", "awake", "aware", "awesome",
    "awful", "axis", "banana", "banner", "barrel", "basic", "basket",
    "battle", "bean", "because", "become", "believe", "bench", "benefit",
    "bicycle", "bird", "birth", "blade", "blanket", "blast", "bleak",
    "blind", "blood", "blossom", "blue", "boat", "bomb", "bone", "bonus",
    "border", "bottom", "bounce", "brain", "brave", "bread", "breeze",
    "brick", "bridge", "brief", "broken", "bronze", "brother", "brush",
    "bubble", "buddy", "budget", "buffalo", "bulk", "bullet", "bundle",
    "burst", "butter", "cabin", "cable", "cage", "camera", "camp",
    "canal", "cancel", "canvas", "captain", "carbon", "cargo", "carpet",
    "carry", "casino", "castle", "catalog", "catch", "cattle", "celery",
    "cement", "census", "century", "cereal", "chalk", "champion",
    "change", "chaos", "chapter", "charge", "chase", "cherry", "chest",
    "chicken", "chief", "child", "choice", "chunk", "cinema", "citizen",
    "claim", "clarify", "claw", "click", "climb", "clock", "close",
    "cloth", "cloud", "clown", "club", "cluster", "coach", "coconut",
    "column", "comfort", "common", "company", "concert", "conduct",
    "confirm", "congress", "connect", "consider", "control", "convince",
    "coral", "corn", "correct", "cotton", "couch", "country", "couple",
    "cover", "craft", "crash", "crater", "crazy", "cream", "credit",
    "crew", "cricket", "crime", "critic", "crop", "cross", "crouch",
    "crowd", "cruel", "cruise", "crumble", "crush", "crystal", "cube",
    "culture", "cupboard", "curtain", "curve", "custom", "cycle",
    "damage", "dance", "danger", "daughter", "dawn", "debate", "december",
    "decide", "decline", "decorate", "decrease", "degree", "delay",
    "deliver", "demand", "depart", "depend", "deposit", "depth", "deputy",
    "derive", "describe", "desert", "design", "detail", "detect",
    "develop", "device", "devote", "diamond", "diesel", "diet",
    "differ", "digital", "dignity", "dilemma", "dinosaur", "direct",
    "disagree", "discover", "disease", "dismiss", "display", "distance",
    "divide", "dizzy", "doctor", "document", "domain", "donate", "donor",
    "door", "dose", "double", "dove", "dragon", "drama", "dream",
    "dress", "drift", "drink", "drip", "drive", "drum", "duck", "dumb",
    "during", "dust", "dutch", "eagle", "earth", "easily", "east",
    "echo", "ecology", "economy", "edge", "effort", "eight", "either",
    "elbow", "elder", "electric", "elegant", "element", "elephant",
    "elite", "else", "embark", "embrace", "emerge", "emotion", "employ",
    "enable", "endorse", "enemy", "energy", "enforce", "engage", "engine",
    "enjoy", "enrich", "ensure", "enter", "entire", "envelope", "episode",
    "equal", "equip", "erode", "erosion", "error", "escape", "essay",
    "essence", "estate", "eternal", "evidence", "evil", "evoke", "evolve",
    "exact", "example", "excess", "exchange", "excite", "exclude",
    "excuse", "execute", "exercise", "exhaust", "exhibit", "exile",
    "exist", "exit", "exotic", "expand", "expect", "expire", "explain",
    "expose", "express", "extend", "extra", "eyebrow", "fabric", "face",
    "faculty", "faint", "faith", "false", "family", "famous", "fancy",
    "fantasy", "fatal", "father", "fatigue", "fault", "favorite",
    "feature", "february", "federal", "feel", "female", "fence",
    "festival", "fetch", "fever", "fiber", "fiction", "field", "figure",
    "film", "filter", "final", "find", "finger", "finish", "fire",
    "fiscal", "fitness", "flag", "flame", "flash", "flight", "flip",
    "float", "flock", "floor", "flower", "fluid", "flush", "foam",
    "focus", "fold", "follow", "food", "foot", "force", "forest",
    "forget", "fork", "fortune", "forum", "forward", "fossil", "foster",
    "found", "fragile", "frame", "fringe", "frog", "frozen", "fruit",
    "fuel", "funny", "furnace", "fury", "future", "gadget", "galaxy",
    "gallery", "game", "garage", "garbage", "garden", "garlic", "garment",
    "gasp", "gate", "gather", "gauge", "gaze", "genius", "genre",
    "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle",
    "ginger", "giraffe", "give", "glad", "glance", "glare", "glass",
    "glide", "globe", "gloom", "glory", "glove", "glow", "glue", "goat",
    "goddess", "gold", "good", "gorilla", "gospel", "gossip", "govern",
    "grace", "grain", "grant", "grape", "grass", "gravity", "great",
    "grid", "grief", "grit", "grocery", "group", "grow", "grunt",
    "guard", "guess", "guide", "guilt", "guitar", "habit", "half",
    "hammer", "hamster", "hand", "happy", "harbor", "harvest", "hawk",
    "hazard", "head", "health", "heart", "heavy", "hedgehog", "height",
    "hello", "helmet", "hero", "hidden", "high", "hill", "hint", "hire",
    "hobby", "hockey", "hold", "hole", "holiday", "hollow", "home",
    "honey", "hood", "hope", "horn", "horror", "horse", "hospital",
    "host", "hour", "hover", "huge", "human", "humble", "humor",
    "hundred", "hurdle", "hurry", "husband", "hybrid", "ice", "icon",
    "idea", "identify", "idle", "ignore", "image", "imitate", "immense",
    "immune", "impact", "impose", "improve", "impulse", "inch", "include",
    "income", "increase", "index", "indicate", "indoor", "industry",
    "infant", "inflict", "inform", "initial", "inject", "inmate",
    "inner", "innocent", "input", "inquiry", "insane", "insect", "inside",
    "inspire", "install", "intact", "interest", "invest", "invite",
    "involve", "island", "isolate", "issue", "ivory", "jacket", "jaguar",
    "jelly", "jewel", "join", "joke", "journey", "judge", "juice",
    "jungle", "junior", "junk", "kangaroo", "keen", "keep", "kernel",
    "kick", "kidney", "kind", "kingdom", "kiss", "kitten", "kiwi",
    "knee", "knife", "knock", "know", "labor", "ladder", "lake", "lamp",
    "language", "laptop", "large", "later", "latin", "laugh", "laundry",
    "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn",
    "leave", "lecture", "legal", "legend", "leisure", "lemon", "lend",
    "length", "lens", "leopard", "lesson", "letter", "level", "liberty",
    "library", "license", "life", "lift", "light", "like", "limb",
    "limit", "link", "lion", "liquid", "list", "little", "live",
    "lizard", "load", "loan", "lobster", "local", "lock", "logic",
    "lonely", "long", "loop", "lottery", "loud", "lounge", "love",
    "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury",
    "lyrics", "machine", "magic", "magnet", "maid", "major", "make",
    "mammal", "manage", "mandate", "mango", "mansion", "manual", "maple",
    "marble", "march", "margin", "marine", "market", "marriage", "mask",
    "mass", "master", "match", "material", "matrix", "matter", "maximum",
    "maze", "meadow", "mean", "measure", "media", "melody", "member",
    "memory", "mention", "menu", "mercy", "merge", "merit", "mesh",
    "method", "midnight", "milk", "million", "mimic", "mind", "minimum",
    "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake",
    "mixture", "mobile", "model", "modify", "moment", "monitor", "monkey",
    "monster", "month", "moon", "moral", "morning", "mosquito", "mother",
    "motion", "motor", "mountain", "mouse", "move", "much", "muffin",
    "mule", "multiply", "muscle", "museum", "music", "must", "mutual",
    "myself", "mystery", "myth", "naive", "name", "napkin", "narrow",
    "nasty", "nation", "nature", "near", "neck", "need", "negative",
    "neglect", "neither", "nephew", "nerve", "nest", "network", "neutral",
    "never", "news", "next", "nice", "night", "noble", "noise", "normal",
    "north", "nose", "notable", "nothing", "notice", "novel", "now",
    "nuclear", "number", "nurse", "nut", "oak", "obey", "object",
    "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean",
    "october", "odor", "office", "often", "olive", "olympic", "omit",
    "once", "one", "onion", "online", "open", "opera", "opinion",
    "oppose", "option", "orange", "orbit", "orchard", "order", "ordinary",
    "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor",
    "outer", "output", "outside", "oval", "oven", "over", "own", "owner",
    "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair",
    "palace", "palm", "panda", "panel", "panic", "panther", "paper",
    "parade", "parent", "park", "parrot", "party", "pass", "patch",
    "path", "patient", "patrol", "pattern", "pause", "pave", "payment",
    "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty",
    "pencil", "people", "pepper", "perfect", "permit", "person", "pet",
    "phone", "photo", "phrase", "physical", "piano", "picnic", "picture",
    "piece", "pilot", "pink", "pioneer", "pipe", "pistol", "pitch",
    "pizza", "place", "planet", "plastic", "plate", "play", "please",
    "pledge", "pluck", "plug", "plunge", "poem", "poet", "point",
    "polar", "pole", "police", "pond", "pony", "pool", "popular",
    "portion", "position", "possible", "post", "potato", "pottery",
    "poverty", "powder", "power", "practice", "praise", "predict",
    "prefer", "prepare", "present", "pretty", "prevent", "price", "pride",
    "primary", "print", "priority", "prison", "private", "prize",
    "problem", "process", "produce", "profit", "program", "project",
    "promote", "proof", "property", "prosper", "protect", "proud",
    "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin",
    "punch", "pupil", "puppy", "purchase", "purity", "purpose", "purse",
    "push", "puzzle", "pyramid", "quality", "quantum", "quarter", "question",
    "quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race",
    "rack", "radar", "radio", "rail", "rain", "raise", "rally", "ramp",
    "ranch", "random", "range", "rapid", "rare", "rate", "rather",
    "raven", "raw", "razor", "ready", "real", "reason", "rebel",
    "rebuild", "recall", "receive", "recipe", "record", "recycle",
    "reduce", "reflect", "reform", "region", "regret", "regular",
    "reject", "relax", "release", "relief", "rely", "remain", "remember",
    "remind", "remove", "render", "renew", "rent", "reopen", "repair",
    "repeat", "replace", "report", "require", "rescue", "resemble",
    "resist", "resource", "response", "result", "retire", "retreat",
    "return", "reunion", "reveal", "review", "reward", "rhythm", "ribbon",
    "rice", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot",
    "ripple", "risk", "ritual", "rival", "river", "road", "roast",
    "robot", "robust", "rocket", "romance", "roof", "rookie", "room",
    "rose", "rotate", "rough", "round", "route", "royal", "rubber",
    "rude", "rug", "rule", "rural", "sad", "saddle", "sadness", "safe",
    "sail", "salad", "salmon", "salon", "salt", "salute", "same",
    "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save",
    "scale", "scan", "scatter", "scene", "scheme", "school", "science",
    "scissors", "scorpion", "scout", "scrap", "screen", "script",
    "scrub", "search", "season", "seat", "second", "secret", "section",
    "security", "seed", "seek", "segment", "select", "sell", "seminar",
    "senior", "sense", "sentence", "series", "service", "session",
    "settle", "setup", "seven", "shadow", "shaft", "shallow", "share",
    "shed", "shell", "sheriff", "shield", "shift", "shine", "ship",
    "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder",
    "shove", "shrimp", "shuffle", "shy", "sibling", "sick", "side",
    "siege", "sight", "sign", "silent", "silk", "silly", "silver",
    "similar", "simple", "since", "sing", "siren", "sister", "situate",
    "size", "skate", "sketch", "ski", "skill", "skin", "skirt", "skull",
    "slab", "slam", "sleep", "slender", "slice", "slide", "slight",
    "slim", "slogan", "slot", "slow", "slush", "small", "smart", "smile",
    "smoke", "smooth", "snack", "snake", "snap", "sniff", "snow", "soap",
    "soccer", "social", "sock", "soda", "soft", "solar", "soldier",
    "solid", "solution", "solve", "someone", "song", "soon", "sorry",
    "sort", "soul", "sound", "soup", "source", "south", "space", "spare",
    "spatial", "spawn", "speak", "special", "speed", "spell", "spend",
    "sphere", "spice", "spider", "spike", "spin", "spirit", "split",
    "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring",
    "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff",
    "stage", "stairs", "stamp", "stand", "start", "state", "stay",
    "steak", "steel", "stem", "step", "stereo", "stick", "still",
    "sting", "stock", "stomach", "stone", "stool", "story", "stove",
    "strategy", "street", "strike", "strong", "struggle", "student",
    "stuff", "stumble", "style", "subject", "submit", "subway", "success",
    "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer",
    "sun", "sunny", "sunset", "super", "supply", "supreme", "sure",
    "surface", "surge", "surprise", "surround", "survey", "suspect",
    "sustain", "swallow", "swamp", "swap", "swarm", "sweet", "swim",
    "swing", "switch", "sword", "symbol", "symptom", "syrup", "system",
    "table", "tackle", "tag", "tail", "talent", "talk", "tank", "tape",
    "target", "task", "taste", "tattoo", "taxi", "teach", "team", "tell",
    "ten", "tenant", "tennis", "tent", "term", "test", "text", "thank",
    "that", "theme", "then", "theory", "there", "they", "thing", "this",
    "thought", "three", "thrive", "throw", "thumb", "thunder", "ticket",
    "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired",
    "tissue", "title", "toast", "tobacco", "today", "toddler", "toe",
    "together", "toilet", "token", "tomato", "tomorrow", "tone", "tongue",
    "tonight", "tool", "tooth", "top", "topic", "topple", "torch",
    "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower",
    "town", "toy", "track", "trade", "traffic", "tragic", "train",
    "transfer", "trap", "trash", "travel", "tray", "treat", "tree",
    "trend", "trial", "tribe", "trick", "trigger", "trim", "trip",
    "trophy", "trouble", "truck", "true", "truly", "trumpet", "trust",
    "truth", "try", "tube", "tuna", "tunnel", "turkey", "turn", "turtle",
    "twelve", "twenty", "twice", "twin", "twist", "two", "type",
    "typical", "ugly", "umbrella", "unable", "unaware", "uncle", "uncover",
    "under", "undo", "unfair", "unfold", "unhappy", "uniform", "unique",
    "unit", "universe", "unknown", "unlock", "until", "unusual", "unveil",
    "update", "upgrade", "uphold", "upon", "upper", "upset", "urban",
    "usage", "use", "used", "useful", "useless", "usual", "utility",
    "vacant", "vacuum", "vague", "valid", "valley", "valve", "van",
    "vanish", "vapor", "various", "vast", "vault", "vehicle", "velvet",
    "vendor", "venture", "venue", "verb", "verify", "version", "very",
    "vessel", "veteran", "viable", "vibrant", "vicious", "victory",
    "video", "view", "village", "vintage", "violin", "virtual", "virus",
    "visa", "visit", "visual", "vital", "vivid", "vocal", "voice",
    "void", "volcano", "volume", "vote", "voyage", "wage", "wagon",
    "wait", "walk", "wall", "walnut", "want", "warfare", "warm", "warrior",
    "wash", "wasp", "waste", "water", "wave", "way", "wealth", "weapon",
    "wear", "weasel", "weather", "web", "wedding", "weekend", "weird",
    "welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when",
    "where", "whip", "whisper", "wide", "width", "wife", "wild", "will",
    "win", "window", "wine", "wing", "wink", "winner", "winter", "wire",
    "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder",
    "wood", "wool", "word", "work", "world", "worry", "worth", "wrap",
    "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year",
    "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo",
}


def _looks_like_mnemonic(text):
    """Check if text contains a BIP-39 mnemonic seed phrase (12/24 words)."""
    words = text.lower().split()
    for start in range(len(words)):
        for length in (24, 12):
            chunk = words[start:start + length]
            if len(chunk) == length and all(w in _BIP39_COMMON for w in chunk):
                return True
    return False


def _get_home_re():
    """Lazily compile home path regex for current user."""
    global _RE_HOME_PATH
    if _RE_HOME_PATH is None:
        username = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
        if username:
            home = os.path.expanduser("~")
            escaped = re.escape(home)
            _RE_HOME_PATH = re.compile(escaped + r'(?=/|$|\s)')
        else:
            _RE_HOME_PATH = re.compile(r'/home/[a-z_][a-z0-9_-]*(?=/|$|\s)')
    return _RE_HOME_PATH


def _luhn_check(num_str):
    """Luhn algorithm to validate credit card numbers."""
    digits = [int(d) for d in num_str if d.isdigit()]
    if len(digits) != 16:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _entropy(s):
    """Shannon entropy of a string (bits per character)."""
    if not s:
        return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# Environment variables that are NOT sensitive
_ENV_SAFE = {
    "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "XDG_SESSION_TYPE",
    "XDG_SESSION_CLASS", "XDG_SESSION_ID", "XDG_SEAT", "XDG_VTNR",
    "XDG_SEAT_PATH", "XDG_SESSION_PATH", "XDG_CONFIG_DIRS", "XDG_DATA_DIRS",
    "XDG_CURRENT_DESKTOP", "XDG_SESSION_DESKTOP", "XDG_MENU_PREFIX",
    "SHELL", "TERM", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE",
    "HOME", "USER", "LOGNAME", "PATH", "PWD", "OLDPWD", "HOSTNAME",
    "EDITOR", "VISUAL", "PAGER", "COLORTERM", "TERM_PROGRAM",
    "DBUS_SESSION_BUS_ADDRESS", "SSH_AUTH_SOCK",
    "DESKTOP_SESSION", "SESSION_MANAGER", "GDMSESSION",
    "QT_ACCESSIBILITY", "QT_IM_MODULE", "GTK_IM_MODULE",
}


# --- Scrub functions ---

def _scrub_env_vars(text):
    """Redact KEY=value assignments, preserving non-sensitive system vars."""
    def repl(m):
        key = m.group(1)
        if key in _ENV_SAFE:
            return m.group(0)
        quote = m.group(2)
        return f"{key}={quote}[REDACTED]{quote} "
    return _RE_ENV_ASSIGN.sub(repl, text)


# PHP define() keys that are safe (not secrets)
_PHP_SAFE = {
    "DB_NAME", "DB_HOST", "DB_CHARSET", "DB_COLLATE", "DB_TABLE_PREFIX",
    "WP_DEBUG", "WP_DEBUG_LOG", "WP_DEBUG_DISPLAY", "ABSPATH",
    "WP_HOME", "WP_SITEURL", "WP_CONTENT_DIR", "WP_CONTENT_URL",
    "DISALLOW_FILE_EDIT", "DISALLOW_FILE_MODS", "WP_AUTO_UPDATE_CORE",
    "FS_METHOD", "WP_MEMORY_LIMIT", "WP_MAX_MEMORY_LIMIT",
}


def _scrub_php_defines(text):
    """Redact PHP define('KEY', 'value') assignments (WordPress etc)."""
    def repl(m):
        key = m.group(1)
        if key in _PHP_SAFE:
            return m.group(0)
        quote = m.group(2)
        return f"define('{key}', {quote}[REDACTED]{quote})"
    return _RE_PHP_DEFINE.sub(repl, text)


def _scrub_tokens(text):
    """Redact known secret patterns (API keys, vendor tokens)."""
    return _RE_TOKENS.sub("[REDACTED]", text)


def _scrub_private_keys(text):
    """Redact PEM private key blocks."""
    return _RE_PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", text)


def _scrub_jwts(text):
    """Redact JSON Web Tokens."""
    return _RE_JWT.sub("[REDACTED_JWT]", text)


def _scrub_conn_strings(text):
    """Redact database/service connection strings with credentials."""
    return _RE_CONN_STRING.sub("[REDACTED_CONNECTION_STRING]", text)


def _scrub_git_creds(text):
    """Redact git remote URLs with embedded credentials."""
    return _RE_GIT_CRED_URL.sub("[REDACTED_URL]", text)


def _scrub_http_auth(text):
    """Redact HTTP auth headers."""
    return _RE_HTTP_AUTH.sub("[REDACTED_HEADER]", text)


def _scrub_credit_cards(text):
    """Redact credit card numbers (with Luhn validation to reduce false positives)."""
    def repl(m):
        if _luhn_check(m.group(0)):
            return "[REDACTED_CC]"
        return m.group(0)
    return _RE_CREDIT_CARD.sub(repl, text)


def _scrub_ssn(text):
    """Redact Social Security Numbers."""
    return _RE_SSN.sub("[REDACTED_SSN]", text)


def _scrub_phone(text):
    """Redact phone numbers."""
    return _RE_PHONE.sub("[REDACTED_PHONE]", text)


def _scrub_totp(text):
    """Redact TOTP/OTP URIs."""
    return _RE_TOTP.sub("[REDACTED_TOTP]", text)


def _scrub_paths(text):
    """Replace /home/username/ with /home/[USER]/."""
    home_re = _get_home_re()
    return home_re.sub("/home/[USER]", text)


def _scrub_ips(text):
    """Redact IP addresses, preserving localhost."""
    def repl(m):
        ip = m.group(0)
        if ip in ("127.0.0.1", "0.0.0.0"):
            return ip
        return "[REDACTED_IP]"
    return _RE_IPV4.sub(repl, text)


def _scrub_emails(text):
    """Redact email addresses."""
    return _RE_EMAIL.sub("[REDACTED_EMAIL]", text)


def _scrub_hex_secrets(text):
    """Redact long high-entropy hex strings (likely keys/hashes)."""
    def repl(m):
        s = m.group(0)
        if _entropy(s) > 3.5:  # random hex is ~4.0, repeated patterns are lower
            return "[REDACTED_HEX]"
        return s
    return _RE_HEX_SECRET.sub(repl, text)


def _scrub_shadow_hashes(text):
    """Redact Unix shadow password hashes."""
    return _RE_SHADOW_HASH.sub("[REDACTED_HASH]", text)


def _scrub_cli_passwords(text):
    """Redact passwords passed on command lines."""
    return _RE_CLI_PASSWORD.sub("[REDACTED_CLI_PASSWORD]", text)


def _scrub_netrc(text):
    """Redact .netrc credential lines."""
    return _RE_NETRC.sub("[REDACTED_NETRC]", text)


def _scrub_htpasswd(text):
    """Redact htpasswd entries."""
    return _RE_HTPASSWD.sub("[REDACTED_HTPASSWD]", text)


def _scrub_sql_creds(text):
    """Redact SQL credential statements."""
    return _RE_SQL_CREDS.sub("[REDACTED_SQL_CRED]", text)


def _scrub_dsn(text):
    """Redact ODBC/DSN connection strings."""
    return _RE_DSN.sub("[REDACTED_DSN]", text)


def _scrub_smtp_creds(text):
    """Redact SMTP URLs with credentials."""
    return _RE_SMTP_CREDS.sub("[REDACTED_SMTP]", text)


def _scrub_docker_auth(text):
    """Redact Docker config auth blobs."""
    return _RE_DOCKER_AUTH.sub('"auth": "[REDACTED]"', text)


def _scrub_structured_secrets(text):
    """Redact YAML/JSON/config secret key-value patterns."""
    return _RE_STRUCTURED_SECRETS.sub("[REDACTED_SECRET]", text)


def _scrub_mnemonics(text):
    """Redact BIP-39 mnemonic seed phrases."""
    if not _looks_like_mnemonic(text):
        return text
    words = text.split()
    lower_words = [w.lower() for w in words]
    # Find and replace 12/24 word sequences that are all BIP-39 words
    i = 0
    while i < len(words):
        for length in (24, 12):
            chunk = lower_words[i:i + length]
            if len(chunk) == length and all(w in _BIP39_COMMON for w in chunk):
                words[i:i + length] = ["[REDACTED_MNEMONIC]"]
                lower_words[i:i + length] = ["[redacted_mnemonic]"]
                break
        i += 1
    return " ".join(words)


# Category name -> scrub function (order matters: specific before generic)
SCRUBBERS = {
    "private_keys": _scrub_private_keys,
    "tokens": _scrub_tokens,
    "jwts": _scrub_jwts,
    "conn_strings": _scrub_conn_strings,
    "git_creds": _scrub_git_creds,
    "http_auth": _scrub_http_auth,
    "totp": _scrub_totp,
    "credit_cards": _scrub_credit_cards,
    "ssn": _scrub_ssn,
    "phone": _scrub_phone,
    "env_vars": _scrub_env_vars,
    "php_defines": _scrub_php_defines,
    "shadow_hashes": _scrub_shadow_hashes,
    "cli_passwords": _scrub_cli_passwords,
    "netrc": _scrub_netrc,
    "htpasswd": _scrub_htpasswd,
    "sql_creds": _scrub_sql_creds,
    "dsn": _scrub_dsn,
    "smtp_creds": _scrub_smtp_creds,
    "docker_auth": _scrub_docker_auth,
    "structured_secrets": _scrub_structured_secrets,
    "mnemonics": _scrub_mnemonics,
    "paths": _scrub_paths,
    "ips": _scrub_ips,
    "emails": _scrub_emails,
    "hex_secrets": _scrub_hex_secrets,
}

# All categories enabled by default
DEFAULT_CATEGORIES = set(SCRUBBERS.keys())


def scrub(text, config=None):
    """Scrub sensitive data from text.

    Args:
        text: The text to scrub.
        config: Optional dict with:
            - categories: list of category names to enable (default: all)
            - custom_patterns: list of (pattern, replacement) tuples

    Returns:
        (scrubbed_text, matched_categories) tuple.
        matched_categories is a set of category names that had matches.
    """
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8", errors="replace")
        except Exception:
            return text, set()
    if text is None:
        return "", set()
    if not text:
        return text, set()

    if config and "categories" in config:
        categories = set(config["categories"])
    else:
        categories = DEFAULT_CATEGORIES

    matched = set()
    result = text

    for cat_name in categories:
        fn = SCRUBBERS.get(cat_name)
        if fn is None:
            continue
        scrubbed = fn(result)
        if scrubbed != result:
            matched.add(cat_name)
            result = scrubbed

    # Custom patterns
    if config and config.get("custom_patterns"):
        for pattern, replacement in config["custom_patterns"]:
            compiled = re.compile(pattern)
            new_result = compiled.sub(replacement, result)
            if new_result != result:
                matched.add("custom")
                result = new_result

    return result, matched

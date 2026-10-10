"""Constants and env-driven settings. No imports from the rest of the app."""
import os

MAX_AGE_30_DAYS = 60 * 60 * 24 * 30
SESSION_MAX_AGE_SHORT = 24 * 60 * 60  # без "Remember me": 24 часа

ALLOWED_HOSTS = {"askpc.cc", "www.askpc.cc", "localhost:8000", "127.0.0.1:8000"}
CORS_ORIGINS = [
    "https://askpc.cc",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

# --- Sponsors / Solana ---
SOLANA_WALLET = os.getenv(
    "SOLANA_WALLET_ADDRESS", "9xQeWvG816bUx9EPjHmaT23yvVM2VYdeHzM2a6C3Vfc"
)
SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com"
USDT_MINT = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
MIN_SPONSOR_USDT = 1.99  # accounts for minor rounding
SPONSOR_PERIOD_DAYS = 30
SPONSOR_GOAL = 10

# --- GitHub content sync ---
# Only these top-level directories are ever synced (webhook and manual re-sync).
GITHUB_REPO = os.getenv("GITHUB_REPO")  # "owner/repo"
GITHUB_SYNC_BRANCH = os.getenv("GITHUB_SYNC_BRANCH", "main")
SYNC_DIRECTORIES = ("wiki/", "docs/")

REGISTRATION_OPEN = os.getenv("REGISTRATION_OPEN", "0") == "1"

def get_domain() -> str:
    """Read at call time so env changes / dotenv loading order don't matter."""
    return os.getenv("DOMAIN", "askpc.cc").strip()

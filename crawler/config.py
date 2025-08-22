import os

CLAIM_ENDPOINT = os.getenv("CLAIM_ENDPOINT", os.getenv("APP_BASE_URL", "http://localhost") + "/claim-block")
BULK_ENDPOINT = os.getenv("BULK_ENDPOINT", os.getenv("APP_BASE_URL", "http://localhost") + "/add-responses-batch")

# Authentication token for API endpoints
API_AUTH_TOKEN = "vLyYYwS2vOijm8uJs3iCtBZI0Vfo"

# Telegram notification settings
TELEGRAM_BOT_TOKEN = "8267827005:AAFPf3_vLyYYwS2vOijm8uJs3iCtBZI0Vfo"
TELEGRAM_CHAT_ID = 7037777940
NOTIFY_ON_CRAWLER_ERRORS = os.getenv("NOTIFY_ON_CRAWLER_ERRORS", "true").lower() in ("true", "1", "yes")

# Limits should mirror database model constraints
BANNER_LIMIT = 512
HTTP_LIMIT = 8192
HEADERS_LIMIT = 4096
CERT_LIMIT = 8192

DEFAULT_TIMEOUT_SECS = float(os.getenv("CRAWLER_TIMEOUT_SECS", "10")) # 5
CONCURRENCY = int(os.getenv("CRAWLER_CONCURRENCY", "50")) # 100
BATCH_SIZE = int(os.getenv("CRAWLER_BATCH_SIZE", "100")) # 500
FETCH_CERT = os.getenv("CRAWLER_FETCH_CERT", "0").lower() in ("1", "true", "yes", "on")
FETCH_ICON = os.getenv("CRAWLER_FETCH_ICON", "0").lower() in ("1", "true", "yes", "on")
ICON_MAX_BYTES = int(os.getenv("CRAWLER_ICON_MAX_BYTES", "2000000"))

# Realistic browser-like default headers
DEFAULT_HEADERS = {
    "User-Agent": os.getenv("CRAWLER_USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/124.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "DNT": "1",
}

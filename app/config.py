import os
from typing import List

# Telegram Bot Configuration

TELEGRAM_BOT_TOKEN="8267827005:AAFPf3_vLyYYwS2vOijm8uJs3iCtBZI0Vfo"
TELEGRAM_CHAT_ID=7037777940

# API Authentication
API_AUTH_TOKEN = os.getenv("API_AUTH_TOKEN", "vLyYYwS2vOijm8uJs3iCtBZI0Vfo")
API_AUTH_ENABLED = os.getenv("API_AUTH_ENABLED", "true").lower() in ("true", "1", "yes")

# Error Notification Settings
NOTIFY_ON_STARLETTE_ERRORS = os.getenv("NOTIFY_ON_STARLETTE_ERRORS", "true").lower() in ("true", "1", "yes")
NOTIFY_ON_CRAWLER_ERRORS = os.getenv("NOTIFY_ON_CRAWLER_ERRORS", "true").lower() in ("true", "1", "yes")

# Development mode
DEVELOPMENT_MODE = os.getenv("DEVELOPMENT_MODE", "true").lower() in ("true", "1", "yes")

import logging
from typing import Optional
import httpx

logger = logging.getLogger(__name__)

TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"


class TelegramNotifier:
    def __init__(self, bot_token: str, chat_id: str):
        self._token = bot_token
        self._chat_id = chat_id

    def send(self, message: str) -> None:
        url = TELEGRAM_API.format(token=self._token)
        try:
            with httpx.Client(timeout=10) as http:
                resp = http.post(url, json={
                    "chat_id": self._chat_id,
                    "text": message,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                })
                resp.raise_for_status()
        except Exception as exc:
            logger.error("Telegram send failed: %s", exc)

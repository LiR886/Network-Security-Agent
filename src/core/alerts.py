from __future__ import annotations

import logging
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any, Dict, Optional

import httpx


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TelegramConfig:
    enabled: bool
    bot_token: str
    chat_id: str


@dataclass(frozen=True)
class SlackConfig:
    enabled: bool
    webhook_url: str


@dataclass(frozen=True)
class EmailConfig:
    enabled: bool
    smtp_host: str
    smtp_port: int
    username: str
    password: str
    to: str


class AlertManager:
    def __init__(
        self,
        telegram: TelegramConfig,
        slack: SlackConfig,
        email: EmailConfig,
    ):
        self.telegram = telegram
        self.slack = slack
        self.email = email

    async def send(self, title: str, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        extra = extra or {}
        text = f"{title}\n{message}\n{extra}" if extra else f"{title}\n{message}"

        # Fire-and-forget best effort
        try:
            if self.telegram.enabled:
                await self._send_telegram(text)
        except Exception as e:
            logger.warning("telegram_alert_failed", extra={"err": str(e)})

        try:
            if self.slack.enabled:
                await self._send_slack(text)
        except Exception as e:
            logger.warning("slack_alert_failed", extra={"err": str(e)})

        try:
            if self.email.enabled:
                self._send_email(title, text)
        except Exception as e:
            logger.warning("email_alert_failed", extra={"err": str(e)})

    async def _send_telegram(self, text: str) -> None:
        url = f"https://api.telegram.org/bot{self.telegram.bot_token}/sendMessage"
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(url, json={"chat_id": self.telegram.chat_id, "text": text})

    async def _send_slack(self, text: str) -> None:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(self.slack.webhook_url, json={"text": text})

    def _send_email(self, subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.email.username
        msg["To"] = self.email.to
        msg.set_content(body)

        with smtplib.SMTP(self.email.smtp_host, self.email.smtp_port, timeout=15) as s:
            s.starttls()
            if self.email.username:
                s.login(self.email.username, self.email.password)
            s.send_message(msg)







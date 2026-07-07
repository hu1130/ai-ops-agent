from __future__ import annotations

import json
import smtplib
import time
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any


@dataclass
class Notifier:
    webhook_url: str = ""
    cooldown_seconds: int = 300
    email: dict[str, Any] = field(default_factory=dict)
    _last_sent: dict[str, float] = field(default_factory=dict)

    def send(self, title: str, text: str, dedupe_key: str = "default") -> bool:
        now = time.time()
        last_sent = self._last_sent.get(dedupe_key, 0)
        if now - last_sent < self.cooldown_seconds:
            print(f"[alert skipped by cooldown] {title}")
            return False

        self._last_sent[dedupe_key] = now
        print(f"[alert] {title}\n{text}")
        sent = False

        if self.webhook_url:
            self.send_webhook(title, text)
            sent = True

        if self.email.get("enabled", False):
            self.send_email(title, text)
            sent = True

        return True if sent else True

    def send_webhook(self, title: str, text: str) -> None:
        payload = {
            "title": title,
            "text": text,
            "msgtype": "text",
            "content": {"text": f"{title}\n\n{text}"},
        }
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self.webhook_url,
            data=data,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()

    def send_email(self, title: str, text: str) -> None:
        host = str(self.email.get("smtp_host", ""))
        port = int(self.email.get("smtp_port", 465))
        username = str(self.email.get("username", ""))
        password = str(self.email.get("password", ""))
        from_email = str(self.email.get("from_email") or username)
        to_emails = self.email.get("to_emails", [])
        use_ssl = bool(self.email.get("use_ssl", True))
        use_tls = bool(self.email.get("use_tls", False))

        if isinstance(to_emails, str):
            to_emails = [to_emails]
        recipients = [str(item) for item in to_emails if str(item).strip()]
        if not host or not username or not password or not recipients:
            raise ValueError("Email alert is enabled but smtp_host, username, password, or to_emails is missing")

        message = EmailMessage()
        message["Subject"] = sanitize_header_value(title)
        message["From"] = from_email
        message["To"] = ", ".join(recipients)
        message.set_content(text, charset="utf-8")

        if use_ssl:
            with smtplib.SMTP_SSL(host, port, timeout=20) as smtp:
                smtp.login(username, password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=20) as smtp:
                if use_tls:
                    smtp.starttls()
                smtp.login(username, password)
                smtp.send_message(message)


def sanitize_header_value(value: str) -> str:
    return " ".join(str(value).replace("\r", " ").replace("\n", " ").split())

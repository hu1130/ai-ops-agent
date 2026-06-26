from __future__ import annotations

import json
import time
import urllib.request
from dataclasses import dataclass, field


@dataclass
class Notifier:
    webhook_url: str = ""
    cooldown_seconds: int = 300
    _last_sent: dict[str, float] = field(default_factory=dict)

    def send(self, title: str, text: str, dedupe_key: str = "default") -> bool:
        now = time.time()
        last_sent = self._last_sent.get(dedupe_key, 0)
        if now - last_sent < self.cooldown_seconds:
            print(f"[alert skipped by cooldown] {title}")
            return False

        self._last_sent[dedupe_key] = now
        print(f"[alert] {title}\n{text}")
        if not self.webhook_url:
            return True

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
        return True

"""Email outbox. Backend chosen by SIGNET_MAIL: memory | log | smtp (default log).

Every send is also written to the `mail_log` table by the caller so delivery is auditable.
"""
from __future__ import annotations

import os
import smtplib
from dataclasses import dataclass, field
from email.message import EmailMessage


@dataclass
class Mail:
    to: str
    subject: str
    body: str


@dataclass
class MemoryOutbox:
    sent: list[Mail] = field(default_factory=list)

    def send(self, m: Mail) -> None:
        self.sent.append(m)


class LogOutbox:
    def send(self, m: Mail) -> None:
        print(f"[mail] to={m.to} subject={m.subject!r}\n{m.body}\n")


class SmtpOutbox:
    def __init__(self) -> None:
        self.host = os.environ["SMTP_HOST"]
        self.port = int(os.environ.get("SMTP_PORT", "587"))
        self.user = os.environ.get("SMTP_USER")
        self.password = os.environ.get("SMTP_PASS")
        self.sender = os.environ.get("SMTP_FROM", self.user or "signet@localhost")

    def send(self, m: Mail) -> None:
        msg = EmailMessage()
        msg["From"] = self.sender
        msg["To"] = m.to
        msg["Subject"] = m.subject
        msg.set_content(m.body)
        with smtplib.SMTP(self.host, self.port, timeout=15) as s:
            s.starttls()
            if self.user:
                s.login(self.user, self.password or "")
            s.send_message(msg)


def make_outbox():
    kind = os.environ.get("SIGNET_MAIL", "log")
    if kind == "memory":
        return MemoryOutbox()
    if kind == "smtp":
        return SmtpOutbox()
    return LogOutbox()

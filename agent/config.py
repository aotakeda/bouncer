from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from .net import ip_key
from .policy import Thresholds

DEFAULT_APP_DESCRIPTION = "OWASP Juice Shop, an Angular + Express + SQLite online juice store with a REST API under /rest and /api. Not WordPress, no PHP."
FIX_MODES = ("dry_run", "pr")


class Config:
    def __init__(self, env: Mapping[str, str] = os.environ):
        self.port = int(env.get("AGENT_PORT", "8080"))
        self.data_dir = Path(env.get("AGENT_DATA_DIR", "./agent-data"))
        self.events_sha256 = env.get("AGENT_EVENTS_SHA256", "")
        self.dash_sha256 = env.get("AGENT_DASH_SHA256", "")
        self.jev_url = env.get("JEV_URL", "")
        self.runner_url = env.get("RUNNER_URL", "")
        self.door_url = env.get("DOOR_URL", "").rstrip("/")
        self.door_token = env.get("DOOR_TOKEN", "")
        self.runner_token = env.get("RUNNER_TOKEN", "")
        self.owner_ips = {ip_key(ip.strip()) for ip in env.get("OWNER_IPS", "").split(",") if ip.strip()}
        self.block_seconds = int(env.get("BLOCK_SECONDS", "300"))
        self.tarpit_seconds = int(env.get("TARPIT_SECONDS", "600"))
        self.dedupe_seconds = int(env.get("DEDUPE_SECONDS", "600"))
        self.shield_seconds = int(env.get("SHIELD_SECONDS", "86400"))
        self.busy_retry_seconds = float(env.get("BUSY_RETRY_SECONDS", "30"))
        self.busy_retries = int(env.get("BUSY_RETRIES", "12"))
        self.pending_per_ip = int(env.get("PENDING_PER_IP", "5"))
        self.pending_total = int(env.get("PENDING_TOTAL", "500"))
        self.replay_threshold = float(env.get("REPLAY_THRESHOLD", "0.9"))
        self.min_list_confidence = float(env.get("MIN_LIST_CONFIDENCE", "0.5"))
        self.min_list_malicious = float(env.get("MIN_LIST_MALICIOUS", "0.8"))
        self.failed_attack_malicious = float(env.get("FAILED_ATTACK_MALICIOUS", "0.7"))
        self.fix_mode = env.get("FIX_MODE", "dry_run")
        self.anthropic_url = env.get("ANTHROPIC_URL", "")
        self.github_url = env.get("GITHUB_URL", "")
        self.github_repo = env.get("GITHUB_REPO", "aotakeda/juice-shop")
        self.github_branch = env.get("GITHUB_BRANCH", "master")
        self.fix_model = env.get("FIX_MODEL", "claude-opus-5-5")
        self.fix_per_hour = int(env.get("FIX_PER_HOUR", "3"))
        self.app_description = env.get("APP_DESCRIPTION", DEFAULT_APP_DESCRIPTION)

    @property
    def fixes_enabled(self) -> bool:
        return self.fix_mode in FIX_MODES and bool(self.anthropic_url and self.github_url and self.runner_url)

    @property
    def thresholds(self) -> Thresholds:
        return Thresholds(
            replay=self.replay_threshold,
            min_list_confidence=self.min_list_confidence,
            min_list_malicious=self.min_list_malicious,
            failed_attack_malicious=self.failed_attack_malicious,
            dedupe_seconds=self.dedupe_seconds,
            proven_seconds=max(self.shield_seconds, self.block_seconds),
        )

    def is_owner(self, ip: str | None) -> bool:
        return ip in self.owner_ips

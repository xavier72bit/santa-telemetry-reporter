# -*- coding: UTF-8 -*-
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path, PurePath

from ..base import Processor
from .models import ProcessAccessSummary


class SSHAccessAnalyzer(Processor[list[dict], dict[str, ProcessAccessSummary]]):
    """
    按可执行文件路径聚合对 SSH 目录（默认 ~/.ssh）的访问/操作事件。
    """

    # SantaMessage oneof 中与文件访问/操作相关的事件字段名
    _FILE_EVENT_KEYS = (
        "file_access",
        "close",
        "rename",
        "unlink",
        "link",
        "clone",
        "copyfile",
    )

    def __init__(self, target_path: Path | str | None = None):
        self.target_path = Path(target_path or Path.home() / ".ssh").expanduser()

    def analyze(self, messages: list[dict]) -> dict[str, ProcessAccessSummary]:
        summaries: dict[str, ProcessAccessSummary] = {}

        for message in messages:
            raise NotImplementedError

    def _handle_message(self, message: dict) -> ProcessAccessSummary:
        pass

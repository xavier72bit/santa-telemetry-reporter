# -*- coding: UTF-8 -*-
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ProcessAccessSummary:
    """
    按可执行文件路径聚合的目录访问摘要
    """

    executable_path: str
    event_counts: dict[str, int] = field(default_factory=dict)
    unique_paths: set[str] = field(default_factory=set)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    team_id: str | None = None
    signing_id: str | None = None
    effective_user: str | None = None

# -*- coding: UTF-8 -*-
from .analyzer.analyzers import SSHAccessAnalyzer


def process_data(original_data: list[dict]):
    ssh_access_analyzer = SSHAccessAnalyzer()
    report = ssh_access_analyzer.analyze(original_data)
    print(report)
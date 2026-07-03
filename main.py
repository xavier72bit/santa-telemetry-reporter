import json

import deserializer
from processor import client


SPOOL_DIR = "./spool"


if __name__ == '__main__':
    # 解析 spool 目录中的所有文件
    print(f"Loading spool files from: {SPOOL_DIR}")
    messages = deserializer.load_all_spool_messages(SPOOL_DIR)
    print(f"\nTotal messages parsed: {len(messages)}\n")

    client.process_data(messages)
    print(1)

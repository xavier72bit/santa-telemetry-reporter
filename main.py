import json

import deserializer
import analyzer
import reporter


SPOOL_DIR = "./spool"


if __name__ == '__main__':
    # 解析 spool 目录中的所有文件
    print(f"Loading spool files from: {SPOOL_DIR}")
    messages = deserializer.load_all_spool_messages(SPOOL_DIR)
    print(f"\nTotal messages parsed: {len(messages)}\n")

    if messages:
        # 生成事件分析报告
        report = analyzer.generate_report(messages)

        # 打印终端报告
        analyzer.print_report(report)

        # 保存 JSON 报告
        with open("santa_report.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        print(f"\nJSON 报告已保存到 santa_report.json")

        # ⑤ 生成 HTML 报告
        reporter.generate_html_report(report, "santa_report.html")
        print(f"HTML 报告已保存到 santa_report.html")

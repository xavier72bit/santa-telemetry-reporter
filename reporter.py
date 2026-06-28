# -*- coding: UTF-8 -*-
# @Project: PythonPracticeLab
# @File   : html_report.py
# @Author : Xavier Wu
# @Date   : 2026/6/26 15:00

import json
from html import escape as html_escape


def generate_html_report(report: dict, output_path: str = "santa_report.html"):
    """将报告 dict 渲染为自包含 HTML 文件。

    Args:
        report: santa_analyzer.generate_report() 返回的报告 dict
        output_path: HTML 输出路径
    """
    ov = report["overview"]
    severity = report["severity_breakdown"]
    categories = report["category_breakdown"]
    event_types = report["event_type_breakdown"]
    alerts = report["security_alerts"]
    highlights = report["highlights"]
    all_events = report["all_events"]

    severity_colors = {
        "CRITICAL": "#dc3545",
        "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107",
        "LOW": "#28a745",
    }

    # 安全等级条
    severity_bars = ""
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = severity.get(sev, 0)
        if count:
            color = severity_colors.get(sev, "#6c757d")
            width = min(count / max(1, ov["total_events"]) * 100, 100)
            severity_bars += f"""
            <div class="sev-row">
                <span class="sev-label" style="color:{color}">{sev}</span>
                <div class="sev-bar-bg">
                    <div class="sev-bar" style="width:{width}%;background:{color}"></div>
                </div>
                <span class="sev-count">{count}</span>
            </div>"""

    # 分类统计行
    cat_rows = ""
    for cat_name, count in sorted(categories.items(), key=lambda x: -x[1]):
        cat_rows += f"<tr><td>{html_escape(cat_name)}</td><td class='num'>{count}</td></tr>\n"

    # 事件类型行
    et_rows = ""
    for et, count in sorted(event_types.items(), key=lambda x: -x[1]):
        et_rows += f"<tr><td>{html_escape(et)}</td><td class='num'>{count}</td></tr>\n"

    # 安全告警区块
    alert_html = _build_alerts_html(alerts, severity_colors)

    # 高亮事件表
    hl_rows = ""
    for s in highlights[:50]:
        sev = s.get("severity", "MEDIUM")
        color = severity_colors.get(sev, "#6c757d")
        hl_rows += f"""<tr>
            <td><span class="badge" style="background:{color}">{sev}</span></td>
            <td>{html_escape(str(s.get('description', '')))}</td>
            <td>{html_escape(str(s.get('process', '')))}</td>
            <td>{html_escape(str(s.get('file', s.get('target', ''))))}</td>
            <td class="ts">{html_escape(str(s.get('timestamp', '')))}</td>
        </tr>\n"""

    # 全量事件 JSON（供搜索过滤）
    events_json = json.dumps(all_events, ensure_ascii=False, default=str)

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Santa 事件安全报告</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           background: #f5f6fa; color: #2d3436; line-height: 1.6; padding: 20px; }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    h1 {{ text-align: center; margin-bottom: 24px; font-size: 1.8em; color: #2d3436; }}
    h2 {{ margin: 24px 0 12px; font-size: 1.2em; color: #636e72;
          border-bottom: 2px solid #dfe6e9; padding-bottom: 6px; }}

    /* 概览卡片 */
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }}
    .card {{ background: #fff; border-radius: 8px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,.1);
             text-align: center; }}
    .card .value {{ font-size: 2em; font-weight: 700; color: #0984e3; }}
    .card .label {{ font-size: .85em; color: #636e72; margin-top: 4px; }}

    /* 安全等级条 */
    .sev-row {{ display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }}
    .sev-label {{ width: 80px; font-weight: 600; font-size: .9em; text-align: right; }}
    .sev-bar-bg {{ flex: 1; background: #dfe6e9; border-radius: 4px; height: 20px; overflow: hidden; }}
    .sev-bar {{ height: 100%; border-radius: 4px; transition: width .3s; }}
    .sev-count {{ width: 50px; font-size: .9em; color: #636e72; }}

    /* 表格 */
    table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px;
             overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); margin-bottom: 16px; }}
    th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #f1f2f6; font-size: .9em; }}
    th {{ background: #f8f9fa; font-weight: 600; color: #636e72; position: sticky; top: 0; }}
    td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
    td.ts {{ font-size: .8em; color: #b2bec3; white-space: nowrap; }}
    tr:hover {{ background: #f8f9fa; }}

    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; color: #fff;
              font-size: .75em; font-weight: 600; }}

    /* 两列布局 */
    .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
    @media (max-width: 700px) {{ .two-col {{ grid-template-columns: 1fr; }} }}

    /* 告警区块 */
    .alert-section {{ margin-bottom: 16px; }}
    .alert-card {{ background: #fff; border-left: 4px solid; border-radius: 4px; padding: 12px 16px;
                   margin-bottom: 8px; box-shadow: 0 1px 2px rgba(0,0,0,.06); }}
    .alert-card h4 {{ font-size: .95em; margin-bottom: 6px; }}
    .alert-item {{ font-size: .85em; padding: 4px 0; border-bottom: 1px solid #f1f2f6; }}
    .alert-item:last-child {{ border-bottom: none; }}

    /* 搜索框 */
    .search-box {{ width: 100%; padding: 10px 14px; border: 1px solid #dfe6e9; border-radius: 6px;
                   font-size: .95em; margin-bottom: 12px; outline: none; }}
    .search-box:focus {{ border-color: #0984e3; box-shadow: 0 0 0 2px rgba(9,132,227,.15); }}

    .table-wrap {{ max-height: 500px; overflow-y: auto; border-radius: 8px;
                   box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
    .table-wrap table {{ margin-bottom: 0; }}
</style>
</head>
<body>
<div class="container">
    <h1>Santa 事件安全报告</h1>

    <!-- 概览 -->
    <div class="cards">
        <div class="card">
            <div class="value">{ov['total_events']}</div>
            <div class="label">事件总数</div>
        </div>
        <div class="card">
            <div class="value">{ov['unique_event_types']}</div>
            <div class="label">事件类型</div>
        </div>
        <div class="card">
            <div class="value">{len(highlights)}</div>
            <div class="label">值得关注</div>
        </div>
        <div class="card">
            <div class="value">{sum(1 for v in alerts.values() for _ in v)}</div>
            <div class="label">安全告警</div>
        </div>
    </div>

    <p style="text-align:center;color:#b2bec3;font-size:.85em;margin-bottom:20px">
        时间范围: {ov['time_range']['earliest']} → {ov['time_range']['latest']}
    </p>

    <!-- 安全等级分布 -->
    <h2>安全等级分布</h2>
    {severity_bars}

    <!-- 分类 + 事件类型 -->
    <div class="two-col">
        <div>
            <h2>事件分类统计</h2>
            <table><thead><tr><th>分类</th><th style="text-align:right">数量</th></tr></thead>
            <tbody>{cat_rows}</tbody></table>
        </div>
        <div>
            <h2>事件类型统计</h2>
            <table><thead><tr><th>事件类型</th><th style="text-align:right">数量</th></tr></thead>
            <tbody>{et_rows}</tbody></table>
        </div>
    </div>

    <!-- 安全告警 -->
    {alert_html}

    <!-- 值得关注的事件 -->
    <h2>值得关注的事件 ({len(highlights)} 条)</h2>
    <div class="table-wrap">
    <table><thead><tr>
        <th>等级</th><th>描述</th><th>进程</th><th>文件/目标</th><th>时间</th>
    </tr></thead><tbody>{hl_rows}</tbody></table>
    </div>

    <!-- 全量事件搜索 -->
    <h2>全部事件 ({ov['total_events']} 条)</h2>
    <input type="text" class="search-box" id="searchInput" placeholder="搜索事件（支持事件类型、描述、进程名...）">
    <div class="table-wrap" style="max-height:600px">
    <table id="allEventsTable"><thead><tr>
        <th>等级</th><th>类型</th><th>描述</th><th>进程</th><th>详情</th><th>时间</th>
    </tr></thead><tbody id="eventsBody"></tbody></table>
    </div>
</div>

<script>
const events = {events_json};
const sevColors = {json.dumps(severity_colors)};
const tbody = document.getElementById('eventsBody');

function esc(s) {{
    const d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
}}

function renderEvents(list) {{
    tbody.innerHTML = list.slice(0, 500).map(e => {{
        const sev = e.severity || 'MEDIUM';
        const color = sevColors[sev] || '#6c757d';
        const details = Object.entries(e)
            .filter(([k]) => !['event_id','timestamp','event_type','category','severity',
                               'machine_id','description','process','highlight','file'].includes(k))
            .map(([k,v]) => k + ': ' + (typeof v === 'object' ? JSON.stringify(v) : v))
            .join('; ');
        return `<tr>
            <td><span class="badge" style="background:${{color}}">${{esc(sev)}}</span></td>
            <td>${{esc(e.event_type)}}</td>
            <td>${{esc(e.description)}}</td>
            <td>${{esc(e.process || '')}}</td>
            <td style="font-size:.8em;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
                title="${{esc(details)}}">${{esc(details)}}</td>
            <td class="ts">${{esc(e.timestamp)}}</td>
        </tr>`;
    }}).join('');
    if (list.length > 500) {{
        tbody.innerHTML += `<tr><td colspan="6" style="text-align:center;color:#b2bec3">
            显示前 500 条，共 ${{list.length}} 条</td></tr>`;
    }}
}}

renderEvents(events);

document.getElementById('searchInput').addEventListener('input', function() {{
    const q = this.value.toLowerCase();
    if (!q) {{ renderEvents(events); return; }}
    const filtered = events.filter(e =>
        JSON.stringify(e).toLowerCase().includes(q)
    );
    renderEvents(filtered);
}});
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


def _build_alerts_html(alerts: dict, severity_colors: dict) -> str:
    """构建安全告警区块的 HTML"""
    sections = [
        ("denied_executions", "被拒绝的执行", "CRITICAL",
         lambda s: f"<strong>{html_escape(str(s.get('process', '')))}</strong>"
                   f"<br>决策: {html_escape(str(s.get('decision', '')))} / "
                   f"原因: {html_escape(str(s.get('reason', '')))}"
                   + (f"<br>来源: {html_escape(str(s.get('quarantine_url', '')))}"
                      if s.get('quarantine_url') else "")),
        ("denied_file_access", "被拒绝的文件访问", "HIGH",
         lambda s: f"<strong>{html_escape(str(s.get('process', '')))}</strong> → "
                   f"{html_escape(str(s.get('file', '')))}"
                   f"<br>策略: {html_escape(str(s.get('policy_name', '')))} / "
                   f"决策: {html_escape(str(s.get('policy_decision', '')))}"),
        ("xprotect_detections", "XProtect 恶意软件检测", "CRITICAL",
         lambda s: f"<strong>{html_escape(str(s.get('malware', '')))}</strong> @ "
                   f"{html_escape(str(s.get('path', '')))}"),
        ("gatekeeper_overrides", "Gatekeeper 策略覆盖", "HIGH",
         lambda s: f"<strong>{html_escape(str(s.get('process', '')))}</strong> → "
                   f"{html_escape(str(s.get('file', '')))}"),
        ("auth_failures", "认证失败", "HIGH",
         lambda s: f"{html_escape(str(s.get('description', '')))}"),
    ]

    html = ""
    has_any = False

    for key, title, sev, formatter in sections:
        items = alerts.get(key, [])
        if not items:
            continue
        has_any = True
        color = severity_colors.get(sev, "#6c757d")
        items_html = "".join(
            f'<div class="alert-item">{formatter(s)}</div>'
            for s in items[:20]
        )
        more = f'<div class="alert-item" style="color:#b2bec3">...还有 {len(items)-20} 条</div>' \
            if len(items) > 20 else ""

        html += f"""
    <div class="alert-card" style="border-color:{color}">
        <h4 style="color:{color}">[{len(items)}] {title}</h4>
        {items_html}{more}
    </div>"""

    if has_any:
        return f'<h2>安全告警</h2><div class="alert-section">{html}</div>'
    return ""

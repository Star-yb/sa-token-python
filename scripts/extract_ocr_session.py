"""从 Open Code Review 的会话 jsonl 里抽出已提交的审查意见。

整次扫描中断时，--output 指定的结果文件不会生成，但 code_comment
工具调用已经写进会话。本脚本只保留这些意见，不包含模型的计划草稿。
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

SEVERITY_ORDER = ("high", "medium", "low")


def load_comments(session_path: Path) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    comments: list[dict[str, str]] = []
    failed: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    with session_path.open(encoding="utf-8") as handle:
        for line in handle:
            event = json.loads(line)
            event_type = event.get("type")
            if event_type == "review_item_failed":
                failed.append(
                    {
                        "path": str(event.get("filePath") or ""),
                        "error": str(event.get("error") or ""),
                    }
                )
                continue
            if event_type != "tool_call" or event.get("tool_name") != "code_comment":
                continue
            if not event.get("ok"):
                continue
            arguments = json.loads(event["arguments"])
            for comment in arguments.get("comments") or []:
                path = str(comment.get("path") or event.get("filePath") or "")
                content = str(comment.get("content") or "").strip()
                severity = str(comment.get("severity") or "low")
                identity = (path, severity, content)
                if identity in seen:
                    continue
                seen.add(identity)
                comments.append(
                    {
                        "path": path,
                        "severity": severity,
                        "category": str(comment.get("category") or ""),
                        "content": content,
                        "existing_code": str(comment.get("existing_code") or "").strip(),
                        "suggestion_code": str(comment.get("suggestion_code") or "").strip(),
                    }
                )
    return comments, failed


def render_report(
    session_path: Path,
    comments: list[dict[str, str]],
    failed: list[dict[str, str]],
) -> str:
    grouped: dict[str, dict[str, list[dict[str, str]]]] = defaultdict(lambda: defaultdict(list))
    for comment in comments:
        grouped[comment["severity"]][comment["path"]].append(comment)

    lines = [
        "# sa-token-python 中断扫描的审查意见",
        "",
        f"来源：`{session_path}`",
        "",
        (
            f"已提交意见 {len(comments)} 条。"
            "这些是模型调用 `code_comment` 时写下的内容，扫描被中断后没有进入最终 json。"
        ),
        "",
    ]
    for severity in SEVERITY_ORDER:
        count = sum(len(items) for items in grouped.get(severity, {}).values())
        lines.append(f"- **{severity}**: {count}")
    lines.append(f"- **未完成文件**: {len(failed)}")
    lines.append("")

    for severity in SEVERITY_ORDER:
        files = grouped.get(severity)
        if not files:
            continue
        lines.append(f"## {severity}")
        lines.append("")
        for path in sorted(files):
            lines.append(f"### `{path}`")
            lines.append("")
            for comment in files[path]:
                lines.append(f"- **{comment['category']}**")
                lines.append("")
                lines.append(comment["content"])
                lines.append("")
                if comment["existing_code"]:
                    lines.append("```")
                    lines.append(comment["existing_code"])
                    lines.append("```")
                    lines.append("")
                if comment["suggestion_code"]:
                    lines.append("建议改成：")
                    lines.append("")
                    lines.append("```")
                    lines.append(comment["suggestion_code"])
                    lines.append("```")
                    lines.append("")

    if failed:
        lines.append("## 未完成")
        lines.append("")
        lines.append("这些文件没有形成可恢复的完成记录。")
        lines.append("")
        for item in failed:
            message = item["error"].split("\n", 1)[0]
            lines.append(f"- `{item['path']}`：{message}")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="整理 Open Code Review 会话里的审查意见")
    parser.add_argument("session", type=Path, help="会话 jsonl 路径")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="写出的 Markdown 路径；省略时打印到标准输出",
    )
    args = parser.parse_args()
    comments, failed = load_comments(args.session)
    report = render_report(args.session, comments, failed)
    if args.output is None:
        print(report)
        return
    args.output.write_text(report, encoding="utf-8")
    print(f"wrote {len(comments)} comments to {args.output}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Post-process the standalone HTML pandoc builds from report/*.md.

Two things pandoc's HTML writer has no built-in option for:
  1. Long code/output blocks (script listings, terminal transcripts) take up a lot
     of vertical space. Blocks longer than LINE_THRESHOLD lines are wrapped in
     <details><summary> so they render collapsed by default.
  2. The output file lives at the repo root (so GitHub Pages can serve it with
     zero config, "branch: main, folder: /"), while the source .md files (and the
     images they reference) stay in report/. Image paths are rewritten accordingly.

Usage: python3 postprocess-html.py <path-to.html>
"""
import re
import sys

LINE_THRESHOLD = 10

SOURCECODE_BLOCK = re.compile(
    r'<div class="sourceCode" id="([^"]+)">.*?</div>', re.DOTALL
)
PLAIN_PRE_BLOCK = re.compile(r"<pre>\s*<code>.*?</code>\s*</pre>", re.DOTALL)

DIV_TAG = re.compile(r"<div\b[^>]*>|</div>")


def extract_balanced_divs(html: str, class_name: str) -> tuple[str, list[str]]:
    """Pull out every <div class="{class_name}">...</div> (depth-aware, since these
    contain their own nested <div>s, e.g. sourceCode blocks) and replace each with a
    placeholder, so later processing can skip their contents entirely."""
    open_tag = re.compile(r'<div\s+class="' + re.escape(class_name) + r'"[^>]*>')
    protected: list[str] = []
    out = []
    i = 0
    while True:
        m = open_tag.search(html, i)
        if not m:
            out.append(html[i:])
            break
        out.append(html[i : m.start()])
        depth = 1
        pos = m.end()
        while depth > 0:
            tm = DIV_TAG.search(html, pos)
            if not tm:
                raise ValueError(f"unbalanced <div class=\"{class_name}\">")
            depth += -1 if tm.group(0).startswith("</div>") else 1
            pos = tm.end()
        protected.append(html[m.start() : pos])
        out.append(f"@@PROTECTED{len(protected) - 1}@@")
        i = pos
    return "".join(out), protected


def count_lines(block: str) -> int:
    span_lines = re.findall(r'<span id="cb\d+-\d+"', block)
    if span_lines:
        return len(span_lines)
    inner = re.search(r"<code>(.*?)</code>", block, re.DOTALL)
    text = inner.group(1) if inner else block
    return text.count("\n") + 1


def fold_if_long(match: re.Match) -> str:
    block = match.group(0)
    lines = count_lines(block)
    if lines <= LINE_THRESHOLD:
        return block
    return (
        f'<details><summary>Vis kode ({lines} linjer)</summary>\n'
        f"{block}\n"
        f"</details>"
    )


def fix(path: str) -> None:
    with open(path, "r", encoding="utf-8") as f:
        html = f.read()

    html = html.replace('src="screenshots/', 'src="report/screenshots/')

    # Code inside a side-by-side comparison must stay visible for at-a-glance
    # comparison, so it's exempt from the long-code auto-fold below.
    html, protected_compares = extract_balanced_divs(html, "compare")

    html = SOURCECODE_BLOCK.sub(fold_if_long, html)
    html = PLAIN_PRE_BLOCK.sub(fold_if_long, html)

    for idx, block in enumerate(protected_compares):
        html = html.replace(f"@@PROTECTED{idx}@@", block)

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"post-processed {path}")


if __name__ == "__main__":
    fix(sys.argv[1])

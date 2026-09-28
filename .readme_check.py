import re
from pathlib import Path

md = Path("README.md").read_text(encoding="utf-8")
print("bytes:", len(md.encode("utf-8")))
print("lines:", md.count("\n") + 1)
print()

fence = "`" * 3
fences = re.findall(r"^" + fence, md, re.M)
print("code fences:", len(fences), "balanced" if len(fences) % 2 == 0 else "UNBALANCED")

toc = re.findall(r"\]\(#([a-z0-9-]+)\)", md)
heads = re.findall(r"^#{2,3} (.+)$", md, re.M)


def slug(h):
    s = h.lower()
    s = re.sub(r"[^a-z0-9 -]", "", s)
    return s.replace(" ", "-")


slugs = {slug(h) for h in heads}
missing = [t for t in toc if t not in slugs]
print("TOC links:", len(toc), "| broken anchors:", missing or "none")
print()

# Tables: every row in a table block must have a consistent pipe count.
lines = md.split("\n")
blocks, current = [], []
for line in lines:
    if line.strip().startswith("|"):
        current.append(line)
    else:
        if current:
            blocks.append(current)
        current = []
if current:
    blocks.append(current)

bad = 0
for block in blocks:
    counts = {line.count("|") for line in block}
    if len(counts) > 1:
        bad += 1
        print("  inconsistent table:", block[0][:60], counts)
print("tables:", len(blocks), "| inconsistent:", bad)
print()

# Every referenced file path in the layout section must exist.
root = Path(".")
paths = re.findall(r"^│?\s*[│├└─\s]*([\w./-]+\.(?:py|js|css|html|toml|md|txt))", md, re.M)
missing_files = sorted({p for p in paths if not (root / p).exists()})
print("referenced files:", len(set(paths)), "| missing on disk:", missing_files or "none")

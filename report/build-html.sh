#!/usr/bin/env bash
# Bygger index.html (til GitHub Pages, "branch: main, folder: /") fra report/NN-*.md.
# Køres fra report/: ./build-html.sh
# Filerne samles i navnerækkefølge (00-, 01-, ...), så moduler kan tilføjes løbende.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

pandoc [0-9][0-9]-*.md \
  --standalone --toc --toc-depth=2 \
  --css=style.css \
  --syntax-highlighting=cyberpunk.theme \
  -o ../index.html

cp style.css ../style.css

python3 postprocess-html.py ../index.html

echo "Bygget: ../index.html (+ ../style.css)"

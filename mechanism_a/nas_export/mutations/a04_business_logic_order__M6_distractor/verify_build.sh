#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
python3 -c "import ast; ast.parse(open('mod.py').read())"

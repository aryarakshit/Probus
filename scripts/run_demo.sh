#!/usr/bin/env bash
# Live Hackathon Demo Launcher
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
python "$DIR/run_demo.py" --rounds 3

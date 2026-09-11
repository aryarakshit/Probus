#!/usr/bin/env bash
# Shell wrapper for anti-cheat static analysis verification
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
python "$DIR/verify_anti_cheat.py"

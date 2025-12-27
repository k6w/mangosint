#!/bin/bash
# Simple launcher for mangosint

export PYTHONPATH="$(pwd)/src"
python3 -m mangosint.cli "$@"
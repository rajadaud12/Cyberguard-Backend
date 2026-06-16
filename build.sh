#!/usr/bin/env bash
# Exit immediately if a command exits with a non-zero status
set -o errexit

echo "=== Starting Build Process ==="

# 1. Install python dependencies
echo "Installing python dependencies..."
pip install -r requirements.txt

# 2. Download and install Nuclei Linux binary
if [ -f bin/nuclei ]; then
    echo "Nuclei binary already exists at bin/nuclei. Skipping download."
else
    python install_nuclei.py
fi

echo "=== Build Process Completed Successfully ==="

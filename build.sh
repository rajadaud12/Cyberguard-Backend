#!/usr/bin/env bash
# Exit immediately if a command exits with a non-zero status
set -o errexit

echo "=== Starting Build Process ==="

# 1. Install python dependencies
echo "Installing python dependencies..."
pip install -r requirements.txt

# 2. Download, install, and initialize Nuclei
python install_nuclei.py

echo "=== Build Process Completed Successfully ==="

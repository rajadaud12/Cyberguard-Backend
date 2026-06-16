#!/usr/bin/env bash
# Exit immediately if a command exits with a non-zero status
set -o errexit

echo "=== Starting Build Process ==="

# 1. Install python dependencies
echo "Installing python dependencies..."
pip install -r requirements.txt

# 2. Download and install Nuclei Linux binary
mkdir -p bin

if [ -f bin/nuclei ]; then
    echo "Nuclei binary already exists at bin/nuclei. Skipping download."
else
    echo "Downloading latest Nuclei binary for Linux AMD64..."
    # Retrieve the latest release URL for Linux AMD64 from GitHub api
    LATEST_NUCLEI_URL=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep "browser_download_url" | grep "linux_amd64.tar.gz" | cut -d '"' -f 4)
    
    if [ -z "$LATEST_NUCLEI_URL" ]; then
        echo "Error: Could not retrieve latest Nuclei release URL."
        exit 1
    fi
    
    echo "Downloading from: $LATEST_NUCLEI_URL"
    curl -L "$LATEST_NUCLEI_URL" -o nuclei.tar.gz
    
    echo "Extracting binary..."
    tar -xzf nuclei.tar.gz -C bin nuclei
    rm nuclei.tar.gz
    
    chmod +x bin/nuclei
    echo "Nuclei successfully installed at bin/nuclei!"
fi

echo "=== Build Process Completed Successfully ==="

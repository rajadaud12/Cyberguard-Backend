import os
import sys
import urllib.request
import zipfile
import io
import shutil

def install_nuclei():
    print("=== Downloading Nuclei Linux Binary ===")
    
    # 1. Fetch the latest release redirect URL (bypasses GitHub API rate limits)
    latest_url = "https://github.com/projectdiscovery/nuclei/releases/latest"
    try:
        req = urllib.request.Request(
            latest_url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        with urllib.request.urlopen(req) as response:
            redirected_url = response.geturl()
    except Exception as e:
        print(f"Error fetching latest release redirect URL: {e}", file=sys.stderr)
        sys.exit(1)
        
    # Example redirected_url: https://github.com/projectdiscovery/nuclei/releases/tag/v3.9.0
    tag = redirected_url.split('/')[-1]
    if not tag or not tag.startswith('v'):
        # Fallback to a hardcoded stable version if parsing failed
        tag = "v3.3.4"
        print(f"Failed to parse tag from redirect URL. Falling back to default: {tag}")
    else:
        print(f"Detected latest version tag: {tag}")

    version = tag.lstrip('v')
    
    # 2. Construct download URL for Linux AMD64 zip
    download_url = f"https://github.com/projectdiscovery/nuclei/releases/download/{tag}/nuclei_{version}_linux_amd64.zip"
    print(f"Downloading from: {download_url}")
    
    try:
        # 3. Download the zip file in-memory
        req_dl = urllib.request.Request(
            download_url,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req_dl) as dl_response:
            zip_data = dl_response.read()
    except Exception as e:
        print(f"Error downloading Nuclei binary zip: {e}", file=sys.stderr)
        sys.exit(1)

    # 4. Extract nuclei binary to bin/ folder
    os.makedirs("bin", exist_ok=True)
    bin_name = "nuclei" # We are downloading the Linux binary, so it's named 'nuclei'
    
    try:
        with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
            # Look for the nuclei binary inside the zip (could be 'nuclei' or './nuclei')
            target_file = None
            for name in z.namelist():
                if name == "nuclei" or name.endswith("/nuclei"):
                    target_file = name
                    break
            
            if not target_file:
                print("Error: 'nuclei' binary not found inside the zip archive.", file=sys.stderr)
                print(f"Files found in zip: {z.namelist()}", file=sys.stderr)
                sys.exit(1)
                
            print(f"Extracting '{target_file}' to 'bin/{bin_name}'...")
            with z.open(target_file) as source, open(os.path.join("bin", bin_name), "wb") as target:
                shutil.copyfileobj(source, target)
                
        # 5. Set executable permissions (Unix/Linux)
        target_path = os.path.join("bin", bin_name)
        if os.name != 'nt':
            os.chmod(target_path, 0o755)
            print(f"Set executable permissions for {target_path}")
            
        print("=== Nuclei Installation Completed Successfully ===")
        
    except Exception as e:
        print(f"Error extracting binary: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    install_nuclei()

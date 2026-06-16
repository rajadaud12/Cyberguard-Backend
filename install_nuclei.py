import os
import sys
import urllib.request
import zipfile
import io
import shutil

def install_nuclei():
    is_windows = os.name == "nt"
    bin_name = "nuclei.exe" if is_windows else "nuclei"
    target_path = os.path.join("bin", bin_name)
    
    if os.path.exists(target_path):
        print(f"Nuclei binary already exists at {target_path}. Skipping download.")
    else:
        print("=== Downloading Nuclei Linux Binary ===")
        
        # 1. Fetch the latest release redirect URL (bypasses GitHub API rate limits)
        latest_url = "https://github.com/projectdiscovery/nuclei/releases/latest"
        try:
            req = urllib.request.Request(
                latest_url, 
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            with urllib.request.urlopen(req) as response:
                redirected_url = response.geturl()
        except Exception as e:
            print(f"Error fetching latest release redirect URL: {e}", file=sys.stderr)
            sys.exit(1)
            
        # Example redirected_url: https://github.com/projectdiscovery/nuclei/releases/tag/v3.9.0
        tag = redirected_url.split('/')[-1]
        if not tag or not tag.startswith('v'):
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
        
        try:
            with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
                target_file = None
                for name in z.namelist():
                    if name == "nuclei" or name.endswith("/nuclei"):
                        target_file = name
                        break
                
                if not target_file:
                    print("Error: 'nuclei' binary not found inside the zip archive.", file=sys.stderr)
                    sys.exit(1)
                    
                print(f"Extracting '{target_file}' to '{target_path}'...")
                with z.open(target_file) as source, open(target_path, "wb") as target:
                    shutil.copyfileobj(source, target)
                    
            # 5. Set executable permissions (Unix/Linux)
            if not is_windows:
                os.chmod(target_path, 0o755)
                print(f"Set executable permissions for {target_path}")
                
        except Exception as e:
            print(f"Error extracting binary: {e}", file=sys.stderr)
            sys.exit(1)

    # 6. Initialize / update templates (Run always, even if binary exists)
    print("Initializing/downloading Nuclei templates...")
    import subprocess
    try:
        # Run the binary to download the templates
        # We also pass -ud to make sure they are stored under the user's home directory normally
        # or it will download default templates into the default location.
        result = subprocess.run([target_path, "-update-templates"], capture_output=True, text=True, timeout=180)
        if result.returncode == 0:
            print("Nuclei templates downloaded/updated successfully!")
        else:
            print(f"Warning: Nuclei template update exited with code {result.returncode}")
            print(f"Stdout: {result.stdout}")
            print(f"Stderr: {result.stderr}")
    except Exception as te:
        print(f"Warning: Could not update templates automatically: {te}")
        
    print("=== Nuclei Installation Completed Successfully ===")

if __name__ == "__main__":
    install_nuclei()

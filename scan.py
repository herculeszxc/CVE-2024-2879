import re
import sys
import requests

def check_vulnerability(version_str):
    return version_str.strip() in ["7.9.11", "7.10.0"]

def scan_url(url, index, total, valid_file):
    try:
        response = requests.get(url, timeout=5)  # Set a timeout to avoid waiting indefinitely
        if response.status_code == 200:
            content = response.text
            pattern = r'layerslider\.css\?ver=(\d+\.\d+\.\d+)|Powered by LayerSlider (\d+\.\d+\.\d+)'
            found_vuln = False
            for match in re.findall(pattern, content):
                version_str = next(filter(None, match))
                if check_vulnerability(version_str):
                    print(f"[{index}/{total}] : {url} - VULN VER {version_str}")
                    with open(valid_file, 'a') as f:
                        f.write(url + '\n')
                    found_vuln = True
                    break  # Once vulnerability is detected, move to the next URL
            if not found_vuln:
                print(f"[{index}/{total}] : {url} - NOT VULN")
        else:
            print(f"[{index}/{total}] : {url} - NOT VULN (Failed to fetch)")
    except Exception as e:
        print(f"[{index}/{total}] : {url} - NOT VULN (Error occurred)")

def scan_file(filename, valid_file):
    try:
        with open(filename, 'r') as f:
            urls = f.read().splitlines()
            total = len(urls)
            for i, url in enumerate(urls, start=1):
                scan_url(url, i, total, valid_file)
    except Exception as e:
        print("Error occurred while reading the file:", e)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scan.py <url_or_file>")
        sys.exit(1)

    target = sys.argv[1]

    valid_file = 'vulns.txt'

    if target.startswith("http://") or target.startswith("https://"):
        scan_url(target, 1, 1, valid_file)
    else:
        scan_file(target, valid_file)
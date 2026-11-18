#!/usr/bin/env python3
# ReconX - Standalone passive recon script (original)
import os
import sys
import tempfile
from urllib.parse import urlsplit, urlparse
import subprocess

def get_hostname(url):
    if url.startswith('http'):
        url_components = urlsplit(url)
        return url_components.netloc
    else:
        return url

def good_url(url):
    extensions = ['.json', '.js', '.fnt', '.ogg', '.css', '.jpg', '.jpeg', '.png', '.svg', '.ing', '.gif', '.exe', '.mp4', '.ftv', '.pdf', '.doc', '.ogv',
                    'webm', '.wmv', '.webp', '.mov', '.mp3', '.m4a', '.m4p', '.ppt', '.pptx', '.scss', '.tif', '.ttff', '.ttf', '.otf', '.woff',
                    '.woff2', '.bmp', '.ico', '.ect', '.htc', '.swf', '.rtf', '.image', '.rf', '.txt', 'xml', 'zip']
    try:
        parsed_url = urlparse(url)
        for ext in extensions:
            if (parsed_url.path).endswith(ext):
                return False
        return True
    except Exception as e:
        print(f"Error: {str(e)}")
        return None
    return None

def finalize(file_path, domain):
    unique_lines = set()
    with open(file_path, 'r') as file:
        for line in file:
            if good_url(line):
                unique_lines.add(line.strip())
    unique_lines = {value for value in unique_lines if value}
    if len(unique_lines) == 0:
        return False
    with open(f"{domain}.passive", 'w') as file:
        for element in unique_lines:
            file.write(str(element) + '\n')
    return unique_lines

def is_file(filepath):
    return os.path.isfile(filepath)

def generate_temp_file():
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
        return temp_file.name

class colors:
    GRAY = '\033[90m'
    RESET = '\033[0m'

def run_command_in_zsh(command):
    try:
        result = subprocess.run(['zsh', '-c', command], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"{colors.GRAY}Error running command: {e}{colors.RESET}")
        return ""

def run_nice_passive(domain):
    temp_file = generate_temp_file()
    print(f"{colors.GRAY}gathering URLs passively for: {domain}{colors.RESET}")
    commands = [
        f"echo https://{domain}/ | tee {temp_file}",
        f"echo {domain} | waybackurls | sort -u | uro | tee -a {temp_file}",
        f"gau {domain} --threads 1 --subs | sort -u | uro | tee -a {temp_file}"
    ]
    for command in commands:
        print(f"{colors.GRAY}Executing commands: {command}{colors.RESET}")
        res = run_command_in_zsh(command)
    print(f"{colors.GRAY}merging result for: {domain}{colors.RESET}")
    res = finalize(temp_file, domain)
    res_num = len(res) if res else 0
    print(f"{colors.GRAY}done for {domain}, results: {res_num}{colors.RESET}")

def get_input():
    if not sys.stdin.isatty():
        return sys.stdin.readline().strip()
    elif len(sys.argv) > 1:
        return sys.argv[1]
    else:
        return None

if __name__ == "__main__":
    input = get_input()
    if input is None:
        print("Usage: echo domain.tld | nice_passive")
        print("Usage: cat domains.txt | nice_passive")
        sys.exit()
    if is_file(input):
        with open(input, 'r') as file:
            for line in file:
                domain = get_hostname(line.strip())
                run_nice_passive(domain)
    else:
        run_nice_passive(get_hostname(input.strip()))

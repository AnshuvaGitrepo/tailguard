"""Compare the console text of the bash script and the Go exe.

The two tools must explain findings in the same words. Differences that are
expected between Linux and Windows are normalised away first: "sudo ",
path separators, the date/time line and the report paths.

Usage: python compare_output.py EXE_OUTPUT.txt SH_OUTPUT.txt
Exit 0 if the same, 1 (with a word diff) if not.
"""
import difflib
import re
import sys


def words(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    text = text.replace("\r", "").replace(chr(92), "/").replace("sudo ", "")
    lines = [l for l in text.split("\n")
             if not l.startswith("Report:") and "tailscale-audit-" not in l]
    text = "\n".join(lines)
    text = re.sub(r"\d+ \w{3} \d{4} \d{2}:\d{2}", "DATE", text)
    # D:/path (Windows) vs /d/path (Git Bash)
    text = re.sub(r"\b([A-Za-z]):/", lambda m: "/" + m.group(1).lower() + "/", text)
    # "with sudo" (Linux) vs "from an Administrator PowerShell" (Windows)
    text = re.sub(r"from\s+an\s+Administrator\s+PowerShell", "with", text)
    return [w for w in text.split() if w != "sudo"]


a, b = words(sys.argv[1]), words(sys.argv[2])
if a == b:
    sys.exit(0)
for line in difflib.unified_diff(a, b, "exe", "sh", n=8, lineterm=""):
    print(line)
sys.exit(1)

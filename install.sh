#!/usr/bin/env bash
# SearchCVE - Live NVD CVE Search Tool
# Owner: Prekarshamaxx123 (https://github.com/Prekarshamaxx123)

set -e

echo "[*] Installing SearchCVE by Prekarshamaxx123..."

# Install python package
python3 -m pip install --upgrade .

# Ensure ~/.local/bin exists
mkdir -p "$HOME/.local/bin"

BIN_PATH=$(which searchcve 2>/dev/null || echo "$HOME/.local/bin/searchcve")

for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -f "$rc" ]; then
        if ! grep -q "SearchCVE" "$rc"; then
            echo -e '\n# SearchCVE - Live NVD CVE Search Tool (Owner: Prekarshamaxx123)\nexport PATH="$HOME/.local/bin:$PATH"\nalias searchcve="'"$BIN_PATH"'"' >> "$rc"
            echo "[+] Registered searchcve in $rc"
        fi
    fi
done

echo ""
echo "[+] Installation successful!"
echo "[+] Owner: Prekarshamaxx123 (https://github.com/Prekarshamaxx123)"
echo "[+] You can now run 'searchcve' from any terminal."

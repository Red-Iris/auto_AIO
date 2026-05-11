#!/usr/bin/env bash
# AutoAIO Security Test Platform - One-Click Environment Setup
# Run: chmod +x setup.sh && ./setup.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.json"
TOOLS_DIR="$SCRIPT_DIR/tools"
CVE_VENV_DIR="$TOOLS_DIR/cve-venv"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m'

status_ok()    { echo -e "  ${GREEN}[OK]${NC}    $1${2:+ ${GRAY}- $2${NC}}"; }
status_miss()  { echo -e "  ${RED}[MISS]${NC}  $1${2:+ ${GRAY}- $2${NC}}"; }

ALL_OK=true

echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  AutoAIO Security Test Platform - Environment Setup${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

# ============================================================
# Step 1 - Check Python
# ============================================================
echo -e "${YELLOW}[1/5] Checking Python...${NC}"
if command -v python3 &>/dev/null; then
    PY_VER=$(python3 --version 2>&1)
    status_ok "Python" "$PY_VER"
    PYTHON=python3
elif command -v python &>/dev/null; then
    PY_VER=$(python --version 2>&1)
    status_ok "Python" "$PY_VER"
    PYTHON=python
else
    status_miss "Python" "Not installed"
    echo -e "         Install: sudo apt install python3 (Debian/Ubuntu)"
    echo -e "                  brew install python3 (macOS)"
    ALL_OK=false
fi

# ============================================================
# Step 2 - Check Wireshark/TShark
# ============================================================
echo ""
echo -e "${YELLOW}[2/5] Checking Wireshark/TShark...${NC}"
if command -v tshark &>/dev/null; then
    TSHARK_VER=$(tshark --version 2>&1 | head -1)
    status_ok "TShark" "$TSHARK_VER"
else
    status_miss "TShark" "Not found in PATH"
    echo -e "         Install: sudo apt install tshark (Debian/Ubuntu)"
    echo -e "                  brew install wireshark (macOS)"
    ALL_OK=false
fi

# ============================================================
# Step 3 - Check Nmap
# ============================================================
echo ""
echo -e "${YELLOW}[3/5] Checking Nmap...${NC}"
if command -v nmap &>/dev/null; then
    NMAP_VER=$(nmap --version 2>&1 | head -1)
    status_ok "Nmap" "$NMAP_VER"
else
    status_miss "Nmap" "Not found in PATH"
    echo -e "         Install: sudo apt install nmap (Debian/Ubuntu)"
    echo -e "                  brew install nmap (macOS)"
    ALL_OK=false
fi

# ============================================================
# Step 4 - Check OpenSSL
# ============================================================
echo ""
echo -e "${YELLOW}[4/5] Checking OpenSSL...${NC}"
if command -v openssl &>/dev/null; then
    SSL_VER=$(openssl version 2>&1)
    status_ok "OpenSSL" "$SSL_VER"
else
    status_miss "OpenSSL" "Not found in PATH"
    echo -e "         Install: sudo apt install openssl (Debian/Ubuntu)"
    echo -e "                  brew install openssl (macOS)"
    ALL_OK=false
fi

# ============================================================
# Step 5 - Setup cve-bin-tool
# ============================================================
echo ""
echo -e "${YELLOW}[5/5] Setting up cve-bin-tool...${NC}"

CVE_BIN="$CVE_VENV_DIR/bin/cve-bin-tool"
if [ -x "$CVE_BIN" ]; then
    CVE_VER=$("$CVE_BIN" --version 2>&1 | head -1)
    status_ok "cve-bin-tool" "(tools/cve-venv) $CVE_VER"
else
    echo -e "        Creating isolated cve-bin-tool virtual environment..."
    echo -e "        Location: $CVE_VENV_DIR"

    mkdir -p "$TOOLS_DIR"
    ${PYTHON:-python3} -m venv "$CVE_VENV_DIR"

    PIP="$CVE_VENV_DIR/bin/pip"
    echo -e "        Installing cve-bin-tool (this may take a few minutes)..."
    "$PIP" install cve-bin-tool==3.4 --quiet

    if [ -x "$CVE_BIN" ]; then
        CVE_VER=$("$CVE_BIN" --version 2>&1 | head -1)
        status_ok "cve-bin-tool" "$CVE_VER"
        echo -e "        ${GREEN}cve-bin-tool installed successfully in tools/cve-venv/${NC}"
    else
        status_miss "cve-bin-tool" "Installation incomplete"
        ALL_OK=false
    fi
fi

# ============================================================
# Generate config.json
# ============================================================
echo ""
echo -e "${YELLOW}Generating config.json...${NC}"

CONFIG="{}"
if [ -f "$CONFIG_FILE" ]; then
    CONFIG=$(cat "$CONFIG_FILE")
fi

# Use Python to merge and write JSON
${PYTHON:-python3} -c "
import json, os, shutil
cfg = {}
try:
    with open('$CONFIG_FILE', 'r') as f:
        cfg = json.load(f)
except: pass

cfg['cve_bin_tool_path'] = os.path.join('$CVE_VENV_DIR', 'bin', 'cve-bin-tool')

tshark_path = shutil.which('tshark')
if tshark_path:
    cfg['tshark_path'] = tshark_path

with open('$CONFIG_FILE', 'w') as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
"
echo -e "        Config saved to: $CONFIG_FILE"

# ============================================================
# Summary
# ============================================================
echo ""
echo -e "${CYAN}============================================================${NC}"
if [ "$ALL_OK" = true ]; then
    echo -e "  ${GREEN}All tools ready! You can now run the application.${NC}"
else
    echo -e "  ${YELLOW}Some tools are missing. See install hints above.${NC}"
    echo -e "  ${YELLOW}After installing missing tools, re-run this script.${NC}"
fi
echo -e "${CYAN}============================================================${NC}"
echo ""
echo -e "Next steps:"
echo -e "  1. Run: python3 gui.py"
echo -e "  2. Go to 'System Check' tab to verify all tools"
echo -e "  3. (Optional) Apply for NVD API Key: https://nvd.nist.gov/developers/request-an-api-key"
echo ""

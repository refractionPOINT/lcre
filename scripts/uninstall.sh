#!/usr/bin/env bash
# LCRE Uninstaller - Removes LCRE and all its components
#
# Usage: bash uninstall.sh
#    or: ~/.local/share/lcre/uninstall.sh

set -euo pipefail

INSTALL_DIR="${HOME}/.local/share/lcre"
BIN_DIR="${HOME}/.local/bin"

# Colors for output
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
else
    GREEN=''
    YELLOW=''
    NC=''
fi

echo ""
echo "LCRE Uninstaller"
echo "================"
echo ""

# Check what exists
installed=()
if [ -d "$INSTALL_DIR" ]; then
    installed+=("$INSTALL_DIR")
fi
if [ -f "${BIN_DIR}/lcre" ]; then
    installed+=("${BIN_DIR}/lcre")
fi

if [ ${#installed[@]} -eq 0 ]; then
    echo "LCRE does not appear to be installed."
    exit 0
fi

echo "The following will be removed:"
for item in "${installed[@]}"; do
    echo "  - $item"
done

# Calculate installed size if possible
if [ -d "$INSTALL_DIR" ]; then
    size=$(du -sh "$INSTALL_DIR" 2>/dev/null | cut -f1 || echo "unknown")
    echo ""
    echo -e "${YELLOW}This will free approximately ${size} of disk space.${NC}"
fi

echo ""
read -p "Are you sure you want to uninstall LCRE? [y/N] " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Removing LCRE..."

    if [ -d "$INSTALL_DIR" ]; then
        rm -rf "$INSTALL_DIR"
        echo "  Removed $INSTALL_DIR"
    fi

    if [ -f "${BIN_DIR}/lcre" ]; then
        rm -f "${BIN_DIR}/lcre"
        echo "  Removed ${BIN_DIR}/lcre"
    fi

    echo ""
    echo -e "${GREEN}LCRE has been uninstalled successfully.${NC}"
else
    echo ""
    echo "Uninstall cancelled."
fi

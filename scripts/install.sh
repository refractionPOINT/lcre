#!/usr/bin/env bash
# LCRE Installer - Downloads and sets up LCRE with full Ghidra support
# No sudo required, everything installed to ~/.local/
#
# Usage: curl -fsSL https://raw.githubusercontent.com/USER/lcre/main/scripts/install.sh | bash

set -euo pipefail

# Configuration
LCRE_VERSION="${LCRE_VERSION:-latest}"
GHIDRA_VERSION="11.0.3"
GHIDRA_DATE="20231218"
JDK_VERSION="17"

# XDG-compliant install locations
INSTALL_DIR="${HOME}/.local/share/lcre"
BIN_DIR="${HOME}/.local/bin"

# Colors for output (if terminal supports it)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

# Detect architecture
detect_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)
            echo "x64"
            ;;
        aarch64|arm64)
            echo "aarch64"
            ;;
        *)
            error "Unsupported architecture: $arch (only x86_64 and aarch64 are supported)"
            ;;
    esac
}

# Detect OS
detect_os() {
    local os
    os=$(uname -s)
    case "$os" in
        Linux)
            echo "linux"
            ;;
        *)
            error "Unsupported OS: $os (only Linux is currently supported)"
            ;;
    esac
}

# Check required tools
check_dependencies() {
    local missing=()
    for cmd in curl tar unzip; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -ne 0 ]; then
        error "Missing required tools: ${missing[*]}"
    fi
}

# Download with progress
download() {
    local url="$1"
    local output="$2"
    local description="$3"

    info "Downloading $description..."
    if ! curl -fSL --progress-bar -o "$output" "$url"; then
        error "Failed to download $description from $url"
    fi
}

# Get the latest LCRE release version from GitHub
get_latest_version() {
    local latest
    latest=$(curl -fsSL "https://api.github.com/repos/refractionPOINT/lcre/releases/latest" 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/' || echo "")
    if [ -z "$latest" ]; then
        error "Failed to get latest LCRE version from GitHub"
    fi
    echo "$latest"
}

# Install LCRE binary
install_lcre_binary() {
    local arch="$1"
    local lcre_arch

    # Map architecture for LCRE binary naming
    case "$arch" in
        x64)
            lcre_arch="amd64"
            ;;
        aarch64)
            lcre_arch="arm64"
            ;;
    esac

    local version="$LCRE_VERSION"
    if [ "$version" = "latest" ]; then
        info "Fetching latest LCRE version..."
        version=$(get_latest_version)
    fi

    local url="https://github.com/refractionPOINT/lcre/releases/download/${version}/lcre-linux-${lcre_arch}"
    local output="${INSTALL_DIR}/bin/lcre"

    download "$url" "$output" "LCRE ${version}"
    chmod +x "$output"
    success "LCRE binary installed"
}

# Install Adoptium JDK
install_jdk() {
    local arch="$1"
    local jdk_dir="${INSTALL_DIR}/jdk"

    # Check if JDK is already installed
    if [ -d "$jdk_dir" ] && [ -n "$(ls -A "$jdk_dir" 2>/dev/null)" ]; then
        local existing_jdk
        existing_jdk=$(ls -1 "$jdk_dir" | head -1)
        if [ -x "${jdk_dir}/${existing_jdk}/bin/java" ]; then
            success "JDK already installed at ${jdk_dir}/${existing_jdk}"
            return
        fi
    fi

    # Adoptium API for JDK download
    local url="https://api.adoptium.net/v3/binary/latest/${JDK_VERSION}/ga/linux/${arch}/jdk/hotspot/normal/eclipse"
    local tmp_file="${INSTALL_DIR}/tmp/jdk.tar.gz"

    mkdir -p "${INSTALL_DIR}/tmp"
    download "$url" "$tmp_file" "Adoptium JDK ${JDK_VERSION}"

    info "Extracting JDK..."
    mkdir -p "$jdk_dir"
    tar -xzf "$tmp_file" -C "$jdk_dir"
    rm -f "$tmp_file"

    success "JDK installed"
}

# Install Ghidra
install_ghidra() {
    local ghidra_dir="${INSTALL_DIR}/ghidra"
    local ghidra_full_dir="${ghidra_dir}/ghidra_${GHIDRA_VERSION}_PUBLIC"

    # Check if Ghidra is already installed
    if [ -d "$ghidra_full_dir" ] && [ -x "${ghidra_full_dir}/support/analyzeHeadless" ]; then
        success "Ghidra already installed at ${ghidra_full_dir}"
        return
    fi

    local url="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip"
    local tmp_file="${INSTALL_DIR}/tmp/ghidra.zip"

    mkdir -p "${INSTALL_DIR}/tmp"
    download "$url" "$tmp_file" "Ghidra ${GHIDRA_VERSION}"

    info "Extracting Ghidra (this may take a moment)..."
    mkdir -p "$ghidra_dir"
    unzip -q "$tmp_file" -d "$ghidra_dir"
    rm -f "$tmp_file"

    success "Ghidra installed"
}

# Install Ghidra scripts
install_ghidra_scripts() {
    local scripts_dir="${INSTALL_DIR}/scripts/ghidra"
    mkdir -p "$scripts_dir"

    # Download scripts from the repository
    local base_url="https://raw.githubusercontent.com/refractionPOINT/lcre/main/scripts/ghidra"

    info "Installing Ghidra scripts..."
    curl -fsSL "${base_url}/ExportAnalysis.java" -o "${scripts_dir}/ExportAnalysis.java"

    success "Ghidra scripts installed"
}

# Create wrapper script
create_wrapper() {
    local arch="$1"
    local jdk_path
    local ghidra_path="${INSTALL_DIR}/ghidra/ghidra_${GHIDRA_VERSION}_PUBLIC"
    local scripts_path="${INSTALL_DIR}/scripts/ghidra"

    # Find the JDK directory (it includes version in name)
    jdk_path=$(ls -d "${INSTALL_DIR}/jdk/jdk-"* 2>/dev/null | head -1)
    if [ -z "$jdk_path" ]; then
        error "JDK installation not found"
    fi

    mkdir -p "$BIN_DIR"

    cat > "${BIN_DIR}/lcre" << EOF
#!/usr/bin/env bash
# LCRE wrapper script - sets up environment for Ghidra support

export JAVA_HOME="${jdk_path}"
export PATH="\${JAVA_HOME}/bin:\${PATH}"
export GHIDRA_HOME="${ghidra_path}"
export LCRE_SCRIPTS_PATH="${scripts_path}"

exec "${INSTALL_DIR}/bin/lcre" "\$@"
EOF

    chmod +x "${BIN_DIR}/lcre"
    success "Wrapper script created at ${BIN_DIR}/lcre"
}

# Copy uninstall script
install_uninstaller() {
    local uninstall_script="${INSTALL_DIR}/uninstall.sh"

    cat > "$uninstall_script" << 'EOF'
#!/usr/bin/env bash
# LCRE Uninstaller

set -euo pipefail

INSTALL_DIR="${HOME}/.local/share/lcre"
BIN_DIR="${HOME}/.local/bin"

echo "This will remove LCRE and all its components from:"
echo "  - ${INSTALL_DIR}"
echo "  - ${BIN_DIR}/lcre"
echo ""
read -p "Are you sure you want to uninstall? [y/N] " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "${INSTALL_DIR}"
    rm -f "${BIN_DIR}/lcre"
    echo "LCRE has been uninstalled."
else
    echo "Uninstall cancelled."
fi
EOF

    chmod +x "$uninstall_script"
    success "Uninstaller script installed at ${uninstall_script}"
}

# Check if PATH includes ~/.local/bin
check_path() {
    if [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
        echo ""
        warn "${BIN_DIR} is not in your PATH"
        echo ""
        echo "Add it to your shell profile with one of these commands:"
        echo ""
        echo "  For bash (~/.bashrc):"
        echo "    echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc"
        echo ""
        echo "  For zsh (~/.zshrc):"
        echo "    echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc"
        echo ""
        echo "Then restart your shell or run: source ~/.bashrc (or ~/.zshrc)"
    fi
}

# Cleanup on failure
cleanup_on_error() {
    error "Installation failed. Cleaning up..."
    rm -rf "${INSTALL_DIR}/tmp"
}

# Main installation
main() {
    echo ""
    echo "=============================================="
    echo "  LCRE Installer"
    echo "  LimaCharlie Reverse Engineering Toolkit"
    echo "=============================================="
    echo ""

    trap cleanup_on_error ERR

    info "Checking system requirements..."
    check_dependencies

    local os
    local arch
    os=$(detect_os)
    arch=$(detect_arch)
    info "Detected: ${os} ${arch}"

    # Create installation directories
    info "Creating installation directories..."
    mkdir -p "${INSTALL_DIR}/bin"
    mkdir -p "${INSTALL_DIR}/ghidra"
    mkdir -p "${INSTALL_DIR}/jdk"
    mkdir -p "${INSTALL_DIR}/scripts/ghidra"
    mkdir -p "${INSTALL_DIR}/tmp"

    # Install components
    install_lcre_binary "$arch"
    install_jdk "$arch"
    install_ghidra
    install_ghidra_scripts
    create_wrapper "$arch"
    install_uninstaller

    # Cleanup
    rm -rf "${INSTALL_DIR}/tmp"

    echo ""
    echo "=============================================="
    success "LCRE installation complete!"
    echo "=============================================="
    echo ""
    echo "Installation location: ${INSTALL_DIR}"
    echo ""
    echo "Components installed:"
    echo "  - LCRE binary"
    echo "  - Adoptium JDK ${JDK_VERSION}"
    echo "  - Ghidra ${GHIDRA_VERSION}"
    echo "  - Ghidra analysis scripts"
    echo ""

    check_path

    echo ""
    echo "Quick start:"
    echo "  lcre --version          # Check installation"
    echo "  lcre analyze /bin/ls    # Quick analysis"
    echo "  lcre analyze --deep /bin/ls  # Deep analysis with Ghidra"
    echo ""
    echo "To uninstall: ${INSTALL_DIR}/uninstall.sh"
    echo ""
}

main "$@"

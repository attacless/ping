#!/usr/bin/env bash
#
# Ping - Decentralized Encrypted Messenger
# Autoinstaller Script
#
# Usage: curl -sSL https://raw.githubusercontent.com/attacless/ping/main/install.sh | bash
#    or: ./install.sh [OPTIONS]
#
# Options:
#   --no-optional     Skip optional dependencies (secp256k1, coincurve, qrcode)
#   --pip-only        Force pip installation even on Debian-based systems
#   --clone           Clone full repository instead of single file download
#   --help            Show this help message
#
# Repository: https://github.com/attacless/ping
# License: MIT
#

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

REPO_URL="https://github.com/attacless/ping.git"
RAW_URL="https://raw.githubusercontent.com/attacless/ping/main/ping.py"
SCRIPT_NAME="ping.py"
MIN_PYTHON_VERSION="3.12"

# Colors (disabled if not in terminal)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m' # No Color
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' NC=''
fi

# =============================================================================
# Default Options
# =============================================================================

INSTALL_OPTIONAL=true
FORCE_PIP=false
CLONE_REPO=false

# =============================================================================
# Utility Functions
# =============================================================================

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[✓]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_step()    { echo -e "${CYAN}[→]${NC} $*"; }

die() {
    log_error "$*"
    exit 1
}

print_banner() {
    echo -e "${BOLD}${CYAN}"
    cat << 'EOF'
    ____  _            
   / __ \(_)___  ____ _
  / /_/ / / __ \/ __ `/
 / ____/ / / / / /_/ / 
/_/   /_/_/ /_/\__, /  
              /____/   
EOF
    echo -e "${NC}"
    echo -e "${BOLD}Decentralized Encrypted Messenger${NC}"
    echo -e "Installer v1.0.0"
    echo ""
}

print_help() {
    cat << EOF
Ping Autoinstaller

Usage: $0 [OPTIONS]

Options:
    --no-optional     Skip optional dependencies (secp256k1, coincurve, qrcode)
    --pip-only        Force pip installation even on Debian-based systems
    --clone           Clone full repository instead of single file download
    --help            Show this help message

Examples:
    # Standard installation
    ./install.sh

    # Minimal installation (required deps only)
    ./install.sh --no-optional

    # Clone full repository
    ./install.sh --clone

EOF
}

# =============================================================================
# Detection Functions
# =============================================================================

detect_os() {
    local os=""
    
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        os="${ID:-unknown}"
    elif [[ -f /etc/debian_version ]]; then
        os="debian"
    elif [[ -f /etc/redhat-release ]]; then
        os="rhel"
    elif [[ "$(uname)" == "Darwin" ]]; then
        os="macos"
    elif [[ -n "${TERMUX_VERSION:-}" ]] || [[ -d "/data/data/com.termux" ]]; then
        os="termux"
    elif [[ "$(uname -o 2>/dev/null)" == "Android" ]]; then
        os="termux"
    else
        os="unknown"
    fi
    
    echo "$os"
}

detect_distro_family() {
    local os="$1"
    
    case "$os" in
        debian|ubuntu|linuxmint|pop|elementary|zorin|kali|parrot|tails|mx|antix|deepin|lmde)
            echo "debian"
            ;;
        fedora|centos|rhel|rocky|alma|oracle|scientific|amzn)
            echo "rhel"
            ;;
        arch|manjaro|endeavouros|artix|garuda)
            echo "arch"
            ;;
        opensuse*|suse|sles)
            echo "suse"
            ;;
        alpine)
            echo "alpine"
            ;;
        macos)
            echo "macos"
            ;;
        termux)
            echo "termux"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

check_command() {
    command -v "$1" &>/dev/null
}

check_python_version() {
    local python_cmd="$1"
    local min_version="$2"
    
    if ! check_command "$python_cmd"; then
        return 1
    fi
    
    local version
    version=$("$python_cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null) || return 1
    
    local min_major min_minor cur_major cur_minor
    min_major="${min_version%%.*}"
    min_minor="${min_version#*.}"
    cur_major="${version%%.*}"
    cur_minor="${version#*.}"
    
    if [[ "$cur_major" -gt "$min_major" ]]; then
        return 0
    elif [[ "$cur_major" -eq "$min_major" ]] && [[ "$cur_minor" -ge "$min_minor" ]]; then
        return 0
    fi
    
    return 1
}

find_python() {
    local python_cmds=("python3.13" "python3.12" "python3" "python")
    
    for cmd in "${python_cmds[@]}"; do
        if check_python_version "$cmd" "$MIN_PYTHON_VERSION"; then
            echo "$cmd"
            return 0
        fi
    done
    
    return 1
}

find_pip() {
    local python_cmd="$1"
    local pip_cmds=("${python_cmd} -m pip" "pip3" "pip")
    
    for cmd in "${pip_cmds[@]}"; do
        if $cmd --version &>/dev/null; then
            echo "$cmd"
            return 0
        fi
    done
    
    return 1
}

# =============================================================================
# Installation Functions
# =============================================================================

install_python_debian() {
    log_step "Installing Python ${MIN_PYTHON_VERSION}+ via apt..."
    
    sudo apt-get update -qq || die "Failed to update apt cache"
    
    # Try python3.12 first, fall back to python3
    if apt-cache show python3.12 &>/dev/null; then
        sudo apt-get install -y python3.12 python3.12-venv || die "Failed to install python3.12"
    else
        sudo apt-get install -y python3 python3-venv || die "Failed to install python3"
    fi
}

install_python_rhel() {
    log_step "Installing Python ${MIN_PYTHON_VERSION}+ via dnf/yum..."
    
    if check_command dnf; then
        sudo dnf install -y python3.12 || sudo dnf install -y python3 || die "Failed to install python3"
    else
        sudo yum install -y python3 || die "Failed to install python3"
    fi
}

install_python_arch() {
    log_step "Installing Python via pacman..."
    sudo pacman -Sy --noconfirm python python-pip || die "Failed to install python"
}

install_python_termux() {
    log_step "Installing Python via pkg..."
    pkg update -y || die "Failed to update pkg"
    pkg install -y python || die "Failed to install python"
}

install_pip_debian() {
    log_step "Installing pip via apt..."
    sudo apt-get install -y python3-pip || die "Failed to install pip"
}

install_pip_rhel() {
    log_step "Installing pip..."
    
    if check_command dnf; then
        sudo dnf install -y python3-pip || die "Failed to install pip"
    else
        sudo yum install -y python3-pip || sudo yum install -y python-pip || die "Failed to install pip"
    fi
}

install_deps_debian_native() {
    log_step "Installing dependencies via apt (native packages)..."
    
    local packages=("python3-cryptography" "python3-websockets" "python3-certifi")
    
    if [[ "$INSTALL_OPTIONAL" == true ]]; then
        packages+=("python3-coincurve" "python3-qrcode")
        # python3-secp256k1 may not be available in all repos
        if apt-cache show python3-secp256k1 &>/dev/null; then
            packages+=("python3-secp256k1")
        fi
    fi
    
    sudo apt-get install -y "${packages[@]}" 2>/dev/null || {
        log_warn "Some native packages not available, falling back to pip for missing packages"
        return 1
    }
    
    return 0
}

install_deps_pip() {
    local pip_cmd="$1"
    local break_system=""
    
    # Detect if we need --break-system-packages (Python 3.11+ on some distros)
    if $pip_cmd install --help 2>&1 | grep -q "break-system-packages"; then
        break_system="--break-system-packages"
    fi
    
    log_step "Installing required dependencies via pip..."
    $pip_cmd install $break_system cryptography websockets certifi || die "Failed to install required dependencies"
    
    if [[ "$INSTALL_OPTIONAL" == true ]]; then
        log_step "Installing optional dependencies via pip..."
        
        # Try secp256k1 first (faster), fall back to coincurve
        if ! $pip_cmd install $break_system secp256k1 2>/dev/null; then
            log_warn "secp256k1 not available, trying coincurve..."
            $pip_cmd install $break_system coincurve 2>/dev/null || log_warn "coincurve also unavailable (optional)"
        fi
        
        # QR code generation
        $pip_cmd install $break_system qrcode 2>/dev/null || log_warn "qrcode unavailable (optional)"
    fi
}

install_deps_termux() {
    log_step "Configuring Termux environment..."
    
    # Export Android API level for cryptography build
    if check_command getprop; then
        export ANDROID_API_LEVEL
        ANDROID_API_LEVEL=$(getprop ro.build.version.sdk)
        log_info "Detected Android API level: $ANDROID_API_LEVEL"
    fi
    
    log_step "Installing build dependencies..."
    pkg install -y rust binutils || log_warn "Some build tools may not be available"
    
    local pip_cmd
    pip_cmd=$(find_pip python) || die "pip not found"
    
    log_step "Installing cryptography (this may take a while on Termux)..."
    $pip_cmd install cryptography || die "Failed to install cryptography"
    
    log_step "Installing remaining dependencies..."
    $pip_cmd install websockets certifi || die "Failed to install websockets/certifi"
    
    if [[ "$INSTALL_OPTIONAL" == true ]]; then
        $pip_cmd install coincurve 2>/dev/null || log_warn "coincurve unavailable (optional)"
        $pip_cmd install qrcode 2>/dev/null || log_warn "qrcode unavailable (optional)"
    fi
}

download_ping() {
    local target_dir="${1:-.}"
    
    if [[ "$CLONE_REPO" == true ]]; then
        log_step "Cloning repository..."
        
        if ! check_command git; then
            die "git is required for --clone. Install git or run without --clone flag."
        fi
        
        if [[ -d "ping" ]]; then
            log_warn "Directory 'ping' already exists"
            read -rp "Remove and re-clone? [y/N] " response
            if [[ "$response" =~ ^[Yy]$ ]]; then
                rm -rf ping
            else
                die "Aborted"
            fi
        fi
        
        git clone "$REPO_URL" || die "Failed to clone repository"
        cd ping || die "Failed to enter ping directory"
        
    else
        log_step "Downloading ${SCRIPT_NAME}..."
        
        if [[ -f "$target_dir/$SCRIPT_NAME" ]]; then
            log_warn "${SCRIPT_NAME} already exists"
            read -rp "Overwrite? [y/N] " response
            if [[ ! "$response" =~ ^[Yy]$ ]]; then
                die "Aborted"
            fi
        fi
        
        if check_command curl; then
            curl -fsSL -o "$target_dir/$SCRIPT_NAME" "$RAW_URL" || die "Failed to download ${SCRIPT_NAME}"
        elif check_command wget; then
            wget -q -O "$target_dir/$SCRIPT_NAME" "$RAW_URL" || die "Failed to download ${SCRIPT_NAME}"
        else
            die "Neither curl nor wget found. Please install one of them."
        fi
        
        chmod +x "$target_dir/$SCRIPT_NAME"
    fi
}

verify_installation() {
    local python_cmd="$1"
    
    log_step "Verifying installation..."
    
    local missing=()
    
    # Check required modules
    for module in cryptography websockets certifi; do
        if ! $python_cmd -c "import $module" 2>/dev/null; then
            missing+=("$module")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required modules: ${missing[*]}"
        return 1
    fi
    
    # Check optional modules
    local optional_found=()
    local optional_missing=()
    
    for module in secp256k1 coincurve qrcode; do
        if $python_cmd -c "import $module" 2>/dev/null; then
            optional_found+=("$module")
        else
            optional_missing+=("$module")
        fi
    done
    
    if [[ ${#optional_found[@]} -gt 0 ]]; then
        log_info "Optional modules installed: ${optional_found[*]}"
    fi
    
    if [[ "$INSTALL_OPTIONAL" == true ]] && [[ ${#optional_missing[@]} -gt 0 ]]; then
        log_warn "Optional modules not installed: ${optional_missing[*]}"
    fi
    
    return 0
}

# =============================================================================
# Main Installation Flow
# =============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --no-optional)
                INSTALL_OPTIONAL=false
                shift
                ;;
            --pip-only)
                FORCE_PIP=true
                shift
                ;;
            --clone)
                CLONE_REPO=true
                shift
                ;;
            --help|-h)
                print_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                print_help
                exit 1
                ;;
        esac
    done
    
    print_banner
    
    # Detect platform
    local os distro_family
    os=$(detect_os)
    distro_family=$(detect_distro_family "$os")
    
    log_info "Detected OS: $os (family: $distro_family)"
    
    # Check/install Python
    local python_cmd
    if ! python_cmd=$(find_python); then
        log_warn "Python ${MIN_PYTHON_VERSION}+ not found. Attempting to install..."
        
        case "$distro_family" in
            debian)  install_python_debian ;;
            rhel)    install_python_rhel ;;
            arch)    install_python_arch ;;
            termux)  install_python_termux ;;
            macos)
                die "Python ${MIN_PYTHON_VERSION}+ required. Install via: brew install python@3.12"
                ;;
            *)
                die "Python ${MIN_PYTHON_VERSION}+ required. Please install manually."
                ;;
        esac
        
        python_cmd=$(find_python) || die "Python installation failed or version too old"
    fi
    
    log_success "Found Python: $python_cmd ($($python_cmd --version 2>&1))"
    
    # Install dependencies based on platform
    if [[ "$distro_family" == "termux" ]]; then
        install_deps_termux
        
    elif [[ "$distro_family" == "debian" ]] && [[ "$FORCE_PIP" != true ]]; then
        # Try native packages first on Debian-based systems
        if ! install_deps_debian_native; then
            log_info "Falling back to pip installation..."
            local pip_cmd
            pip_cmd=$(find_pip "$python_cmd") || {
                install_pip_debian
                pip_cmd=$(find_pip "$python_cmd") || die "pip installation failed"
            }
            install_deps_pip "$pip_cmd"
        fi
        
    else
        # Use pip for all other platforms
        local pip_cmd
        pip_cmd=$(find_pip "$python_cmd") || {
            case "$distro_family" in
                rhel) install_pip_rhel ;;
                *)    die "pip not found. Please install pip manually." ;;
            esac
            pip_cmd=$(find_pip "$python_cmd") || die "pip installation failed"
        }
        install_deps_pip "$pip_cmd"
    fi
    
    # Download Ping
    download_ping
    
    # Verify installation
    if ! verify_installation "$python_cmd"; then
        die "Installation verification failed"
    fi
    
    # Success message
    echo ""
    log_success "Installation complete!"
    echo ""
    echo -e "${BOLD}To start Ping:${NC}"
    if [[ "$CLONE_REPO" == true ]]; then
        echo -e "  ${CYAN}cd ping && $python_cmd ping.py${NC}"
    else
        echo -e "  ${CYAN}$python_cmd ping.py${NC}"
    fi
    echo ""
    echo -e "${BOLD}Quick commands:${NC}"
    echo -e "  Generate new identity:  ${CYAN}$python_cmd ping.py --new${NC}"
    echo -e "  Show your public key:   ${CYAN}$python_cmd ping.py --show-pubkey${NC}"
    echo -e "  Show help:              ${CYAN}$python_cmd ping.py --help${NC}"
    echo ""
}

# =============================================================================
# Entry Point
# =============================================================================

# Ensure we're not running as root unless necessary (Termux, etc.)
if [[ "$(id -u)" -eq 0 ]] && [[ -z "${TERMUX_VERSION:-}" ]] && [[ ! -d "/data/data/com.termux" ]]; then
    log_warn "Running as root is not recommended. Consider running as a regular user."
    read -rp "Continue anyway? [y/N] " response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        die "Aborted"
    fi
fi

main "$@"

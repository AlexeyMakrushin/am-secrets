#!/bin/bash
set -euo pipefail
umask 077

# am-secrets Installation Script
# ====================================

SECRETS_DIR="$HOME/.secrets"
LAUNCH_AGENTS="$HOME/Library/LaunchAgents"
ZSHRC="${ZDOTDIR:-$HOME}/.zshrc"
PLIST_NAME="com.ai-secrets.daemon.plist"

# Source root — the checkout that contains secrets-cli/ and secrets-daemon/.
#
# Defaults to the directory this script lives in, so running
# ~/Projects/am-secrets/install.sh builds the repository, not a stale copy
# somewhere else. Override with: install.sh --source /path/to/checkout
#
# This matters: before 2026-09-27 the build always read $SECRETS_DIR/secrets-cli,
# which had drifted ten files behind the repository. Running the installer from
# the repo silently installed month-old code.
SOURCE_DIR=""
BUILD_ONLY=false
CORE_ONLY=false
while [ $# -gt 0 ]; do
    case "$1" in
        --source)   SOURCE_DIR="$2"; shift 2 ;;
        --source=*) SOURCE_DIR="${1#*=}"; shift ;;
        --build-only) BUILD_ONLY=true; shift ;;
        --core-only) CORE_ONLY=true; shift ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done
if [ -z "$SOURCE_DIR" ]; then
    SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
if [ ! -d "$SOURCE_DIR" ]; then
    echo "Error: source directory not found: $SOURCE_DIR" >&2
    exit 1
fi
SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd)"

echo "am-secrets Installation"
echo "============================"
echo

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Check for required tools
check_requirements() {
    echo "Checking requirements..."

    # Swift
    if ! command -v swift &> /dev/null; then
        echo -e "${RED}Error: Swift not found. Install Xcode Command Line Tools:${NC}"
        echo "  xcode-select --install"
        exit 1
    fi
    echo -e "  Swift:  ${GREEN}OK${NC} ($(swift --version 2>&1 | head -1))"

    # Rust
    if ! command -v cargo &> /dev/null; then
        if [ -f "$HOME/.cargo/env" ]; then
            source "$HOME/.cargo/env"
        fi
    fi

    if ! command -v cargo &> /dev/null; then
        echo -e "${YELLOW}Warning: Rust not found. Installing...${NC}"
        echo "Install Rust, then rerun this installer." >&2
        exit 1

    fi
    echo -e "  Rust:   ${GREEN}OK${NC} ($(rustc --version))"

    # codesign
    if ! command -v codesign &> /dev/null; then
        echo -e "${RED}Error: codesign not found${NC}"
        exit 1
    fi
    echo -e "  codesign: ${GREEN}OK${NC}"

    # nc (netcat) - used for daemon verification
    if ! command -v nc &> /dev/null; then
        echo -e "${YELLOW}Warning: nc (netcat) not found. Daemon verification will be skipped.${NC}"
        NC_AVAILABLE=false
    else
        NC_AVAILABLE=true
        echo -e "  nc:       ${GREEN}OK${NC}"
    fi

    echo
}

# Install the secret matcher (resident process + hooks)
install_matcher() {
    echo "Installing secret matcher..."

    if [ ! -d "$SOURCE_DIR/matcher" ]; then
        echo -e "  ${YELLOW}SKIPPED: $SOURCE_DIR/matcher not found${NC}"
        echo
        return 0
    fi

    mkdir -p "$SECRETS_DIR/matcher"
    for file in secret-matcher.py secret-guard.py secret-postguard.py matcher-start.sh; do
        cp "$SOURCE_DIR/matcher/$file" "$SECRETS_DIR/matcher/$file"
        chmod 755 "$SECRETS_DIR/matcher/$file"
    done

    # guard.conf правится руками, поэтому создаём только если его ещё нет
    if [ ! -f "$SECRETS_DIR/guard.conf" ]; then
        cp "$SOURCE_DIR/matcher/guard.conf.example" "$SECRETS_DIR/guard.conf"
        echo -e "  created ${GREEN}$SECRETS_DIR/guard.conf${NC}"
    else
        echo -e "  kept existing ${GREEN}$SECRETS_DIR/guard.conf${NC}"
    fi

    echo -e "  ${GREEN}Installed to $SECRETS_DIR/matcher${NC}"
    echo -e "  Start it with: $SECRETS_DIR/matcher/matcher-start.sh"
    echo
}

# Report what exactly is about to be installed
report_source() {
    echo "Source: $SOURCE_DIR"

    if [ -d "$SOURCE_DIR/.git" ]; then
        local rev
        rev=$(git -C "$SOURCE_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
        local branch
        branch=$(git -C "$SOURCE_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
        echo "  Revision: $rev ($branch)"

        if [ -n "$(git -C "$SOURCE_DIR" status --porcelain -- secrets-cli secrets-daemon install.sh 2>/dev/null)" ]; then
            echo -e "  ${YELLOW}WARNING: uncommitted changes in build sources — installing a dirty tree${NC}"
            git -C "$SOURCE_DIR" status --short -- secrets-cli secrets-daemon install.sh | sed 's/^/    /'
        fi
    else
        echo -e "  ${YELLOW}WARNING: not a git checkout. Installing whatever is in this directory.${NC}"
        echo -e "  ${YELLOW}If this is $SECRETS_DIR, the sources there may be stale.${NC}"
    fi

    if [ ! -d "$SOURCE_DIR/secrets-cli" ] || [ ! -d "$SOURCE_DIR/secrets-daemon" ]; then
        echo -e "${RED}Error: $SOURCE_DIR does not contain secrets-cli/ and secrets-daemon/${NC}" >&2
        echo "  Run from the repository, or pass: install.sh --source /path/to/checkout" >&2
        exit 1
    fi

    echo
}

# Stop existing daemon
stop_daemon() {
    echo "Stopping existing daemon (if any)..."
    launchctl unload "$LAUNCH_AGENTS/$PLIST_NAME" 2>/dev/null || true

    # Remove old socket
    rm -f "$SECRETS_DIR/daemon.sock"

    echo -e "  ${GREEN}Done${NC}"
    echo
}

# Build Swift daemon
build_daemon() {
    echo "Building Swift daemon..."
    cd "$SOURCE_DIR/secrets-daemon"

    swift build -c release -Xswiftc -O

    if [ ! -f ".build/release/secrets-daemon" ]; then
        echo -e "${RED}Error: Daemon build failed${NC}"
        exit 1
    fi

    echo -e "  ${GREEN}Build successful${NC}"
    echo
}

# Build Rust CLI
build_cli() {
    echo "Building Rust CLI..."

    # Ensure cargo is in PATH
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi

    cd "$SOURCE_DIR/secrets-cli"

    cargo build --release --locked

    if [ ! -f "target/release/secrets" ]; then
        echo -e "${RED}Error: CLI build failed${NC}"
        exit 1
    fi

    echo -e "  ${GREEN}Build successful${NC}"
    echo
}

# Sign binaries
sign_binaries() {
    echo "Signing binaries (ad-hoc)..."

    # Sign daemon
    codesign -s - --force "$SOURCE_DIR/secrets-daemon/.build/release/secrets-daemon" 2>/dev/null
    echo -e "  Daemon: ${GREEN}Signed${NC}"

    # Sign CLI
    codesign -s - --force "$SOURCE_DIR/secrets-cli/target/release/secrets" 2>/dev/null
    echo -e "  CLI:    ${GREEN}Signed${NC}"

    echo
}

# Install binaries
install_binaries() {
    echo "Installing binaries..."

    mkdir -p "$SECRETS_DIR"
    chmod 700 "$SECRETS_DIR"
    local snapshot
    snapshot=$(mktemp -d "$SECRETS_DIR/backup-install-$(date +%Y%m%d-%H%M%S)-XXXXXX")
    for name in secrets secrets-daemon-bin trusted_hashes; do
        if [ -f "$SECRETS_DIR/$name" ]; then cp -p "$SECRETS_DIR/$name" "$snapshot/$name"; fi
    done
    if [ -f "$LAUNCH_AGENTS/$PLIST_NAME" ]; then cp -p "$LAUNCH_AGENTS/$PLIST_NAME" "$snapshot/$PLIST_NAME"; fi
    if [ -f "$ZSHRC" ]; then cp -p "$ZSHRC" "$snapshot/zshrc"; fi
    echo "  Rollback files: $snapshot"
    install -m 755 "$SOURCE_DIR/secrets-daemon/.build/release/secrets-daemon" "$SECRETS_DIR/.daemon-new"
    install -m 755 "$SOURCE_DIR/secrets-cli/target/release/secrets" "$SECRETS_DIR/.cli-new"
    mv -f "$SECRETS_DIR/.daemon-new" "$SECRETS_DIR/secrets-daemon-bin"
    mv -f "$SECRETS_DIR/.cli-new" "$SECRETS_DIR/secrets"

    # Remove quarantine attribute (prevents macOS from blocking ad-hoc signed binaries)
    xattr -d com.apple.quarantine "$SECRETS_DIR/secrets-daemon-bin" 2>/dev/null || true
    xattr -d com.apple.quarantine "$SECRETS_DIR/secrets" 2>/dev/null || true

    echo -e "  ${GREEN}Installed to $SECRETS_DIR${NC}"
    echo
}

# Get CDHash of a binary
get_cdhash() {
    codesign -dvvv "$1" 2>&1 | grep "CDHash=" | head -1 | cut -d= -f2
}

# Update trusted hashes
update_whitelist() {
    echo "Updating trusted_hashes..."

    HASHES_FILE="$SECRETS_DIR/trusted_hashes"
    CLI_HASH=$(get_cdhash "$SECRETS_DIR/secrets")

    if [ -z "$CLI_HASH" ]; then
        echo -e "  ${RED}Could not get CDHash${NC}"
        return 1
    fi

    # Create or update file
    if [ ! -f "$HASHES_FILE" ]; then
        echo "# Trusted CDHashes for am-secrets" > "$HASHES_FILE"
        echo "# Format: cdhash comment" >> "$HASHES_FILE"
    fi

    # Check if hash already exists
    if grep -q "$CLI_HASH" "$HASHES_FILE" 2>/dev/null; then
        echo -e "  CDHash already in whitelist"
    else
        echo "$CLI_HASH $("$SECRETS_DIR/secrets" --version) ($(date +%Y-%m-%d))" >> "$HASHES_FILE"
        echo -e "  Added: ${GREEN}$CLI_HASH${NC}"
    fi

    chmod 600 "$HASHES_FILE"
    echo
}

# Create launchd plist
create_launchd_plist() {
    echo "Creating launchd configuration..."

    mkdir -p "$LAUNCH_AGENTS"
    mkdir -p "$SECRETS_DIR/logs"

    cat > "$LAUNCH_AGENTS/$PLIST_NAME" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ai-secrets.daemon</string>

    <key>ProgramArguments</key>
    <array>
        <string>$SECRETS_DIR/secrets-daemon-bin</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>StandardOutPath</key>
    <string>$SECRETS_DIR/logs/daemon.log</string>

    <key>StandardErrorPath</key>
    <string>$SECRETS_DIR/logs/daemon.error.log</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>SECRETS_SOCKET</key>
        <string>$SECRETS_DIR/daemon.sock</string>
    </dict>

    <key>ProcessType</key>
    <string>Background</string>

    <key>LowPriorityBackgroundIO</key>
    <true/>
</dict>
</plist>
EOF

    echo -e "  Created: ${GREEN}$LAUNCH_AGENTS/$PLIST_NAME${NC}"
    echo
}

# Start daemon
start_daemon() {
    echo "Starting daemon..."

    launchctl load "$LAUNCH_AGENTS/$PLIST_NAME"

    # Wait for daemon to start
    sleep 1

    # Check if running
    if launchctl list | grep -q "ai-secrets"; then
        echo -e "  ${GREEN}Daemon started${NC}"
    else
        echo -e "  ${YELLOW}Daemon may not have started. Check logs:${NC}"
        echo "    tail -f $SECRETS_DIR/logs/daemon.log"
    fi
    echo
}

# Verify installation
verify_installation() {
    echo "Verifying installation..."

    # Test PING (only if nc is available)
    if [ "$NC_AVAILABLE" = true ]; then
        RESPONSE=""
        for attempt in {1..20}; do
            RESPONSE=$(echo '{"v":2,"cmd":"PING"}' | nc -w 2 -U "$SECRETS_DIR/daemon.sock" 2>/dev/null || true)
            if echo "$RESPONSE" | grep -q '"status":"alive"'; then break; fi
            sleep 0.25
        done

        if echo "$RESPONSE" | grep -q '"status":"alive"'; then
            echo -e "  Daemon PING: ${GREEN}OK${NC}"
        else
            echo -e "  Daemon PING: ${RED}FAILED${NC}"
            return 1
        fi
    else
        echo -e "  Daemon PING: ${YELLOW}SKIPPED${NC} (nc not available)"
    fi

    # Check CLI
    if "$SECRETS_DIR/secrets" --version &>/dev/null; then
        echo -e "  CLI:         ${GREEN}OK${NC}"
    else
        echo -e "  CLI:         ${RED}FAILED${NC}"
        return 1
    fi

    echo
}

# Add shell integration to ~/.zshrc
add_shell_integration() {
    local rc="$ZSHRC" target hops=0 temp source_file
    echo "Configuring shell integration..."

    if [ -L "$rc" ] && [ ! -f "$rc" ]; then
        echo "Error: invalid shell configuration link: $rc" >&2
        return 1
    fi
    while [ -L "$rc" ]; do
        if [ "$hops" -ge 40 ]; then
            echo "Error: too many shell configuration links: $ZSHRC" >&2
            return 1
        fi
        target=$(readlink "$rc") || return 1
        case "$target" in
            /*) rc="$target" ;;
            *) rc="$(dirname "$rc")/$target" ;;
        esac
        hops=$((hops + 1))
    done

    temp=$(mktemp "$rc.am-secrets-XXXXXX") || return 1
    source_file=/dev/null
    if [ -e "$rc" ]; then
        if [ ! -f "$rc" ] || ! cp -p "$rc" "$temp"; then
            rm -f "$temp"
            return 1
        fi
        source_file="$rc"
    fi
    if ! awk '
        function write_path() {
            print "# >>> ai-secrets >>>"
            print "export PATH=\"$HOME/.secrets:$PATH\""
            print "# <<< ai-secrets <<<"
            written = 1
        }
        $0 ~ /^# >>> ai-secrets >>>\r?$/ {
            if (inside) invalid = 1
            inside = 1
            next
        }
        $0 ~ /^# <<< ai-secrets <<<\r?$/ {
            if (!inside) invalid = 1
            if (!written) write_path()
            inside = 0
            next
        }
        !inside { print }
        END {
            if (invalid || inside) exit 1
            if (!written) write_path()
        }
    ' "$source_file" > "$temp"; then
        rm -f "$temp"
        echo "Error: could not update $ZSHRC. Check the am-secrets shell markers." >&2
        return 1
    fi
    if ! mv -f "$temp" "$rc"; then
        rm -f "$temp"
        return 1
    fi
    echo "  Updated $ZSHRC"
    echo
}

# Run setup if first time
run_setup_if_needed() {
    if [ ! -f "$SECRETS_DIR/config.yaml" ]; then
        echo "=============================="
        echo "First-time setup"
        echo "=============================="
        echo
        "$SECRETS_DIR/secrets" setup
        return $?
    else
        echo -e "${YELLOW}Config already exists. Skipping setup.${NC}"
        echo "  Run 'secrets unlock' in your terminal to open the existing vault and retire its PIN."
        echo
    fi
}

# Print summary
print_summary() {
    echo "=============================="
    echo -e "${GREEN}Installation complete!${NC}"
    echo "=============================="
    echo
    echo "Binaries installed to:"
    echo "  $SECRETS_DIR/secrets-daemon-bin"
    echo "  $SECRETS_DIR/secrets"
    echo
    echo -e "${YELLOW}Restart terminal or run:${NC} source ~/.zshrc"
    echo
    echo "Usage:"
    echo "  secrets status              # Check system health"
    echo "  secrets add \"item\" \"field\"  # Add secret from provider"
    echo "  secrets get \"item\" \"field\"  # Get secret value"
    echo
}

# Main installation flow
main() {
    check_requirements
    report_source
    build_daemon
    build_cli
    sign_binaries
    if [ "$BUILD_ONLY" = true ]; then echo "Build verified; installation unchanged."; return 0; fi
    stop_daemon
    install_binaries
    if [ "$CORE_ONLY" = false ]; then install_matcher; fi
    update_whitelist
    create_launchd_plist
    start_daemon
    verify_installation
    if [ "$CORE_ONLY" = false ]; then add_shell_integration; fi
    run_setup_if_needed
    print_summary
}

# Run main
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi

#!/usr/bin/env bash

# ===============================
# Post-Install Setup Script
# Runs on first boot as the target user
# NOTE: No 'set -e' — individual steps handle their own errors
# so a single failure doesn't kill the entire unattended setup
# ===============================

LOGFILE="/var/log/post-install.log"
exec > >(sudo tee -a "$LOGFILE") 2>&1
echo "=== Post-install started at $(date) ==="
echo "=== Running as user: $(whoami) ==="

DRY_RUN=false
if [[ "$1" == "--dry-run" ]]; then
  DRY_RUN=true
  echo "=== DRY RUN MODE ENABLED: No changes will be made ==="
fi

run_cmd() {
  if [ "$DRY_RUN" = true ]; then
    echo "[DRY RUN] $*"
  else
    eval "$@"
  fi
}

# -------------------------------
# 1) Base dependencies
# -------------------------------
echo "=== Installing base packages ==="
run_cmd "sudo apt update"
run_cmd "sudo apt install -y zsh git curl wget gnupg ca-certificates software-properties-common open-vm-tools open-vm-tools-desktop openssh-server"

# -------------------------------
# 2) Set zsh as default shell
# -------------------------------
echo "=== Setting Zsh as default shell ==="
if ! getent passwd "$(whoami)" | grep -q '/usr/bin/zsh'; then
  run_cmd "sudo usermod -s /usr/bin/zsh $(whoami)"
fi

# -------------------------------
# 3) Oh-My-Zsh
# -------------------------------
OH_MY_ZSH_DIR="$HOME/.oh-my-zsh"
if [ ! -d "$OH_MY_ZSH_DIR" ]; then
  echo "=== Installing Oh-My-Zsh ==="
  export RUNZSH=no CHSH=no KEEP_ZSHRC=yes
  run_cmd "sh -c \"\$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)\""
else
  echo "=== Oh-My-Zsh already installed, skipping ==="
fi

# -------------------------------
# 4) Powerlevel10k
# -------------------------------
P10K_DIR="${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k"
if [ ! -d "$P10K_DIR" ]; then
  echo "=== Installing Powerlevel10k theme ==="
  run_cmd "git clone --depth=1 https://github.com/romkatv/powerlevel10k.git \"$P10K_DIR\""
else
  echo "=== Powerlevel10k already installed, skipping ==="
fi

# -------------------------------
# 5) Zsh plugins
# -------------------------------
PLUGIN_DIR="${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/plugins"
for plugin in zsh-autosuggestions zsh-syntax-highlighting; do
  if [ ! -d "$PLUGIN_DIR/$plugin" ]; then
    echo "=== Installing plugin: $plugin ==="
    run_cmd "git clone https://github.com/zsh-users/$plugin \"$PLUGIN_DIR/$plugin\""
  else
    echo "=== Plugin $plugin already exists, skipping ==="
  fi
done

# -------------------------------
# 6) Powerlevel10k config
# -------------------------------
P10K_FILE="$HOME/.p10k.zsh"
# If a pre-built config was placed by the installer, use it
if [ -f /opt/post-install/p10k-config.zsh ] && [ ! -f "$P10K_FILE" ]; then
  echo "=== Copying Powerlevel10k config ==="
  cp /opt/post-install/p10k-config.zsh "$P10K_FILE"
elif [ ! -f "$P10K_FILE" ]; then
  echo "=== Writing Powerlevel10k config placeholder ==="
  cat > "$P10K_FILE" <<'EOFP10K'
# ============================================================
# POWERLEVEL10K CONFIG PLACEHOLDER
# Run 'p10k configure' to generate your own config
# ============================================================
EOFP10K
else
  echo "=== Powerlevel10k config already exists, skipping ==="
fi

# -------------------------------
# 7) .zshrc
# -------------------------------
ZSHRC_FILE="$HOME/.zshrc"
if [ ! -f "$ZSHRC_FILE" ]; then
  echo "=== Writing .zshrc ==="
  cat > "$ZSHRC_FILE" <<'EOFZSHRC'
export POWERLEVEL9K_DISABLE_CONFIGURATION_WIZARD=true
if [[ -r "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh" ]]; then
  source "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh"
fi
export ZSH="$HOME/.oh-my-zsh"
ZSH_THEME="powerlevel10k/powerlevel10k"
plugins=(
  git
  zsh-autosuggestions
  zsh-syntax-highlighting
)
source $ZSH/oh-my-zsh.sh
[[ -f ~/.p10k.zsh ]] && source ~/.p10k.zsh
EOFZSHRC
else
  echo "=== .zshrc already exists, skipping ==="
fi

# -------------------------------
# 8) Meslo Nerd Font
# -------------------------------
FONT_DIR="$HOME/.local/share/fonts"
mkdir -p "$FONT_DIR"
for f in "MesloLGS NF Regular.ttf" "MesloLGS NF Bold.ttf" "MesloLGS NF Italic.ttf" "MesloLGS NF Bold Italic.ttf"; do
  if [ ! -f "$FONT_DIR/$f" ]; then
    echo "=== Installing font $f ==="
    run_cmd "wget -q -O \"$FONT_DIR/$f\" \"https://github.com/romkatv/powerlevel10k-media/raw/master/$f\""
  else
    echo "=== Font $f already exists, skipping ==="
  fi
done
run_cmd "fc-cache -f"

# -------------------------------
# 9) Auto-set GNOME Terminal font (safe)
# -------------------------------
if command -v gsettings >/dev/null && [ -n "$DISPLAY" ]; then
  PROFILE_ID=$(gsettings get org.gnome.Terminal.ProfilesList default 2>/dev/null | tr -d "'") || true
  if [ -n "$PROFILE_ID" ]; then
    PROFILE_PATH="org.gnome.Terminal.Legacy.Profile:/org/gnome/terminal/legacy/profiles:/:$PROFILE_ID/"
    echo "=== Setting GNOME Terminal font to MesloLGS NF Regular 11 ==="
    run_cmd "gsettings set \"$PROFILE_PATH\" use-system-font false"
    run_cmd "gsettings set \"$PROFILE_PATH\" font 'MesloLGS NF Regular 11'"
  fi
fi

# -------------------------------
# 10) Antigravity
# -------------------------------
if ! command -v antigravity >/dev/null; then
  echo "=== Installing Antigravity ==="
  run_cmd "sudo mkdir -p /etc/apt/keyrings"
  run_cmd "curl -fsSL https://us-central1-apt.pkg.dev/doc/repo-signing-key.gpg | sudo gpg --dearmor --yes -o /etc/apt/keyrings/antigravity-repo-key.gpg"
  run_cmd "echo 'deb [signed-by=/etc/apt/keyrings/antigravity-repo-key.gpg] https://us-central1-apt.pkg.dev/projects/antigravity-auto-updater-dev/ antigravity-debian main' | sudo tee /etc/apt/sources.list.d/antigravity.list > /dev/null"
  run_cmd "sudo apt update"
  run_cmd "sudo apt install -y antigravity"
else
  echo "=== Antigravity already installed, skipping ==="
fi

# -------------------------------
# 11) VS Code
# -------------------------------
if ! command -v code >/dev/null; then
  echo "=== Installing VS Code ==="
  run_cmd "wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > /tmp/packages.microsoft.gpg"
  run_cmd "sudo install -o root -g root -m 644 /tmp/packages.microsoft.gpg /usr/share/keyrings/"
  run_cmd "sudo sh -c 'echo \"deb [arch=amd64 signed-by=/usr/share/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main\" > /etc/apt/sources.list.d/vscode.list'"
  run_cmd "sudo apt update"
  run_cmd "sudo apt install -y code"
  run_cmd "rm -f /tmp/packages.microsoft.gpg"
else
  echo "=== VS Code already installed, skipping ==="
fi

# -------------------------------
# 12) Claude CLI
# -------------------------------
if ! command -v claude >/dev/null; then
  echo "=== Installing Claude CLI ==="
  run_cmd "curl -fsSL https://claude.ai/install.sh | bash"
else
  echo "=== Claude CLI already installed, skipping ==="
fi

# -------------------------------
# 13) Google Chrome
# -------------------------------
if ! command -v google-chrome >/dev/null; then
  echo "=== Installing Google Chrome ==="
  run_cmd "wget -q -O /tmp/google-chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
  run_cmd "sudo apt install -y /tmp/google-chrome.deb"
  run_cmd "rm -f /tmp/google-chrome.deb"
else
  echo "=== Google Chrome already installed, skipping ==="
fi

# -------------------------------
# Cleanup: Remove firstboot service & temp sudoers
# -------------------------------
echo "=== Removing firstboot service ==="
sudo systemctl disable post-install-firstboot.service 2>/dev/null || true
sudo rm -f /etc/systemd/system/post-install-firstboot.service
sudo rm -f /etc/sudoers.d/post-install-nopasswd

echo "=============================="
echo "=== Setup complete at $(date) ==="
echo "=============================="

#!/usr/bin/env bash
# Mint a Claude subscription OAuth token and write it to .env.
#
# Walks you through:
#   1. installing the `claude` CLI if it's not on PATH
#   2. running `claude setup-token` (interactive — opens a browser)
#   3. pasting the printed token, which then gets written to .env as
#      CLAUDE_CODE_OAUTH_TOKEN (replacing any existing value).
#
# Usage:  ./scripts/setup-claude-token.sh           # writes to ./.env
#         ./scripts/setup-claude-token.sh path/to/.env
set -euo pipefail

ENV_FILE="${1:-.env}"

# 1. Make sure the `claude` CLI is available.
if ! command -v claude >/dev/null 2>&1; then
    cat <<EOF
The 'claude' CLI is required to mint a subscription token but isn't on PATH.

Install it with one of:

  curl -fsSL https://claude.ai/install.sh | bash      # official installer
  brew install --cask claude-code                      # Homebrew

Re-run this script once 'claude' is on your PATH.
EOF
    exit 1
fi

echo "Running 'claude setup-token' — your browser will open for OAuth."
echo "When the command finishes, copy the token it prints (starts with sk-ant-oat-)."
echo
claude setup-token || {
    echo
    echo "claude setup-token failed. Aborting." >&2
    exit 1
}

echo
read -r -p "Paste the token here: " TOKEN
TOKEN="${TOKEN// /}"  # strip stray spaces
if [ -z "$TOKEN" ]; then
    echo "No token provided. Aborting." >&2
    exit 1
fi

# 2. Write/update the token in $ENV_FILE.
if [ ! -f "$ENV_FILE" ]; then
    touch "$ENV_FILE"
fi

if grep -q "^CLAUDE_CODE_OAUTH_TOKEN=" "$ENV_FILE"; then
    # macOS sed needs an empty -i suffix; GNU sed doesn't.
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s|^CLAUDE_CODE_OAUTH_TOKEN=.*|CLAUDE_CODE_OAUTH_TOKEN=$TOKEN|" "$ENV_FILE"
    else
        sed -i "s|^CLAUDE_CODE_OAUTH_TOKEN=.*|CLAUDE_CODE_OAUTH_TOKEN=$TOKEN|" "$ENV_FILE"
    fi
    echo "Updated CLAUDE_CODE_OAUTH_TOKEN in $ENV_FILE"
else
    printf "\nCLAUDE_CODE_OAUTH_TOKEN=%s\n" "$TOKEN" >> "$ENV_FILE"
    echo "Wrote CLAUDE_CODE_OAUTH_TOKEN to $ENV_FILE"
fi

echo "Done. You can now run 'familiar-claude'."

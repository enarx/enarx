#!/bin/sh
# This script allows users to easily opt-in to git hooks.
set -e

if [ -f ".git/hooks/pre-push" ]; then
    echo "It looks like a pre-push hook is already installed."
    read -e -p "Would you like to delete it? [y/N] " choice
    [[ "$choice" == [Yy]* ]] || exit 0
    echo "Removing hook"
    rm .git/hooks/pre-push
else
    echo "This will install a pre-push Git hook for cargo fmt/clippy (read-only checks)."
    echo "This will prevent you from pushing if either fail (but can be bypassed with --no-verify)."
    read -e -p "Would you like to install it? [y/N] " choice
    [[ "$choice" == [Yy]* ]] || exit 0
    echo "Installing hook"
    cp .git-hooks/pre-push .git/hooks/
fi

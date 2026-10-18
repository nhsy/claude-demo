#!/bin/bash
# Scaffold for eval cases: copy saved vault-posture results into the run's working directory
# (the agent's cwd), where the skill looks for "the last review".
# Usage: stage.sh [fixture-dir]  (default: the shared fixtures/vault-posture/ set).
set -euo pipefail

src="${1:-$(cd "$(dirname "$(realpath "${BASH_SOURCE[0]}")")" && pwd)/vault-posture}"
mkdir -p .tmp/vault-posture
cp "$src"/*.json .tmp/vault-posture/
echo '*' >.tmp/vault-posture/.gitignore

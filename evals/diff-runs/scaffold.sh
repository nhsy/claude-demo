#!/bin/bash
# Stage this case's own fixtures/: two audit runs of one cluster, before and after a round of changes (generate-root cancelled, break-glass JWT role deleted, a new any-pod Kubernetes role, the "warning" CA re-issued under the same name).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$here/../fixtures/stage.sh" "$here/fixtures"

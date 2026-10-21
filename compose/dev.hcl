# Extra configuration for the compose.yaml dev servers (dev mode supplies storage and the listener).
plugin_directory = "/vault/plugins"

# VP-CFG-002/003: a long lease ceiling and a second loopback listener serving metrics without a
# token (8201 is the dev cluster port). Loopback inside the container, so it isn't published.
max_lease_ttl = "8760h"
listener "tcp" {
  address = "127.0.0.1:8202"
  tls_disable = true
  telemetry {
    unauthenticated_metrics_access = true
  }
}

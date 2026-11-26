#!/bin/sh
# Runs draugr with the arguments the container was given. Before a scan, it brings the KEV, EPSS
# and Go vulnerability feeds up to date: a container built from this recipe starts with none, and
# a scan without them ranks findings with no word on which are exploited. A copy fetched in the
# last 24 hours is kept, so a volume on /opt/draugr/feeds makes this a quick check.
#
# A scan asked to stay offline fetches nothing, and runs on what the volume holds.
set -eu

if [ "${1:-}" = scan ]; then
  offline=${DRAUGR_OFFLINE:-}
  for arg in "$@"; do
    case "$arg" in --offline | --offline=true) offline=1 ;; esac
  done
  case "$offline" in
    "" | 0 | false) draugr feeds update ;;
  esac
fi

exec draugr "$@"

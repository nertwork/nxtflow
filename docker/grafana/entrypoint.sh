#!/bin/sh
set -eu

SRC_DASH="/etc/grafana/dashboards-src/nxtflow-overview.json"
DST_DIR="/var/lib/grafana/dashboards"
DST_DASH="${DST_DIR}/nxtflow-overview.json"
JOB_NAME="${NXTFLOW_JOB:-nxtflow}"

mkdir -p "${DST_DIR}"

if [ -f "${SRC_DASH}" ]; then
  ESCAPED_JOB="$(printf '%s' "${JOB_NAME}" | sed 's/[\/&"]/\\&/g')"
  sed \
    -e 's/\${DS_LOKI}/loki/g' \
    -e 's/\${DS_PROMETHEUS}/prometheus/g' \
    -e 's/job=\\"nxtflow\\"/job=\\"'"${ESCAPED_JOB}"'\\"/g' \
    "${SRC_DASH}" > "${DST_DASH}.tmp"
  mv "${DST_DASH}.tmp" "${DST_DASH}"
fi

exec /run.sh "$@"

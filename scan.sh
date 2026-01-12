#!/bin/bash

# --- Hardened / Strict Mode ---
set -Eeuo pipefail

# Limit PATH to prevent PATH-hijacking, keeping docker/ssh/trivy available
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOSTS_FILE="$SCRIPT_DIR/hosts.txt"
TEMPLATE_FILE="$SCRIPT_DIR/html.tpl"
REPORT_DIR="$SCRIPT_DIR/trivy_reports"
INDEX_FILE="$REPORT_DIR/index.html"

# --- Validation ---
if ! command -v jq >/dev/null 2>&1; then
  echo "❌ ERROR: 'jq' missing (apt/dnf install jq)." >&2
  exit 1
fi
if [ ! -f "$TEMPLATE_FILE" ]; then
  echo "❌ ERROR: unable to find 'html.tpl' in $SCRIPT_DIR" >&2
  exit 1
fi
if [ ! -f "$HOSTS_FILE" ]; then
  echo "❌ ERROR: unable to find 'hosts.txt' in $SCRIPT_DIR" >&2
  exit 1
fi

mkdir -p "$REPORT_DIR"
# cleanup only in own folder
find "$REPORT_DIR" -maxdepth 1 -type f -name "*.html" -delete
find "$REPORT_DIR" -maxdepth 1 -type f -name "*.json" -delete

# --- HTML header ---
cat > "$INDEX_FILE" <<EOF
<!DOCTYPE html>
<html lang="nl">
<head>
  <meta charset="UTF-8">
  <title>Docker Security Audit</title>
  <style>
    body { font-family: -apple-system, system-ui, sans-serif; margin: 40px; background: #f4f6f8; color: #333; }
    .container { max-width: 1500px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
    h1 { color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 10px; }
    section.server-block { margin-bottom: 25px; border:1px solid #ddd; border-radius:6px; background:#fff; }
    summary { cursor:pointer; padding:10px 15px; display:flex; align-items:center; justify-content:space-between; }
    summary::-webkit-details-marker { display:none; }
    summary::marker { content: ""; }
    tr:hover { background: #f1f3f5; }

    .badge { padding: 3px 8px; border-radius: 10px; font-size: 0.8em; font-weight: bold; color: white; margin-right: 4px; }
    .crit { background-color: #dc3545; }
    .high { background-color: #fd7e14; }
    .safe { background-color: #28a745; }

    .cont-tag { font-family: monospace; background: #e2e3e5; padding: 3px 6px; border-radius: 4px; color: #383d41; font-size: 0.95em; }
    .cont-none { color: #aaa; font-style: italic; background: none; }

    .age-tag { font-weight: bold; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; }
    .age-fresh { color: #155724; background-color: #d4edda; }
    .age-med { color: #856404; background-color: #fff3cd; }
    .age-old { color: #fff; background-color: #fd7e14; }
    .age-ancient { color: #fff; background-color: #dc3545; }

    .server-tag { font-family: monospace; padding: 4px 8px; border-radius: 4px; color: #fff; font-size: 0.9em; font-weight: bold; text-shadow: 0 1px 1px rgba(0,0,0,0.2); }
    .srv-color-0 { background-color: #007bff; }
    .srv-color-1 { background-color: #6610f2; }
    .srv-color-2 { background-color: #6f42c1; }
    .srv-color-3 { background-color: #e83e8c; }
    .srv-color-4 { background-color: #fd7e14; }
    .srv-color-5 { background-color: #20c997; }
    .srv-color-6 { background-color: #17a2b8; }
    .srv-color-7 { background-color: #6c757d; }
    .srv-color-8 { background-color: #343a40; }
    .srv-color-9 { background-color: #28a745; }

    .status-tag { font-size: 0.8em; text-transform: uppercase; padding: 2px 5px; border-radius: 3px; }
    .active { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
    .inactive { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ Docker Security Audit</h1>
    <div style="color:#666; margin-bottom:20px;">Scanned: $(date)</div>
EOF

# --- Support functions ---

calculate_days_old() {
  local created_ts created_sec now_sec
  created_ts=$(echo "$1" | cut -d'T' -f1)
  if [[ -z "$created_ts" || "$created_ts" == "null" ]]; then
    echo "-1"; return
  fi
  if ! created_sec=$(date -d "$created_ts" +%s 2>/dev/null); then
    if ! created_sec=$(date -j -f "%Y-%m-%d" "$created_ts" +%s 2>/dev/null); then
      echo "-1"; return
    fi
  fi
  now_sec=$(date +%s)
  echo $(( (now_sec - created_sec) / 86400 ))
}

get_server_color_class() {
  local srv_name="$1"
  local sum=0 i char val
  for (( i=0; i<${#srv_name}; i++ )); do
    char="${srv_name:$i:1}"
    val=$(printf '%d' "'$char")
    sum=$(( sum + val ))
  done
  local color_id=$(( sum % 10 ))
  echo "srv-color-$color_id"
}

add_row_for_image() {
  local server="$1"
  local image="$2"
  local container_name="$3"
  local status="$4"
  local json_path="$5"
  local html_link="$6"
  local days_old="$7"

  local crit high badges age_html cont_html stat_cls full_report_path

  crit=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "$json_path")
  high=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' "$json_path")
  [[ -z "$crit" || "$crit" == "null" ]] && crit=0
  [[ -z "$high" || "$high" == "null" ]] && high=0

  if [ "$crit" -eq 0 ] && [ "$high" -eq 0 ]; then
    SAFE_IMAGES=$((SAFE_IMAGES+1))
  else
    UNSAFE_IMAGES=$((UNSAFE_IMAGES+1))
  fi
  TOTAL_IMAGES=$((TOTAL_IMAGES+1))

  full_report_path="$REPORT_DIR/$html_link"
  if [ -f "$full_report_path" ]; then
    local btn
    btn='<div style="position:fixed; top:20px; right:20px; z-index:9999;"><a href="index.html" style="background:#007bff; color:white; padding:10px 15px; text-decoration:none; border-radius:5px; font-family:sans-serif; font-weight:bold; box-shadow:0 2px 5px rgba(0,0,0,0.2);">Back to Dashboard</a></div>'
    if sed --version >/dev/null 2>&1; then
      sed -i "s|<body[^>]*>|& $btn|" "$full_report_path"
    else
      sed -i '' "s|<body[^>]*>|& $btn|" "$full_report_path"
    fi
  fi

  badges=""
  if [ "$crit" -gt 0 ]; then badges="$badges<span class=\"badge crit\">CRIT: $crit</span>"; fi
  if [ "$high" -gt 0 ]; then badges="$badges<span class=\"badge high\">HIGH: $high</span>"; fi
  if [ -z "$badges" ]; then badges="<span class=\"badge safe\">Safe</span>"; fi

  age_html="<span style=\"color:#999\">?</span>"
  if [ "$days_old" -ne "-1" ]; then
    local a_cls="age-fresh"
    if [ "$days_old" -gt 180 ]; then a_cls="age-ancient"
    elif [ "$days_old" -gt 90 ]; then a_cls="age-old"
    elif [ "$days_old" -gt 30 ]; then a_cls="age-med"; fi
    age_html="<span class=\"age-tag $a_cls\">$days_old dagen</span>"
  fi

  cont_html="<span class=\"cont-tag\">$container_name</span>"
  if [ "$container_name" == "-" ]; then
    cont_html="<span class=\"cont-tag cont-none\">Geen (Unused)</span>"
  fi

  stat_cls="inactive"
  if [ "$status" == "Active" ]; then stat_cls="active"; fi

  SERVER_ROWS+=$'<tr>\n'
  SERVER_ROWS+="  <td><span class=\"status-tag $stat_cls\">$status</span></td>"
  SERVER_ROWS+="  <td>$cont_html</td>"
  SERVER_ROWS+="  <td><strong>$image</strong></td>"
  SERVER_ROWS+="  <td>$age_html</td>"
  SERVER_ROWS+="  <td>$badges</td>"
  SERVER_ROWS+="  <td><a href=\"$html_link\" target=\"_self\">Open Report</a></td>"
  SERVER_ROWS+=$'\n</tr>\n'
}

# --- Host loop ---
while IFS= read -r SERVER || [ -n "$SERVER" ]; do
  [[ "$SERVER" =~ ^#.*$ ]] && continue
  [[ -z "$SERVER" ]] && continue
  SERVER=$(echo "$SERVER" | xargs)
  [ -z "$SERVER" ] && continue

  echo "Host: $SERVER" >&2

  SCANNED_ON_THIS_HOST=""
  IS_LOCAL="false"
  TOTAL_IMAGES=0
  SAFE_IMAGES=0
  UNSAFE_IMAGES=0
  SERVER_ROWS=""

  REMOTE_TMP_TPL="/tmp/trivy_html_$(date +%s)_$RANDOM.tpl"

  if [ "$SERVER" = "localhost" ]; then
    IS_LOCAL="true"
    trivy image --download-db-only >/dev/null 2>&1 || true
  else
    if ! ssh -n -o BatchMode=yes -o ConnectTimeout=5 "$SERVER" "echo ok" >/dev/null 2>&1; then
      echo "No connection to $SERVER, skipping" >&2
      continue
    fi
    ssh -n "$SERVER" "trivy image --download-db-only >/dev/null 2>&1" || true
  fi

  # FASE 1: active containers
  if [ "$IS_LOCAL" = "true" ]; then
    mapfile -t RAW_LIST < <(docker ps --format '{{.Image}}|{{.Names}}' | sort | uniq)
  else
    mapfile -t RAW_LIST < <(ssh -n "$SERVER" "docker ps --format '{{.Image}}|{{.Names}}' | sort | uniq")
  fi

  for line in "${RAW_LIST[@]}"; do
    [ -z "$line" ] && continue
    raw_image=${line%%|*}
    container_name=${line#*|}
    base=$(basename "$raw_image")
    if [[ "$base" != *:* ]]; then
      img="${raw_image}:latest"
    else
      img="$raw_image"
    fi

    safe_srv=$(echo "$SERVER" | tr '@.' '_')
    safe_img=$(echo "$img" | tr '/:' '_')
    json_f="$REPORT_DIR/${safe_srv}__${safe_img}.json"
    html_f="$REPORT_DIR/${safe_srv}__${safe_img}.html"
    html_link="${safe_srv}__${safe_img}.html"

    if [ "$IS_LOCAL" = "true" ]; then
      TS=$(docker inspect -f '{{.Created}}' "$img" 2>/dev/null || echo "")
    else
      TS=$(ssh -n "$SERVER" "docker inspect -f '{{.Created}}' '$img'" 2>/dev/null || echo "")
    fi
    AGE=$(calculate_days_old "$TS")

    if [ ! -f "$json_f" ]; then
      if [ "$IS_LOCAL" = "true" ]; then
        trivy image --format json --ignore-unfixed --scanners vuln --skip-db-update -o "$json_f" "$img" >/dev/null 2>&1
        trivy image --format template --template "@$TEMPLATE_FILE" --ignore-unfixed --scanners vuln --skip-db-update -o "$html_f" "$img" >/dev/null 2>&1
      else
        ssh -n "$SERVER" "trivy image --format json --ignore-unfixed --scanners vuln --skip-db-update '$img'" >"$json_f" 2>/dev/null
        cat "$TEMPLATE_FILE" | ssh "$SERVER" "cat > '$REMOTE_TMP_TPL' && trivy image --format template --template '@$REMOTE_TMP_TPL' --ignore-unfixed --scanners vuln --skip-db-update '$img'" >"$html_f" 2>/dev/null
        ssh -n "$SERVER" "rm -f '$REMOTE_TMP_TPL'" >/dev/null 2>&1 || true
      fi
    fi

    add_row_for_image "$SERVER" "$img" "$container_name" "Active" "$json_f" "$html_link" "$AGE"
    SCANNED_ON_THIS_HOST="${SCANNED_ON_THIS_HOST} |${img}|"
  done

  # FASE 2: inactive images
  if [ "$IS_LOCAL" = "true" ]; then
    mapfile -t ALL_LIST < <(docker images --format "{{.Repository}}:{{.Tag}}" | grep -v '<none>' | sort | uniq)
  else
    mapfile -t ALL_LIST < <(ssh -n "$SERVER" "docker images --format '{{.Repository}}:{{.Tag}}' | grep -v '<none>' | sort | uniq")
  fi

  for img in "${ALL_LIST[@]}"; do
    [ -z "$img" ] && continue
    if [[ "$SCANNED_ON_THIS_HOST" == *"|${img}|"* ]]; then
      continue
    fi

    safe_srv=$(echo "$SERVER" | tr '@.' '_')
    safe_img=$(echo "$img" | tr '/:' '_')
    json_f="$REPORT_DIR/${safe_srv}__${safe_img}.json"
    html_f="$REPORT_DIR/${safe_srv}__${safe_img}.html"
    html_link="${safe_srv}__${safe_img}.html"

    if [ "$IS_LOCAL" = "true" ]; then
      TS=$(docker inspect -f '{{.Created}}' "$img" 2>/dev/null || echo "")
      trivy image --format json --ignore-unfixed --scanners vuln --skip-db-update -o "$json_f" "$img" >/dev/null 2>&1
      trivy image --format template --template "@$TEMPLATE_FILE" --ignore-unfixed --scanners vuln --skip-db-update -o "$html_f" "$img" >/dev/null 2>&1
    else
      TS=$(ssh -n "$SERVER" "docker inspect -f '{{.Created}}' '$img'" 2>/dev/null || echo "")
      ssh -n "$SERVER" "trivy image --format json --ignore-unfixed --scanners vuln --skip-db-update '$img'" >"$json_f" 2>/dev/null
      cat "$TEMPLATE_FILE" | ssh "$SERVER" "cat > '$REMOTE_TMP_TPL' && trivy image --format template --template '@$REMOTE_TMP_TPL' --ignore-unfixed --scanners vuln --skip-db-update '$img'" >"$html_f" 2>/dev/null
      ssh -n "$SERVER" "rm -f '$REMOTE_TMP_TPL'" >/dev/null 2>&1 || true
    fi

    AGE=$(calculate_days_old "$TS")
    add_row_for_image "$SERVER" "$img" "-" "Inactive" "$json_f" "$html_link" "$AGE"
    rm -f "$json_f"
  done

  # Write per-server block: details default closed.
  if [ "$TOTAL_IMAGES" -gt 0 ]; then
    color_class=$(get_server_color_class "$SERVER")
    {
      echo "<section class=\"server-block\">"
      echo "  <details>"
      echo "    <summary>"
      echo "      <div><span class=\"server-tag $color_class\">$SERVER</span></div>"
      echo "      <div style=\"font-size:0.9em; color:#555;\">Total images: <strong>$TOTAL_IMAGES</strong>&nbsp;|&nbsp;Safe: <span style=\"color:#28a745; font-weight:bold;\">$SAFE_IMAGES</span>&nbsp;|&nbsp;Unsafe: <span style=\"color:#dc3545; font-weight:bold;\">$UNSAFE_IMAGES</span></div>"
      echo "    </summary>"
      echo "    <div style=\"padding:10px 15px 15px 15px;\">"
      echo "      <table style=\"width:100%; border-collapse:collapse; font-size:0.9em;\">"
      echo "        <thead>"
      echo "          <tr>"
      echo "            <th style=\"text-align:left; padding:8px; border-bottom:1px solid #eee;\">Status</th>"
      echo "            <th style=\"text-align:left; padding:8px; border-bottom:1px solid #eee;\">Container</th>"
      echo "            <th style=\"text-align:left; padding:8px; border-bottom:1px solid #eee;\">Image</th>"
      echo "            <th style=\"text-align:left; padding:8px; border-bottom:1px solid #eee;\">Age</th>"
      echo "            <th style=\"text-align:left; padding:8px; border-bottom:1px solid #eee;\">Vulnerabilities</th>"
      echo "            <th style=\"text-align:left; padding:8px; border-bottom:1px solid #eee;\">Report</th>"
      echo "          </tr>"
      echo "        </thead>"
      echo "        <tbody"
      echo ">"
      printf "%s" "$SERVER_ROWS"
      echo "        </tbody>"
      echo "      </table>"
      echo "    </div>"
      echo "  </details>"
      echo "</section>"
    } >>"$INDEX_FILE"
  fi

done < "$HOSTS_FILE"

# --- Footer ---
cat >> "$INDEX_FILE" <<EOF
  </div>
</body>
</html>
EOF

echo "✅ Done! Dashboard: $INDEX_FILE"

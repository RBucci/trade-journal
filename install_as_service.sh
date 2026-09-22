#!/usr/bin/env bash
#
# install_as_service.sh
#
# One-shot installer for Trade Journal on Ubuntu (Desktop or Server, 22.04+).
# Installs Docker if missing, clones the repo, generates an encryption
# secret, builds the image, and registers a systemd service so the journal
# starts on boot.
#
# Usage (from any directory, on the target machine):
#
#   curl -fsSL https://raw.githubusercontent.com/RBucci/trade-journal/main/install_as_service.sh | sudo bash
#
# or, from a checkout:
#
#   sudo ./install_as_service.sh
#
# Re-running the script on an installed machine pulls the latest code and
# rebuilds. Existing .env and data are never touched.
#
# Optional environment overrides (pass before sudo, e.g. `sudo JOURNAL_PORT=8080 ./install_as_service.sh`):
#
#   INSTALL_DIR       where to install            (default: /opt/trade-journal)
#   REPO_URL          git repository to clone     (default: https://github.com/RBucci/trade-journal.git)
#   REPO_BRANCH       branch to check out         (default: main)
#   JOURNAL_PORT      host port to listen on      (default: 3333)
#   JOURNAL_BIND      host address to publish on  (default: 0.0.0.0; use 127.0.0.1 behind a local reverse proxy)
#   JOURNAL_SECRET    encryption secret           (default: generated)
#   JOURNAL_TRUST_PROXY  read client IP from X-Forwarded-For (default: true)
#
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/trade-journal}"
REPO_URL="${REPO_URL:-https://github.com/RBucci/trade-journal.git}"
REPO_BRANCH="${REPO_BRANCH:-main}"
JOURNAL_PORT="${JOURNAL_PORT:-3333}"
JOURNAL_BIND="${JOURNAL_BIND:-0.0.0.0}"
SERVICE_NAME="trade-journal"
CONTAINER_UID=1000   # the "node" user inside the image owns /data

# ---------- helpers ----------
say()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m  ! \033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run with sudo: sudo $0"
command -v apt-get >/dev/null || die "This installer targets Ubuntu / Debian (apt-get not found)."

# The person who ran sudo owns the checkout so they can edit .env without root.
OWNER="${SUDO_USER:-root}"
OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"

# ---------- 1. system packages ----------
say "Installing base packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl git gnupg openssl >/dev/null

# ---------- 2. Docker Engine + Compose plugin ----------
if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
  say "Docker $(docker --version | awk '{print $3}' | tr -d ,) already installed"
else
  say "Installing Docker Engine from docker.com apt repository"
  install -m 0755 -d /etc/apt/keyrings
  . /etc/os-release
  curl -fsSL "https://download.docker.com/linux/${ID}/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null
fi
systemctl enable --now docker >/dev/null

if [[ "$OWNER" != "root" ]] && ! id -nG "$OWNER" | grep -qw docker; then
  usermod -aG docker "$OWNER"
  warn "$OWNER was added to the docker group. Log out and back in before running docker commands without sudo."
fi

# ---------- 3. source checkout ----------
if [[ -d "$INSTALL_DIR/.git" ]]; then
  say "Updating existing checkout in $INSTALL_DIR"
  git -C "$INSTALL_DIR" fetch -q origin "$REPO_BRANCH"
  git -C "$INSTALL_DIR" checkout -q "$REPO_BRANCH"
  git -C "$INSTALL_DIR" pull -q --ff-only origin "$REPO_BRANCH"
else
  say "Cloning $REPO_URL into $INSTALL_DIR"
  git clone -q --branch "$REPO_BRANCH" "$REPO_URL" "$INSTALL_DIR"
fi
chown -R "$OWNER:$OWNER" "$INSTALL_DIR"

# ---------- 4. data directory ----------
# Docker would otherwise create ./data as root on first start, and the app
# (running as uid 1000 inside the container) could not open its database.
mkdir -p "$INSTALL_DIR/data/users" && chown -R "$CONTAINER_UID:$CONTAINER_UID" "$INSTALL_DIR/data"

# ---------- 5. credentials ----------
ENV_FILE="$INSTALL_DIR/.env"
if [[ -f "$ENV_FILE" ]]; then
  say "Keeping existing $ENV_FILE"
else
  say "Generating credentials in $ENV_FILE"
  JOURNAL_SECRET="${JOURNAL_SECRET:-$(openssl rand -hex 32)}"
  umask 077
  cat > "$ENV_FILE" <<EOF
# Trade Journal secrets. Keep this file: losing JOURNAL_SECRET makes saved broker and AI keys unreadable.
# After editing, run: sudo systemctl restart ${SERVICE_NAME}
JOURNAL_PORT=${JOURNAL_PORT}
JOURNAL_BIND=${JOURNAL_BIND}
JOURNAL_SECRET=${JOURNAL_SECRET}
JOURNAL_TRUST_PROXY=true
EOF
  umask 022
  chown "$OWNER:$OWNER" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
fi

# ---------- 6. systemd service ----------
say "Registering systemd service ${SERVICE_NAME}"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Trade Journal (Docker Compose)
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${INSTALL_DIR}
# --force-recreate so a changed .env is picked up on restart
ExecStart=/usr/bin/docker compose up -d --force-recreate
ExecStop=/usr/bin/docker compose stop
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null

# ---------- 7. build and start ----------
say "Building the image (first build takes a few minutes)"
( cd "$INSTALL_DIR" && docker compose build --quiet )
systemctl restart "$SERVICE_NAME"

# ---------- 8. firewall (only if ufw is active) ----------
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
  ufw allow "${JOURNAL_PORT}/tcp" >/dev/null
  say "Opened port ${JOURNAL_PORT}/tcp in ufw"
fi

# ---------- 9. smoke test ----------
say "Waiting for the app to answer"
PORT_IN_USE="$(grep -E '^JOURNAL_PORT=' "$ENV_FILE" | cut -d= -f2 || true)"
PORT_IN_USE="${PORT_IN_USE:-$JOURNAL_PORT}"
for _ in $(seq 1 30); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:${PORT_IN_USE}/" || true)"
  [[ "$code" == "200" || "$code" == "307" ]] && break
  sleep 1
done
[[ "$code" == "200" || "$code" == "307" ]] || { docker compose -f "$INSTALL_DIR/docker-compose.yml" logs --tail 40; die "App did not respond on port ${PORT_IN_USE}"; }

LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<EOF

============================================================
 Trade Journal is installed and running.

   Local:    http://localhost:${PORT_IN_USE}
   LAN:      http://${LAN_IP:-<this-machine-ip>}:${PORT_IN_USE}
   Install:  ${INSTALL_DIR}
   Data:     ${INSTALL_DIR}/data
   Service:  sudo systemctl {status|restart|stop} ${SERVICE_NAME}
   Logs:     cd ${INSTALL_DIR} && docker compose logs -f
EOF
cat <<EOF

 Open the URL above to create the administrator account. Save the
 recovery key it shows; it is the only way back in if the password is lost.
EOF
cat <<EOF

 Before exposing this to the internet, put an HTTPS reverse proxy
 (Nginx Proxy Manager, Caddy, Cloudflare Tunnel) in front of port ${PORT_IN_USE}.
 To update later, re-run this script.
============================================================
EOF

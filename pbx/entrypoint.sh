#!/bin/bash
set -e

# ============================================================
# SmartCMS Asterisk Entrypoint
# ============================================================

echo "======================================"
echo " SmartCMS Asterisk Server Starting"
echo " Version: ${ASTERISK_VERSION:-21.7.0}"
echo "======================================"

# ---- Wait for MariaDB ----
wait_for_db() {
    echo "[*] Waiting for MariaDB at ${DB_HOST:-mariadb}:${DB_PORT:-3306}..."
    local max_attempts=60
    local attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if curl -sf "telnet://${DB_HOST:-mariadb}:${DB_PORT:-3306}" 2>/dev/null || \
           bash -c "echo > /dev/tcp/${DB_HOST:-mariadb}/${DB_PORT:-3306}" 2>/dev/null; then
            echo "[✓] MariaDB is ready!"
            return 0
        fi
        attempt=$((attempt + 1))
        echo "[*] Attempt $attempt/$max_attempts - MariaDB not ready yet..."
        sleep 2
    done
    echo "[!] MariaDB not available after $max_attempts attempts. Starting anyway..."
    return 1
}

# ---- Configure ODBC ----
configure_odbc() {
    echo "[*] Configuring ODBC connection..."

    # Find MariaDB ODBC driver
    DRIVER_PATH=$(find /usr/lib -name "libmaodbc.so" 2>/dev/null | head -1)
    if [ -z "$DRIVER_PATH" ]; then
        DRIVER_PATH=$(find /usr/lib -name "libmyodbc*.so" 2>/dev/null | head -1)
    fi
    if [ -z "$DRIVER_PATH" ]; then
        echo "[!] MariaDB ODBC driver not found!"
        return 1
    fi
    echo "[✓] Found ODBC driver: $DRIVER_PATH"

    # /etc/odbcinst.ini - Driver registration
    cat > /etc/odbcinst.ini << EOF
[MariaDB]
Description = MariaDB ODBC Connector
Driver = ${DRIVER_PATH}
Setup = ${DRIVER_PATH}
UsageCount = 1
Threading = 2
EOF

    # /etc/odbc.ini - DSN configuration
    cat > /etc/odbc.ini << EOF
[asterisk-connector]
Description = Asterisk MariaDB Connection
Driver = MariaDB
Server = ${DB_HOST:-mariadb}
Port = ${DB_PORT:-3306}
Database = ${DB_NAME:-db_ucx}
User = ${DB_USER:-asterisk}
Password = ${DB_PASS:-asterisk_pass}
Option = 3
Charset = utf8mb4
ReadTimeout = 30
WriteTimeout = 30
EOF

    echo "[✓] ODBC configured successfully"
}

# ---- Configure Asterisk files based on env vars ----
configure_asterisk() {
    echo "[*] Configuring Asterisk..."

    # Set AMI password if provided
    if [ -n "$AMI_SECRET" ]; then
        sed -i "s/secret = .*/secret = ${AMI_SECRET}/" /etc/asterisk/manager.conf 2>/dev/null || true
    fi

    # Set ARI password if provided
    if [ -n "$ARI_PASSWORD" ]; then
        sed -i "s/password = .*/password = ${ARI_PASSWORD}/" /etc/asterisk/ari.conf 2>/dev/null || true
    fi

    # Set external IP for NAT
    if [ -n "$EXTERNAL_IP" ]; then
        sed -i "s/external_media_address=.*/external_media_address=${EXTERNAL_IP}/" /etc/asterisk/pjsip.conf 2>/dev/null || true
        sed -i "s/external_signaling_address=.*/external_signaling_address=${EXTERNAL_IP}/" /etc/asterisk/pjsip.conf 2>/dev/null || true
    fi

    echo "[✓] Asterisk configured"
}

# ---- Fix permissions ----
fix_permissions() {
    chown -R asterisk:asterisk /etc/asterisk
    chown -R asterisk:asterisk /var/lib/asterisk
    chown -R asterisk:asterisk /var/log/asterisk
    chown -R asterisk:asterisk /var/spool/asterisk
    chown -R asterisk:asterisk /var/run/asterisk 2>/dev/null || true
}

# ---- Main ----
wait_for_db
configure_odbc
configure_asterisk
fix_permissions

echo "[*] Starting Asterisk..."
exec "$@"

# ============================================================
# SmartCMS Custom Asterisk Build - From Source
# No external Asterisk images used
# Base: Debian Bookworm (slim)
# ============================================================
FROM debian:bookworm-slim AS builder

LABEL maintainer="SmartCMS <admin@smartcms.local>"
LABEL description="Custom Asterisk 21 LTS with PJSIP, WebSocket, ODBC Realtime"

ENV DEBIAN_FRONTEND=noninteractive
ENV ASTERISK_VERSION=21.7.0

# ---- Install build dependencies ----
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    wget \
    curl \
    ca-certificates \
    gnupg \
    pkg-config \
    libedit-dev \
    libjansson-dev \
    libxml2-dev \
    libsqlite3-dev \
    libssl-dev \
    libncurses5-dev \
    uuid-dev \
    libsrtp2-dev \
    libspandsp-dev \
    libcurl4-openssl-dev \
    libnewt-dev \
    libpopt-dev \
    libical-dev \
    libiksemel-dev \
    libsnmp-dev \
    libcorosync-common-dev \
    libunbound-dev \
    libspeex-dev \
    libspeexdsp-dev \
    libresample1-dev \
    libopus-dev \
    liburiparser-dev \
    # ODBC for MariaDB Realtime
    unixodbc \
    unixodbc-dev \
    odbc-mariadb \
    libmariadb-dev \
    # WebSocket dependencies
    libwebsockets-dev \
    # Lua for dialplan (optional)
    liblua5.2-dev \
    # Sound files
    sox \
    subversion \
    git \
    python3 \
    python3-dev \
    file \
    && rm -rf /var/lib/apt/lists/*

# ---- Download and extract Asterisk source ----
WORKDIR /usr/src
RUN wget -q https://downloads.asterisk.org/pub/telephony/asterisk/releases/asterisk-${ASTERISK_VERSION}.tar.gz \
    && tar xzf asterisk-${ASTERISK_VERSION}.tar.gz \
    && rm asterisk-${ASTERISK_VERSION}.tar.gz

WORKDIR /usr/src/asterisk-${ASTERISK_VERSION}

# ---- Install prerequisites (mp3, pjproject bundled) ----
RUN yes | contrib/scripts/install_prereq install

# ---- Configure with PJSIP bundled, ODBC, Opus ----
RUN ./configure \
    --with-pjproject-bundled \
    --with-jansson-bundled \
    --with-crypto \
    --with-ssl \
    --with-srtp \
    --with-unixodbc \
    --with-opus \
    --with-resample \
    --with-speex \
    --with-speexdsp \
    --with-libedit \
    --libdir=/usr/lib/x86_64-linux-gnu

# ---- Select modules via menuselect ----
RUN make menuselect.makeopts \
    # Enable PJSIP modules
    && menuselect/menuselect \
        --enable res_pjsip \
        --enable res_pjsip_authenticator_digest \
        --enable res_pjsip_caller_id \
        --enable res_pjsip_dialog_info_body_generator \
        --enable res_pjsip_diversion \
        --enable res_pjsip_dlg_options \
        --enable res_pjsip_dtmf_info \
        --enable res_pjsip_empty_info \
        --enable res_pjsip_endpoint_identifier_anonymous \
        --enable res_pjsip_endpoint_identifier_ip \
        --enable res_pjsip_endpoint_identifier_user \
        --enable res_pjsip_exten_state \
        --enable res_pjsip_header_funcs \
        --enable res_pjsip_logger \
        --enable res_pjsip_messaging \
        --enable res_pjsip_mwi \
        --enable res_pjsip_mwi_body_generator \
        --enable res_pjsip_nat \
        --enable res_pjsip_notify \
        --enable res_pjsip_one_touch_record_info \
        --enable res_pjsip_outbound_authenticator_digest \
        --enable res_pjsip_outbound_publish \
        --enable res_pjsip_outbound_registration \
        --enable res_pjsip_path \
        --enable res_pjsip_pidf_body_generator \
        --enable res_pjsip_pidf_digium_body_supplement \
        --enable res_pjsip_pidf_eyebeam_body_supplement \
        --enable res_pjsip_publish_asterisk \
        --enable res_pjsip_pubsub \
        --enable res_pjsip_refer \
        --enable res_pjsip_registrar \
        --enable res_pjsip_rfc3326 \
        --enable res_pjsip_sdp_rtp \
        --enable res_pjsip_send_to_voicemail \
        --enable res_pjsip_session \
        --enable res_pjsip_sips_contact \
        --enable res_pjsip_t38 \
        --enable res_pjsip_transport_websocket \
        --enable res_pjsip_xpidf_body_generator \
        # Enable ODBC modules for Realtime
        --enable res_odbc \
        --enable res_config_odbc \
        --enable cdr_odbc \
        --enable func_odbc \
        --enable cel_odbc \
        # Enable HTTP/WebSocket
        --enable res_http_websocket \
        --enable res_http_post \
        # Enable recording
        --enable res_monitor \
        --enable res_mixmonitor \
        --enable app_mixmonitor \
        # Enable ARI (Asterisk REST Interface)
        --enable res_ari \
        --enable res_ari_applications \
        --enable res_ari_asterisk \
        --enable res_ari_bridges \
        --enable res_ari_channels \
        --enable res_ari_device_states \
        --enable res_ari_endpoints \
        --enable res_ari_events \
        --enable res_ari_mailboxes \
        --enable res_ari_model \
        --enable res_ari_playbacks \
        --enable res_ari_recordings \
        --enable res_ari_sounds \
        --enable res_stasis \
        --enable res_stasis_answer \
        --enable res_stasis_device_state \
        --enable res_stasis_mailbox \
        --enable res_stasis_playback \
        --enable res_stasis_recording \
        --enable res_stasis_snoop \
        # Enable AMI
        --enable res_manager_presencestate \
        # Codecs
        --enable codec_opus \
        --enable codec_speex \
        --enable codec_resample \
        --enable codec_a_mu \
        --enable codec_gsm \
        --enable codec_g722 \
        --enable codec_g726 \
        --enable codec_ilbc \
        --enable FORMAT_MP3 \
        # Core sound and MOH
        --enable CORE-SOUNDS-EN-ULAW \
        --enable CORE-SOUNDS-EN-ALAW \
        --enable CORE-SOUNDS-EN-WAV \
        --enable MOH-OPSOUND-ULAW \
        --enable MOH-OPSOUND-ALAW \
        --enable MOH-OPSOUND-WAV \
        --enable EXTRA-SOUNDS-EN-ULAW \
        --enable EXTRA-SOUNDS-EN-WAV \
        menuselect.makeopts

# ---- Build ----
RUN make -j$(nproc)

# ============================================================
# Runtime stage - smaller image
# ============================================================
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# ---- Install runtime dependencies only ----
RUN apt-get update && apt-get install -y --no-install-recommends \
    libedit2 \
    libjansson4 \
    libxml2 \
    libsqlite3-0 \
    libssl3 \
    libncurses6 \
    libuuid1 \
    libsrtp2-1 \
    libspandsp2 \
    libcurl4 \
    libnewt0.52 \
    libpopt0 \
    libical3 \
    libiksemel3 \
    libsnmp40 \
    libunbound8 \
    libspeex1 \
    libspeexdsp1 \
    libresample1 \
    libopus0 \
    liburiparser1 \
    # ODBC runtime
    unixodbc \
    odbc-mariadb \
    libmariadb3 \
    # WebSocket
    libwebsockets19 \
    # Lua
    liblua5.2-0 \
    # Utilities
    sox \
    curl \
    wget \
    net-tools \
    iputils-ping \
    tcpdump \
    sngrep \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ---- Create asterisk user ----
RUN groupadd -r asterisk && useradd -r -g asterisk -d /var/lib/asterisk -s /bin/false asterisk

# ---- Install from builder ----
COPY --from=builder /usr/src/asterisk-21.7.0 /usr/src/asterisk
WORKDIR /usr/src/asterisk
RUN make install \
    && make samples \
    && make config \
    && make install-logrotate \
    && ldconfig \
    && rm -rf /usr/src/asterisk

# ---- Directory permissions ----
RUN chown -R asterisk:asterisk \
    /etc/asterisk \
    /var/lib/asterisk \
    /var/log/asterisk \
    /var/spool/asterisk \
    /var/run/asterisk \
    /usr/lib/asterisk

# ---- Create directories for custom configs ----
RUN mkdir -p /etc/asterisk/smartcms \
    && chown -R asterisk:asterisk /etc/asterisk/smartcms

# ---- Copy configuration files ----
COPY configs/ /etc/asterisk/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ---- Expose ports ----
# SIP/PJSIP UDP & TCP
EXPOSE 5060/udp
EXPOSE 5060/tcp
# PJSIP TLS
EXPOSE 5061/tcp
# WebSocket (WSS)
EXPOSE 8088/tcp
EXPOSE 8089/tcp
# RTP ports
EXPOSE 10000-20000/udp
# AMI
EXPOSE 5038/tcp
# ARI HTTP
EXPOSE 8088/tcp

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD asterisk -rx "core show channels" || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["asterisk", "-fvvvg", "-c"]

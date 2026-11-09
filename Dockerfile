# DuckNet L7 Security — 軽量セキュリティゲートウェイ(stdlib のみ=依存インストール不要)
FROM python:3.12-slim

LABEL org.opencontainers.image.title="DuckNet-Lite" \
      org.opencontainers.image.description="Lightweight L7 DDoS/WAF security gateway — free AGPL edition (core WAF/DDoS, feature-limited; stdlib only, zero runtime deps)" \
      org.opencontainers.image.version="1.3.0" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.source="https://example.com/ducknet"

WORKDIR /app

# 非root実行。状態は書込み可能な HOME=/data 配下の専用ディレクトリへ。
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
    && python -m pip uninstall -y pip \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 ducknet \
    && mkdir -p /data \
    && chown ducknet /data
# Copy only runtime modules and release notices. A build context can contain
# local backups or logs with private data; broad COPY would bake them into the
# distributable image even if the application never opens them.
COPY --chown=root:root dataplane/__init__.py dataplane/__main__.py dataplane/admin.py dataplane/service.py /app/dataplane/
COPY --chown=root:root dataplane/engine/__init__.py /app/dataplane/engine/
COPY --chown=root:root dataplane/engine/core/__init__.py dataplane/engine/core/accel.py dataplane/engine/core/atomic_io.py dataplane/engine/core/autostart.py dataplane/engine/core/commit_barrier.py dataplane/engine/core/i18n.py dataplane/engine/core/netaddr.py dataplane/engine/core/origin.py dataplane/engine/core/saferegex.py dataplane/engine/core/serving_lease.py dataplane/engine/core/signed_state.py /app/dataplane/engine/core/
COPY --chown=root:root dataplane/engine/lifeform/__init__.py dataplane/engine/lifeform/bloom.py dataplane/engine/lifeform/graphql.py dataplane/engine/lifeform/kb_common.py dataplane/engine/lifeform/monitor.py dataplane/engine/lifeform/netutil.py dataplane/engine/lifeform/pipeline.py dataplane/engine/lifeform/policy.py /app/dataplane/engine/lifeform/
COPY --chown=root:root dataplane/engine/services/__init__.py dataplane/engine/services/banner.py dataplane/engine/services/edge_config.py dataplane/engine/services/proxy.py /app/dataplane/engine/services/
COPY --chown=root:root dataplane/gui/__init__.py dataplane/gui/__main__.py dataplane/gui/settings.py dataplane/gui/tray.py /app/dataplane/gui/
COPY --chown=root:root dataplane/gui/assets/DuckNet-off.ico dataplane/gui/assets/DuckNet.ico dataplane/gui/assets/DuckNet.png /app/dataplane/gui/assets/
COPY --chown=root:root README.md LICENSE.txt THIRD_PARTY_NOTICES.txt sbom.cdx.json /app/
USER ducknet
ENV HOME=/data \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    LANGUAGE= \
    DUCKNET_OFFLINE=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8443 8081

# Liveness inside the container only: bridge-published host ingress may still
# be held by the default private ACL, so healthy does not prove backend readiness.
HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
  CMD python -c 'import http.client,json,sys; e=http.client.HTTPConnection("127.0.0.1",8443,timeout=2); e.request("GET","/healthz"); r=e.getresponse(); edge=r.status==200 and json.loads(r.read(64))=={"status":"ok"}; a=http.client.HTTPConnection("127.0.0.1",8081,timeout=2); a.request("GET","/api/state"); r=a.getresponse(); admin=r.status==401 and json.loads(r.read(128))=={"ok":False,"error":"token required"}; sys.exit(0 if edge and admin else 1)'

ENTRYPOINT ["python", "-m", "dataplane"]
# 既定: 前衛8443→バックエンド(ホストの8080)、管理画面8081(コンテナ内0.0.0.0=ポート公開)。
CMD ["--backend", "host.docker.internal:8080", "--listen", "8443", \
     "--host", "0.0.0.0", \
     "--admin", "8081", "--admin-host", "0.0.0.0", "--health-path", "/healthz"]

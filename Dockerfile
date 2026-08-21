# ChickenNet L7 Security — 軽量セキュリティゲートウェイ(stdlib のみ=依存インストール不要)
FROM python:3.12-slim

LABEL org.opencontainers.image.title="ChickenNet L7 Security" \
      org.opencontainers.image.description="Lightweight L7 DDoS/WAF security gateway (stdlib only, zero runtime deps)" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.licenses="LicenseRef-ChickenNet-Commercial" \
      org.opencontainers.image.source="https://example.com/chickennet"

WORKDIR /app
COPY . /app

# 非root実行(セキュリティ製品として最小権限)。状態(~/.chickennet)は書込可能な HOME=/data へ。
RUN useradd -r -u 10001 chickennet \
    && mkdir -p /data \
    && chown -R chickennet /app /data
USER chickennet
ENV HOME=/data \
    CHICKENNET_OFFLINE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8443 8081

# 管理ダッシュボード(8081)への接続可否で生存確認
HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
  CMD python -c "import socket; socket.create_connection(('127.0.0.1', 8081), 2).close()" || exit 1

ENTRYPOINT ["python", "-m", "dataplane"]
# 既定: 前衛8443→バックエンド(ホストの8080)、管理画面8081(コンテナ内0.0.0.0=ポート公開)。
CMD ["--backend", "host.docker.internal:8080", "--listen", "8443", \
     "--admin", "8081", "--admin-host", "0.0.0.0"]

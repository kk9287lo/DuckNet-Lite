"""The bundled plain-HTTP edge must not be publicly published by default."""

import json
import ipaddress
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
from unittest import SkipTest, mock

import dataplane.service as service
from dataplane.engine.services.proxy import AsyncEdgeGuard


_ROOT = Path(__file__).resolve().parents[1]


def _rendered_ports():
    if not shutil.which("docker"):
        return None
    try:
        run = subprocess.run(["docker", "compose", "config", "--format", "json"],
                             cwd=_ROOT, capture_output=True, text=True, timeout=12)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if run.returncode:
        return None  # Compose plugin absent: assert against the shipped YAML text.
    return json.loads(run.stdout)["services"]["ducknet-lite"]["ports"]


def test_compose_plain_http_edge_and_admin_bind_loopback_by_default():
    ports = _rendered_ports()
    if ports is not None:
        for target, published in ((8443, "8443"), (8081, "8081")):
            selected = [port for port in ports if port.get("target") == target
                        and str(port.get("published")) == published]
            assert len(selected) == 1, (target, selected)
            assert selected[0].get("host_ip") == "127.0.0.1", selected[0]
    else:
        text = (_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        for port in (8443, 8081):
            assert re.search(r'^\s*-\s*["\']127\.0\.0\.1:' + str(port) +
                             r':' + str(port) + r'["\']\s*(?:#.*)?$',
                             text, re.MULTILINE), port


def test_existing_admin_publication_stays_loopback_only():
    ports = _rendered_ports()
    if ports is not None:
        admin = [port for port in ports if port.get("target") == 8081]
        assert len(admin) == 1 and admin[0].get("host_ip") == "127.0.0.1", admin
    else:
        text = (_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        assert '"127.0.0.1:8081:8081"' in text


def test_quickstart_explains_plain_http_requires_tls_terminator():
    compose = (_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    hardening = (_ROOT / "docs" / "hardening.md").read_text(encoding="utf-8")
    assert "TLS 終端" in compose and "127.0.0.1:8443:8443" in compose
    assert "TLS 終端" in readme and "127.0.0.1:8443" in readme
    assert "TLS 終端" in hardening and "8443" in hardening


def test_cli_and_programmatic_edge_default_to_loopback():
    with mock.patch.object(service, "load_env_file"), \
            mock.patch.object(service, "run") as start:
        assert service.main([]) == 0
        assert start.call_args.kwargs["host"] == "127.0.0.1"

    seen = {}

    class Probe(Exception):
        pass

    def capture_guard(**kwargs):
        seen.update(kwargs)
        raise Probe()

    with mock.patch.dict(os.environ, {"DUCKNET_CONFIG": ""}), \
            mock.patch.object(service, "net_shield") as shield, \
            mock.patch.object(service, "AsyncEdgeGuard", side_effect=capture_guard):
        shield.return_value.config_warnings.return_value = []
        try:
            service.run(defaults_on=False)
        except Probe:
            pass
        else:
            raise AssertionError("edge guard was not constructed")
    assert seen["listen_host"] == "127.0.0.1", seen


def test_explicit_public_bind_remains_available_for_tls_fronted_private_network():
    with mock.patch.object(service, "load_env_file"), \
            mock.patch.object(service, "run") as start:
        assert service.main(["--host", "0.0.0.0"]) == 0
        assert start.call_args.kwargs["host"] == "0.0.0.0"


def test_container_commands_explicitly_bind_inside_the_container():
    compose = (_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    dockerfile = (_ROOT / "Dockerfile").read_text(encoding="utf-8")
    for text in (compose, dockerfile):
        assert '"--host", "0.0.0.0"' in text


def test_direct_guard_default_socket_binds_only_loopback():
    guard = AsyncEdgeGuard(listen_port=0, backend_port=9)
    assert guard.listen_host == "127.0.0.1"
    try:
        assert guard.start().get("ok") is True
        assert guard._server.sockets[0].getsockname()[0] == "127.0.0.1"
    finally:
        guard.stop()


def test_explicit_wildcard_bind_remains_available_on_nonloopback_interface():
    try:
        candidates = [item[4][0] for item in socket.getaddrinfo(
            socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM)
            if not (ipaddress.ip_address(item[4][0]).is_loopback or
                    ipaddress.ip_address(item[4][0]).is_link_local)]
    except OSError:
        candidates = []
    if not candidates:
        raise SkipTest("no non-loopback IPv4 interface")
    wildcard = AsyncEdgeGuard(listen_host="0.0.0.0", listen_port=0, backend_port=9)
    try:
        assert wildcard.start().get("ok") is True
        assert wildcard._server.sockets[0].getsockname()[0] == "0.0.0.0"
        try:
            sock = socket.create_connection((candidates[0], wildcard.listen_port), timeout=.4)
        except OSError:
            raise SkipTest("host firewall prevents local non-loopback TCP probe")
        else:
            sock.close()
    finally:
        assert wildcard.stop().get("ok") is True

    # A serving lease intentionally prevents two simultaneous listeners from
    # sharing one state. Probe the default bind after the wildcard owner stops.
    local = AsyncEdgeGuard(listen_port=0, backend_port=9)
    try:
        assert local.start().get("ok") is True
        try:
            sock = socket.create_connection((candidates[0], local.listen_port), timeout=.4)
        except OSError:
            pass
        else:
            sock.close()
            raise AssertionError("default loopback guard accepted non-loopback TCP")
    finally:
        assert local.stop().get("ok") is True

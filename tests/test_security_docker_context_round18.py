"""A Docker image must not absorb unrelated files from its build context."""

from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
from unittest import SkipTest
import uuid


ROOT = Path(__file__).resolve().parents[1]


def _docker(*args, timeout=120):
    return subprocess.run(["docker", *args], text=True, encoding="utf-8",
                          errors="replace", stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout, check=False)


def test_unrelated_backup_never_enters_runtime_image():
    if not shutil.which("docker"):
        raise SkipTest("Docker CLI unavailable")
    try:
        available = _docker("info", "--format", "{{.ServerVersion}}", timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        raise SkipTest("Docker daemon unavailable")
    if available.returncode:
        raise SkipTest("Docker daemon unavailable")

    tag = "ducknet-r18-context:" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix="ducknet-r18-context-") as tmp:
        context = Path(tmp)
        for name in ("Dockerfile", ".dockerignore", "README.md", "LICENSE.txt",
                     "THIRD_PARTY_NOTICES.txt", "sbom.cdx.json"):
            shutil.copyfile(ROOT / name, context / name)
        shutil.copytree(ROOT / "dataplane", context / "dataplane",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        canaries = ("private-backup-r18.txt", "dataplane/private-backup-r18.txt",
                    "dataplane/private_keys.py", "dataplane/gui/assets/private.png")
        for name in canaries:
            (context / name).write_text("DUCKNET_R18_CONFIDENTIAL_CANARY", encoding="ascii")
        container_id = ""
        try:
            # A remote Docker daemon must not receive either canary in its
            # build context, even when a caller supplies another Dockerfile.
            for index, source in enumerate(canaries):
                probe_file = context / "Dockerfile.context-probe"
                probe_file.write_text("FROM scratch\nCOPY " + source + " /leak\n",
                                      encoding="ascii")
                probe_tag = tag + "-probe-" + str(index)
                try:
                    probe = _docker("build", "--pull=false", "--progress=quiet",
                                    "-f", str(probe_file), "-t", probe_tag,
                                    str(context), timeout=30)
                    assert probe.returncode != 0, (
                        "private file reached Docker build context: " + source)
                finally:
                    _docker("image", "rm", "-f", probe_tag, timeout=30)
            # Use the product's exact COPY directives on a scratch base. This
            # tests the image file inventory without fetching a base image or
            # running apt, so the regression is deterministic offline.
            copy_lines = [line.replace("--chown=root:root ", "")
                          for line in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()
                          if line.startswith("COPY ")]
            assert copy_lines, "runtime Dockerfile has no COPY directives"
            copy_file = context / "Dockerfile.copy-probe"
            copy_file.write_text("FROM scratch\n" + "\n".join(copy_lines) + "\n",
                                 encoding="ascii")
            built = _docker("build", "--pull=false", "--progress=quiet", "-f",
                            str(copy_file), "-t", tag, str(context), timeout=60)
            assert built.returncode == 0, built.stderr[-1200:]
            created = _docker("create", "--pull=never", tag, "/unused", timeout=15)
            assert created.returncode == 0, created.stderr[-1200:]
            container_id = created.stdout.strip()
            archive = context / "image-files.tar"
            exported = _docker("export", "-o", str(archive), container_id, timeout=30)
            assert exported.returncode == 0, exported.stderr[-1200:]
            with tarfile.open(archive) as image:
                actual = {member.name.lstrip("./") for member in image.getmembers()
                          if member.isfile() and member.name.lstrip("./").startswith("app/")}
            expected = {"app/" + p.relative_to(ROOT).as_posix()
                        for p in (ROOT / "dataplane").rglob("*")
                        if p.is_file() and p.suffix in (".py", ".ico", ".png")}
            expected.update("app/" + name for name in
                            ("README.md", "LICENSE.txt", "THIRD_PARTY_NOTICES.txt",
                             "sbom.cdx.json"))
            assert actual == expected, (sorted(actual - expected), sorted(expected - actual))
        finally:
            if container_id:
                _docker("rm", "-f", container_id, timeout=15)
            _docker("image", "rm", "-f", tag, timeout=30)

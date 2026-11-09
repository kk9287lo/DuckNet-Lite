"""Dedicated management routes must distinguish absent from invalid fields."""
import copy
from pathlib import Path
from test_sweep_admin_ui import _Admin


def test_paranoia_explicit_null_optional_map_cannot_apply_the_other_field():
    with _Admin() as admin:
        before = copy.deepcopy(admin.sh.cfg)
        audit = Path(admin.adm._audit_path)
        previous = audit.read_bytes() if audit.exists() else b""
        level = 2 if before["paranoia"] != 2 else 3
        status, result = admin.post("/api/shield/paranoia", {"level": level, "optional_sigs": None})
        assert status == 400 and result["ok"] is False
        assert admin.sh.cfg == before
        assert (audit.read_bytes() if audit.exists() else b"") == previous


def test_paranoia_absent_optional_map_keeps_normal_level_updates():
    with _Admin() as admin:
        status, result = admin.post("/api/shield/paranoia", {"level": 2})
        assert status == 200 and result["ok"] is True
        assert admin.sh.cfg["paranoia"] == 2

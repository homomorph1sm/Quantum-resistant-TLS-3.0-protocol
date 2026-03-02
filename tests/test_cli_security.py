from pathlib import Path

import pytest

from python_tls13.client import validate_private_key_permissions as validate_client_key
from python_tls13.server import validate_private_key_permissions as validate_server_key


def test_private_key_permissions_enforced(tmp_path: Path) -> None:
    key = tmp_path / "k.pem"
    key.write_text("dummy", encoding="utf-8")
    key.chmod(0o644)

    with pytest.raises(PermissionError):
        validate_server_key(str(key))
    with pytest.raises(PermissionError):
        validate_client_key(str(key))

    key.chmod(0o600)
    validate_server_key(str(key))
    validate_client_key(str(key))

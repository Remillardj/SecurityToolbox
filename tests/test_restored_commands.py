"""Tests for the commands restored from the pre-2.0 tree."""

import json
import os

import pytest
from click.testing import CliRunner

from bsot.auth.cli import auth, _audit_sshd
from bsot.file.cli import file


@pytest.fixture
def runner():
    return CliRunner()


class TestPermissions:
    @pytest.fixture
    def tree(self, tmp_path):
        (tmp_path / "normal.txt").write_text("x")
        os.chmod(tmp_path / "normal.txt", 0o644)
        (tmp_path / "world.txt").write_text("x")
        os.chmod(tmp_path / "world.txt", 0o666)
        (tmp_path / "worldexec.sh").write_text("x")
        os.chmod(tmp_path / "worldexec.sh", 0o777)
        (tmp_path / "group.txt").write_text("x")
        os.chmod(tmp_path / "group.txt", 0o664)
        return tmp_path

    def _findings(self, runner, tree, *args):
        result = runner.invoke(file, ["permissions", str(tree), "--json", *args])
        return json.loads(result.output)

    def test_flags_world_writable(self, runner, tree):
        data = self._findings(runner, tree)
        flagged = {os.path.basename(f["path"]) for f in data["findings"]}

        assert "world.txt" in flagged
        assert "worldexec.sh" in flagged

    def test_normal_modes_not_flagged(self, runner, tree):
        """0644 and 0755 are ordinary; the old octal-list version flagged 0755."""
        data = self._findings(runner, tree)
        flagged = {os.path.basename(f["path"]) for f in data["findings"]}

        assert "normal.txt" not in flagged

    def test_group_writable_only_when_requested(self, runner, tree):
        default = {os.path.basename(f["path"]) for f in self._findings(runner, tree)["findings"]}
        assert "group.txt" not in default

        opted_in = {
            os.path.basename(f["path"])
            for f in self._findings(runner, tree, "--group-writable")["findings"]
        }
        assert "group.txt" in opted_in

    def test_world_writable_executable_is_critical(self, runner, tree):
        data = self._findings(runner, tree)
        sev = {
            os.path.basename(f["path"]): f["severity"] for f in data["findings"]
        }

        assert sev["worldexec.sh"] == "critical"
        assert sev["world.txt"] == "high"

    def test_sticky_dir_not_flagged(self, runner, tmp_path):
        d = tmp_path / "shared"
        d.mkdir()
        os.chmod(d, 0o1777)  # world-writable but sticky, like /tmp
        data = self._findings(runner, tmp_path)

        assert not [f for f in data["findings"] if f["path"] == str(d)]

    def test_exit_code_signals_findings(self, runner, tree, tmp_path):
        assert runner.invoke(file, ["permissions", str(tree)]).exit_code == 1

        clean = tmp_path / "clean"
        clean.mkdir()
        (clean / "ok.txt").write_text("x")
        os.chmod(clean / "ok.txt", 0o644)
        assert runner.invoke(file, ["permissions", str(clean)]).exit_code == 0


class TestSuidFinder:
    def test_finds_suid_bit(self, runner, tmp_path):
        target = tmp_path / "sneaky"
        target.write_text("x")
        os.chmod(target, 0o4755)

        result = runner.invoke(file, ["suid-finder", str(tmp_path), "--json"])
        data = json.loads(result.output)

        assert data["count"] == 1
        assert data["binaries"][0]["bits"] == ["suid"]
        assert data["unexpected_count"] == 1

    def test_known_binaries_marked_expected(self, runner, tmp_path):
        target = tmp_path / "sudo"
        target.write_text("x")
        os.chmod(target, 0o4755)

        data = json.loads(runner.invoke(file, ["suid-finder", str(tmp_path), "--json"]).output)

        assert data["binaries"][0]["expected"] is True
        assert data["unexpected_count"] == 0

    def test_no_suid_is_clean_exit(self, runner, tmp_path):
        (tmp_path / "plain").write_text("x")
        result = runner.invoke(file, ["suid-finder", str(tmp_path)])

        assert result.exit_code == 0


class TestSSHAudit:
    def test_absent_password_auth_uses_sshd_default(self):
        """PasswordAuthentication defaults to yes, so absence is still a finding."""
        findings = _audit_sshd({"permitrootlogin": "no"})
        pw = [f for f in findings if f["setting"] == "PasswordAuthentication"][0]

        assert pw["severity"] == "high"
        assert pw["source"] == "default"

    def test_explicit_disable_is_ok(self):
        findings = _audit_sshd({"passwordauthentication": "no"})
        pw = [f for f in findings if f["setting"] == "PasswordAuthentication"][0]

        assert pw["severity"] == "ok"
        assert pw["source"] == "config"

    def test_root_login_yes_is_critical(self):
        findings = _audit_sshd({"permitrootlogin": "yes"})
        root = [f for f in findings if f["setting"] == "PermitRootLogin"][0]

        assert root["severity"] == "critical"

    def test_prohibit_password_is_ok(self):
        findings = _audit_sshd({"permitrootlogin": "prohibit-password"})
        root = [f for f in findings if f["setting"] == "PermitRootLogin"][0]

        assert root["severity"] == "ok"

    def test_empty_passwords_critical(self):
        findings = _audit_sshd({"permitemptypasswords": "yes"})

        assert any(f["severity"] == "critical" and f["setting"] == "PermitEmptyPasswords"
                   for f in findings)

    def test_protocol_1_critical(self):
        findings = _audit_sshd({"protocol": "1"})

        assert any(f["setting"] == "Protocol" and f["severity"] == "critical"
                   for f in findings)

    def test_first_occurrence_wins(self, runner, tmp_path):
        """sshd honors the first occurrence of a directive, not the last."""
        cfg = tmp_path / "sshd_config"
        cfg.write_text("PermitRootLogin no\nPermitRootLogin yes\n")

        data = json.loads(runner.invoke(auth, ["ssh-audit", str(cfg), "--json"]).output)
        root = [f for f in data["findings"] if f["setting"] == "PermitRootLogin"][0]

        assert root["value"] == "no"

    def test_comments_ignored(self, runner, tmp_path):
        cfg = tmp_path / "sshd_config"
        cfg.write_text("# PermitRootLogin yes\nPermitRootLogin no\n")

        data = json.loads(runner.invoke(auth, ["ssh-audit", str(cfg), "--json"]).output)
        root = [f for f in data["findings"] if f["setting"] == "PermitRootLogin"][0]

        assert root["value"] == "no"

    def test_exit_code_on_issues(self, runner, tmp_path):
        cfg = tmp_path / "sshd_config"
        cfg.write_text("PermitRootLogin yes\n")

        assert runner.invoke(auth, ["ssh-audit", str(cfg)]).exit_code == 1

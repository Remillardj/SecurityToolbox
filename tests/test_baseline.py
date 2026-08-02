"""Tests for file baseline and diff."""

import json
import os

import pytest
from click.testing import CliRunner

from bsot.file.cli import file


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "tree"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_text("original")
    (root / "b.txt").write_text("keepme")
    (root / "sub" / "c.txt").write_text("nested")
    return root


@pytest.fixture
def baseline_path(runner, tree, tmp_path):
    path = tmp_path / "base.json"
    runner.invoke(file, ["baseline", str(tree), "-o", str(path)])
    return path


def diff_json(runner, baseline_path, tree):
    result = runner.invoke(file, ["diff", str(baseline_path), "-d", str(tree), "--json"])
    return json.loads(result.output)


class TestBaseline:
    def test_records_every_file(self, baseline_path):
        manifest = json.loads(baseline_path.read_text())

        assert manifest["file_count"] == 3
        assert "a.txt" in manifest["files"]
        assert os.path.join("sub", "c.txt") in manifest["files"]

    def test_records_hash_size_and_mode(self, baseline_path):
        entry = json.loads(baseline_path.read_text())["files"]["a.txt"]

        assert len(entry["sha256"]) == 64
        assert entry["size"] == len("original")
        assert "mode" in entry

    def test_honors_exclude(self, runner, tree, tmp_path):
        (tree / "skip.log").write_text("noise")
        path = tmp_path / "excluded.json"
        runner.invoke(file, ["baseline", str(tree), "-o", str(path), "--exclude", "*.log"])

        assert "skip.log" not in json.loads(path.read_text())["files"]


class TestDiff:
    def test_clean_tree_reports_nothing(self, runner, baseline_path, tree):
        report = diff_json(runner, baseline_path, tree)

        assert report["summary"] == {
            "added": 0, "removed": 0, "modified": 0, "content_changed": 0
        }

    def test_detects_added(self, runner, baseline_path, tree):
        (tree / "new.txt").write_text("new")
        assert "new.txt" in diff_json(runner, baseline_path, tree)["added"]

    def test_detects_removed(self, runner, baseline_path, tree):
        (tree / "b.txt").unlink()
        assert "b.txt" in diff_json(runner, baseline_path, tree)["removed"]

    def test_detects_content_change(self, runner, baseline_path, tree):
        (tree / "a.txt").write_text("TAMPERED")
        modified = diff_json(runner, baseline_path, tree)["modified"]

        entry = [m for m in modified if m["path"] == "a.txt"][0]
        assert "content" in entry["changes"]

    def test_detects_permission_change(self, runner, baseline_path, tree):
        os.chmod(tree / "a.txt", 0o777)
        modified = diff_json(runner, baseline_path, tree)["modified"]

        entry = [m for m in modified if m["path"] == "a.txt"][0]
        assert "permissions" in entry["changes"]

    def test_restored_content_reads_as_unchanged(self, runner, baseline_path, tree):
        """Hash comparison means a reverted file is not flagged, unlike mtime."""
        (tree / "a.txt").write_text("something else")
        (tree / "a.txt").write_text("original")

        modified = diff_json(runner, baseline_path, tree)["modified"]
        content_changed = [m for m in modified if "content" in m["changes"]]
        assert content_changed == []

    def test_exit_code_signals_drift(self, runner, baseline_path, tree):
        assert runner.invoke(file, ["diff", str(baseline_path), "-d", str(tree)]).exit_code == 0

        (tree / "a.txt").write_text("TAMPERED")
        assert runner.invoke(file, ["diff", str(baseline_path), "-d", str(tree)]).exit_code == 1

    def test_rejects_corrupt_baseline(self, runner, tmp_path, tree):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json")

        result = runner.invoke(file, ["diff", str(bad), "-d", str(tree)])
        assert result.exit_code == 2

    def test_rejects_unknown_version(self, runner, tmp_path, tree):
        bad = tmp_path / "v99.json"
        bad.write_text(json.dumps({"version": 99, "root": str(tree), "files": {}}))

        result = runner.invoke(file, ["diff", str(bad), "-d", str(tree)])
        assert result.exit_code == 2

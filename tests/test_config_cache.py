"""Tests for configuration layering and the cache layer."""

import json
import stat

import pytest

from bsot.cache import CacheManager, cached
import bsot.cache as cache_module
from bsot.config import Config


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(Config, "CONFIG_FILE", tmp_path / "config.json")
    monkeypatch.setattr(Config, "PROFILES_DIR", tmp_path / "profiles")
    return tmp_path


class TestConfigLayering:
    def test_profile_write_does_not_copy_base_keys(self, cfg):
        base = Config()
        base.set("virustotal_api_key", "BASE-VT-KEY")

        prof = Config(profile="work")
        prof.set("abuseipdb_api_key", "WORK-ABUSE-KEY")

        on_disk = json.loads((cfg / "profiles" / "work.json").read_text())
        assert on_disk == {"abuseipdb_api_key": "WORK-ABUSE-KEY"}
        assert "virustotal_api_key" not in on_disk

    def test_profile_still_reads_through_to_base(self, cfg):
        Config().set("virustotal_api_key", "BASE-VT-KEY")
        prof = Config(profile="work")
        prof.set("abuseipdb_api_key", "WORK-KEY")

        assert prof.get("virustotal_api_key") == "BASE-VT-KEY"
        assert prof.get("abuseipdb_api_key") == "WORK-KEY"

    def test_profile_overrides_base(self, cfg):
        Config().set("virustotal_api_key", "BASE")
        prof = Config(profile="work")
        prof.set("virustotal_api_key", "OVERRIDE")

        assert prof.get("virustotal_api_key") == "OVERRIDE"
        assert Config().get("virustotal_api_key") == "BASE"

    def test_env_var_wins_over_file(self, cfg, monkeypatch):
        Config().set("virustotal_api_key", "FROM-FILE")
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "FROM-ENV")

        assert Config().get("virustotal_api_key") == "FROM-ENV"

    def test_corrupt_config_warns(self, cfg, capsys):
        (cfg / "config.json").write_text("{ this is not json")
        Config()

        assert "not valid JSON" in capsys.readouterr().err

    def test_config_file_is_private(self, cfg):
        Config().set("virustotal_api_key", "SECRET")
        mode = (cfg / "config.json").stat().st_mode

        assert not mode & stat.S_IRGRP
        assert not mode & stat.S_IROTH


class TestGetSettings:
    def test_omits_every_secret_shape(self, cfg):
        c = Config()
        c.set("virustotal_api_key", "x")
        c.set("censys_api_secret", "x")
        c.set("cloudflare_api_token", "x")
        c.set("report_llm_provider", "anthropic")

        settings = c.get_settings()
        assert settings == {"report_llm_provider": "anthropic"}


class TestCache:
    def test_roundtrip(self, tmp_path):
        c = CacheManager(cache_dir=tmp_path)
        c.set("virustotal", "1.2.3.4", {"malicious": 3})

        assert c.get("virustotal", "1.2.3.4") == {"malicious": 3}

    def test_expiry(self, tmp_path):
        c = CacheManager(cache_dir=tmp_path)
        c.set("virustotal", "1.2.3.4", {"malicious": 3}, ttl_hours=-1)

        assert c.get("virustotal", "1.2.3.4") is None

    def test_miss_returns_none(self, tmp_path):
        assert CacheManager(cache_dir=tmp_path).get("virustotal", "nope") is None

    def test_cache_files_are_private(self, tmp_path):
        c = CacheManager(cache_dir=tmp_path)
        c.set("virustotal", "1.2.3.4", {"malicious": 3})
        path = next(tmp_path.rglob("*.json"))

        assert not path.stat().st_mode & stat.S_IROTH

    def test_corrupt_entry_is_discarded(self, tmp_path):
        c = CacheManager(cache_dir=tmp_path)
        c.set("virustotal", "1.2.3.4", {"malicious": 3})
        next(tmp_path.rglob("*.json")).write_text("{corrupt")

        assert c.get("virustotal", "1.2.3.4") is None


class TestCachedDecorator:
    @pytest.fixture(autouse=True)
    def _isolate(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cache_module, "cache", CacheManager(cache_dir=tmp_path))

    def test_caches_method_by_first_real_arg(self):
        calls = []

        class Client:
            @cached("otx")
            def lookup(self, ioc):
                calls.append(ioc)
                return {"ioc": ioc}

        c = Client()
        assert c.lookup("1.2.3.4") == {"ioc": "1.2.3.4"}
        assert c.lookup("1.2.3.4") == {"ioc": "1.2.3.4"}
        assert calls == ["1.2.3.4"], "second call should have hit the cache"

    def test_distinct_args_are_distinct_entries(self):
        calls = []

        class Client:
            @cached("otx")
            def lookup(self, ioc):
                calls.append(ioc)
                return {"ioc": ioc}

        c = Client()
        c.lookup("1.1.1.1")
        c.lookup("2.2.2.2")
        assert calls == ["1.1.1.1", "2.2.2.2"]

    def test_no_cache_bypasses_and_is_not_forwarded(self):
        calls = []

        @cached("otx")
        def lookup(ioc):
            calls.append(ioc)
            return {"ioc": ioc}

        lookup("1.2.3.4")
        lookup("1.2.3.4", no_cache=True)
        assert calls == ["1.2.3.4", "1.2.3.4"]

    def test_preserves_function_metadata(self):
        @cached("otx")
        def lookup(ioc):
            """Look up an IOC."""
            return {}

        assert lookup.__name__ == "lookup"
        assert lookup.__doc__ == "Look up an IOC."

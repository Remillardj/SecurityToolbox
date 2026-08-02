"""Cache round-trip tests for every intel source.

Result classes expose derived values as properties (is_malicious, latitude,
score) that to_dict() emits but the constructor does not accept. Rebuilding a
cached entry with `Cls(**cached)` therefore raised TypeError on every cache
hit, so each source worked exactly once and then failed until its TTL expired.
"""

import dataclasses
import importlib

import pytest

from bsot.cache import from_cached


SOURCES = [
    ("bsot.intel.sources.virustotal", "VTResult"),
    ("bsot.intel.sources.abuseipdb", "AbuseIPDBResult"),
    ("bsot.intel.sources.otx", "OTXResult"),
    ("bsot.intel.sources.greynoise", "GreyNoiseResult"),
    ("bsot.intel.whois_client", "WHOISResult"),
    ("bsot.intel.sources.ipinfo", "IPInfoResult"),
]


def build(cls):
    """Instantiate with placeholders for every required field."""
    required = {
        f.name: "x"
        for f in dataclasses.fields(cls)
        if f.default is dataclasses.MISSING
        and f.default_factory is dataclasses.MISSING
    }
    return cls(**required)


@pytest.mark.parametrize("module,name", SOURCES, ids=[n for _, n in SOURCES])
class TestRoundTrip:
    def _cls(self, module, name):
        return getattr(importlib.import_module(module), name)

    def test_to_dict_then_from_cached(self, module, name):
        cls = self._cls(module, name)
        restored = from_cached(cls, build(cls).to_dict())

        assert isinstance(restored, cls)

    def test_declared_fields_survive(self, module, name):
        cls = self._cls(module, name)
        instance = build(cls)
        restored = from_cached(cls, instance.to_dict())

        emitted = instance.to_dict()
        for field in dataclasses.fields(cls):
            if field.name in emitted:
                assert getattr(restored, field.name) == emitted[field.name]

    def test_unknown_keys_are_ignored(self, module, name):
        cls = self._cls(module, name)
        payload = build(cls).to_dict()
        payload["a_field_that_does_not_exist"] = "boom"

        assert isinstance(from_cached(cls, payload), cls)


class TestHelper:
    def test_filters_to_declared_fields(self):
        @dataclasses.dataclass
        class Sample:
            a: str = ""

            @property
            def derived(self):
                return self.a.upper()

            def to_dict(self):
                return {"a": self.a, "derived": self.derived}

        restored = from_cached(Sample, Sample(a="x").to_dict())

        assert restored.a == "x"

    def test_missing_keys_use_defaults(self):
        @dataclasses.dataclass
        class Sample:
            a: str = "default"
            b: int = 7

        restored = from_cached(Sample, {"a": "set"})

        assert restored.a == "set"
        assert restored.b == 7

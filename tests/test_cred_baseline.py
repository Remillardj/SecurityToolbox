"""Baseline suppression for cred-scan: known findings are fingerprinted by
`file cred-baseline` and skipped by `file cred-scan --baseline`, so CI can
fail only on new secrets.

Writing the baseline is deliberately a separate command rather than a
cred-scan flag: cred-scan is granted READ_ONLY to the agent runtime, and a
write flag on it would smuggle an arbitrary-path filesystem write into that
grant (see safety.py's note on `file baseline`).
"""

import json

import pytest
from click.testing import CliRunner

from bsot.file.cli import file as file_group


# String pieces are concatenated so this test file's own source never matches
# the scanner's patterns when the repo scans itself.
PASSWORD_LINE = 'pass' + 'word = "s3cr3t-hunter2-value"\n'
AWS_KEY_LINE = 'key = "' + 'AKIA' + 'IOSFODNN7EXAMPLE' + '"\n'


@pytest.fixture
def runner():
    return CliRunner()


def plant(directory, name, content):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(content)


def scan(runner, *args):
    return runner.invoke(file_group, ['cred-scan', *args])


def write_baseline(runner, src, baseline):
    return runner.invoke(
        file_group, ['cred-baseline', str(src), '-o', str(baseline)])


def test_scan_without_baseline_still_fails_on_findings(runner, tmp_path):
    plant(tmp_path, 'config.py', PASSWORD_LINE)
    result = scan(runner, str(tmp_path), '--json')
    assert result.exit_code == 1


def test_write_baseline_then_rescan_is_clean(runner, tmp_path):
    plant(tmp_path / 'src', 'config.py', PASSWORD_LINE)
    baseline = tmp_path / 'baseline.json'

    written = write_baseline(runner, tmp_path / 'src', baseline)
    assert written.exit_code == 0
    assert baseline.exists()

    rescan = scan(runner, str(tmp_path / 'src'), '--baseline', str(baseline),
                  '--json')
    assert rescan.exit_code == 0
    payload = json.loads(rescan.output)
    assert payload['findings'] == []
    assert payload['suppressed'] >= 1


def test_new_secret_fails_even_with_baseline(runner, tmp_path):
    plant(tmp_path / 'src', 'config.py', PASSWORD_LINE)
    baseline = tmp_path / 'baseline.json'
    write_baseline(runner, tmp_path / 'src', baseline)

    plant(tmp_path / 'src', 'deploy.py', AWS_KEY_LINE)
    rescan = scan(runner, str(tmp_path / 'src'), '--baseline', str(baseline),
                  '--json')
    assert rescan.exit_code == 1
    payload = json.loads(rescan.output)
    assert len(payload['findings']) == 1
    assert payload['findings'][0]['type'] == 'aws_access_key'
    assert payload['suppressed'] >= 1


def test_baseline_survives_moving_the_scan_root(runner, tmp_path):
    # CI checks out to a different absolute path than the laptop that wrote
    # the baseline, so fingerprints must be relative to the scan root.
    plant(tmp_path / 'root_a' / 'src', 'config.py', PASSWORD_LINE)
    plant(tmp_path / 'root_b' / 'src', 'config.py', PASSWORD_LINE)
    baseline = tmp_path / 'baseline.json'

    write_baseline(runner, tmp_path / 'root_a', baseline)
    rescan = scan(runner, str(tmp_path / 'root_b'), '--baseline', str(baseline),
                  '--json')
    assert rescan.exit_code == 0
    assert json.loads(rescan.output)['findings'] == []


def test_baseline_file_stores_relative_paths_and_no_secret_text(runner, tmp_path):
    plant(tmp_path / 'src', 'config.py', PASSWORD_LINE)
    baseline = tmp_path / 'baseline.json'
    write_baseline(runner, tmp_path / 'src', baseline)

    payload = json.loads(baseline.read_text())
    assert payload['version'] == 1
    assert payload['findings']
    for entry in payload['findings']:
        assert entry['file'] == 'config.py'
        assert 's3cr3t' not in json.dumps(entry)
        assert len(entry['fingerprint']) == 64


def test_missing_baseline_file_is_an_error(runner, tmp_path):
    plant(tmp_path, 'config.py', PASSWORD_LINE)
    result = scan(runner, str(tmp_path), '--baseline',
                  str(tmp_path / 'missing.json'), '--json')
    assert result.exit_code == 2
    assert 'baseline not found' in result.output.lower()


def test_cred_scan_has_no_write_flag(runner, tmp_path):
    # The write stays out of cred-scan so its READ_ONLY agent tier holds.
    plant(tmp_path, 'config.py', PASSWORD_LINE)
    result = scan(runner, str(tmp_path), '--write-baseline')
    assert result.exit_code == 2
    assert 'no such option' in result.output.lower()


def test_cred_baseline_command_is_not_read_only_tiered():
    from bsot.agent.safety import Tier, tier_for

    assert tier_for(('file', 'cred-baseline')) is not Tier.READ_ONLY


def test_fingerprint_ignores_line_number():
    from bsot.file.secrets import SecretFinding, fingerprint_finding

    kwargs = dict(file_path='src/config.py', secret_type='password_assignment',
                  match='pass****lue', line_content='x', confidence='medium')
    moved = fingerprint_finding(SecretFinding(line_number=99, **kwargs), 'src')
    original = fingerprint_finding(SecretFinding(line_number=3, **kwargs), 'src')
    assert moved == original


def test_fingerprint_changes_when_match_changes():
    from bsot.file.secrets import SecretFinding, fingerprint_finding

    kwargs = dict(file_path='src/config.py', secret_type='password_assignment',
                  line_number=3, line_content='x', confidence='medium')
    a = fingerprint_finding(SecretFinding(match='pass****lue', **kwargs), 'src')
    b = fingerprint_finding(SecretFinding(match='pass****her', **kwargs), 'src')
    assert a != b

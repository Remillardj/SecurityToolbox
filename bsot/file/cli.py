"""
CLI commands for the file analysis module.
"""

import click
import sys
import json as json_lib
from pathlib import Path


@click.group()
def file():
    """File analysis and forensics tools."""
    pass


@file.command()
@click.argument('files', nargs=-1, required=True, type=click.Path(exists=True))
@click.option('--algo', '-a', default='sha256',
              help='Hash algorithm(s): md5, sha1, sha256, sha512, all (default: sha256)')
@click.option('--all', 'all_algos', is_flag=True, help='Calculate all hash algorithms')
@click.option('--verify', '-v', help='Verify against expected hash')
@click.option('--recursive', '-r', is_flag=True, help='Hash directories recursively')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def hash(files, algo, all_algos, verify, recursive, json_output):
    """
    Calculate file hashes.
    
    \b
    Examples:
        bsot file hash malware.exe
        bsot file hash file.txt --algo md5,sha256
        bsot file hash file.txt --all
        bsot file hash file.txt --verify abc123...
        bsot file hash ./directory -r
    """
    from .hasher import FileHasher
    from ..utils import Colors
    
    # Parse algorithms
    if all_algos:
        algorithms = ['all']
    else:
        algorithms = [a.strip() for a in algo.split(',')]
    
    hasher = FileHasher(algorithms)
    results = []
    
    for file_path in files:
        path = Path(file_path)
        
        if path.is_dir():
            if recursive:
                dir_results = hasher.hash_directory(str(path), recursive=True)
                results.extend(dir_results)
            else:
                click.echo(f"Skipping directory: {path} (use -r for recursive)", err=True)
        else:
            results.append(hasher.hash_file(str(path)))
    
    if verify and len(results) == 1:
        # Verify mode
        is_valid = hasher.verify(str(files[0]), verify)
        if json_output:
            click.echo(json_lib.dumps({
                'file': results[0].file_path,
                'expected': verify,
                'valid': is_valid
            }))
        else:
            if is_valid:
                click.echo(f"✅ Hash verified: {results[0].file_name}")
            else:
                click.echo(f"❌ Hash mismatch: {results[0].file_name}")
                sys.exit(1)
        return
    
    if json_output:
        output = [r.to_dict() for r in results]
        click.echo(json_lib.dumps(output, indent=2))
    else:
        for result in results:
            if result.error:
                click.echo(f"❌ {result.file_name}: {result.error}")
                continue
            
            click.echo(f"\n{Colors.CYAN}{result.file_name}{Colors.RESET}")
            click.echo(f"  Size: {result.file_size:,} bytes")
            for algo_name, hash_value in result.hashes.items():
                click.echo(f"  {algo_name.upper()}: {hash_value}")


@file.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def identify(file_path, json_output):
    """
    Identify file type by magic bytes.
    
    Detects file type regardless of extension and warns about mismatches.
    
    \b
    Examples:
        bsot file identify suspicious.pdf
        bsot file identify unknown_file --json
    """
    from .identifier import FileIdentifier
    from ..utils import Colors, print_finding
    
    identifier = FileIdentifier()
    result = identifier.identify(file_path)
    
    if json_output:
        click.echo(json_lib.dumps(result.to_dict(), indent=2))
        return
    
    if result.error:
        click.echo(f"❌ Error: {result.error}")
        sys.exit(2)
    
    click.echo(f"\n{Colors.CYAN}File:{Colors.RESET} {result.file_name}")
    click.echo(f"  Size: {result.file_size:,} bytes")
    click.echo(f"  MIME Type: {result.mime_type}")
    click.echo(f"  Description: {result.description}")
    click.echo(f"  Magic Bytes: {result.magic_bytes_hex}")
    
    if result.expected_extensions:
        click.echo(f"  Expected Extensions: {', '.join(result.expected_extensions)}")
    
    if result.extension_mismatch:
        click.echo()
        print_finding('high', 'Extension Mismatch Detected!')
        click.echo(f"    {result.mismatch_warning}")


@file.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--min-length', '-m', default=4, help='Minimum string length (default: 4)')
@click.option('--encoding', '-e', type=click.Choice(['ascii', 'unicode', 'both']), 
              default='both', help='String encoding to extract')
@click.option('--interesting', '-i', is_flag=True, 
              help='Only show interesting strings (URLs, IPs, paths, etc.)')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
@click.option('--max-strings', default=1000, help='Maximum strings to extract')
def strings(file_path, min_length, encoding, interesting, json_output, max_strings):
    """
    Extract printable strings from binary files.
    
    \b
    Examples:
        bsot file strings malware.exe
        bsot file strings binary --min-length 8
        bsot file strings binary --interesting
    """
    from .strings import StringExtractor
    from ..utils import Colors, print_subheader
    
    extractor = StringExtractor(
        min_length=min_length,
        encoding=encoding,
        interesting_only=interesting
    )
    
    result = extractor.extract(file_path, max_strings=max_strings)
    
    if json_output:
        click.echo(json_lib.dumps(result.to_dict(), indent=2))
        return
    
    if result.error:
        click.echo(f"❌ Error: {result.error}")
        sys.exit(2)
    
    click.echo(f"\n{Colors.CYAN}Strings from:{Colors.RESET} {result.file_path}")
    click.echo(f"  File size: {result.file_size:,} bytes")
    click.echo(f"  Strings found: {result.total_strings}")
    
    # Show categorized strings
    if result.urls:
        print_subheader(f"URLs ({len(result.urls)})")
        for url in result.urls[:20]:
            click.echo(f"  • {url}")
        if len(result.urls) > 20:
            click.echo(f"  ... and {len(result.urls) - 20} more")
    
    if result.ips:
        print_subheader(f"IP Addresses ({len(result.ips)})")
        for ip in result.ips[:20]:
            click.echo(f"  • {ip}")
    
    if result.emails:
        print_subheader(f"Emails ({len(result.emails)})")
        for email in result.emails[:10]:
            click.echo(f"  • {email}")
    
    if result.paths:
        print_subheader(f"File Paths ({len(result.paths)})")
        for path in result.paths[:20]:
            click.echo(f"  • {path}")
    
    if result.registry_keys:
        print_subheader(f"Registry Keys ({len(result.registry_keys)})")
        for key in result.registry_keys[:10]:
            click.echo(f"  • {key}")
    
    if result.interesting:
        print_subheader(f"Interesting Strings ({len(result.interesting)})")
        for s in result.interesting[:30]:
            click.echo(f"  • {s[:80]}{'...' if len(s) > 80 else ''}")
    
    # Show all strings if not interesting-only mode
    if not interesting and not (result.urls or result.ips or result.paths):
        print_subheader("All Strings")
        for s in result.strings[:50]:
            click.echo(f"  {s.offset:08x}: {s.value[:80]}{'...' if len(s.value) > 80 else ''}")
        if len(result.strings) > 50:
            click.echo(f"\n  ... and {len(result.strings) - 50} more (use --json for full output)")


@file.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--block-size', '-b', default=256, help='Block size for analysis (default: 256)')
@click.option('--blocks', is_flag=True, help='Show per-block analysis')
@click.option('--visualize', '-v', is_flag=True, help='Show ASCII visualization')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def entropy(file_path, block_size, blocks, visualize, json_output):
    """
    Calculate file entropy to detect packing/encryption.
    
    Entropy scale (0-8):
    - 0-5: Low (text, structured data)
    - 5-7: Normal (typical binaries)
    - 7-7.5: Medium-high (compressed)
    - 7.5-8: High (encrypted/random)
    
    \b
    Examples:
        bsot file entropy suspicious.exe
        bsot file entropy packed.bin --blocks --visualize
    """
    from .entropy import EntropyAnalyzer
    from ..utils import Colors, print_finding
    
    analyzer = EntropyAnalyzer(block_size=block_size)
    result = analyzer.analyze(file_path, analyze_blocks=blocks or visualize)
    
    if json_output:
        click.echo(json_lib.dumps(result.to_dict(), indent=2))
        return
    
    if result.error:
        click.echo(f"❌ Error: {result.error}")
        sys.exit(2)
    
    click.echo(f"\n{Colors.CYAN}Entropy Analysis:{Colors.RESET} {result.file_path}")
    click.echo(f"  File size: {result.file_size:,} bytes")
    
    # Overall entropy with color
    entropy_color = Colors.GREEN
    if result.verdict == "high":
        entropy_color = Colors.RED
    elif result.verdict == "medium-high":
        entropy_color = Colors.YELLOW
    
    click.echo(f"  Entropy: {entropy_color}{result.entropy:.4f}/8.0{Colors.RESET}")
    click.echo(f"  Verdict: {entropy_color}{result.verdict.upper()}{Colors.RESET}")
    
    if result.is_suspicious:
        click.echo()
        print_finding('high', 'High entropy detected - file may be encrypted, packed, or obfuscated')
    
    # Block statistics
    if blocks and result.block_entropies:
        click.echo(f"\n  Block Analysis (block size: {result.block_size}):")
        click.echo(f"    Min entropy: {result.min_entropy:.4f}")
        click.echo(f"    Max entropy: {result.max_entropy:.4f}")
        click.echo(f"    Avg entropy: {result.avg_entropy:.4f}")
        click.echo(f"    High entropy blocks: {result.high_entropy_blocks}")
    
    # Visualization
    if visualize:
        click.echo()
        viz = analyzer.visualize_entropy(result)
        click.echo(viz)


@file.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def metadata(file_path, json_output):
    """
    Extract metadata from files (images, PDFs, Office docs).
    
    \b
    Examples:
        bsot file metadata image.jpg
        bsot file metadata document.pdf
    """
    from ..utils import Colors, print_subheader
    
    path = Path(file_path)
    metadata = {}
    
    # Basic file info
    stat = path.stat()
    metadata['file'] = {
        'name': path.name,
        'size': stat.st_size,
        'created': stat.st_ctime,
        'modified': stat.st_mtime,
        'accessed': stat.st_atime,
    }
    
    suffix = path.suffix.lower()
    
    # Try EXIF for images
    if suffix in ['.jpg', '.jpeg', '.tiff', '.tif']:
        try:
            import exifread
            with open(path, 'rb') as f:
                tags = exifread.process_file(f, details=False)
                metadata['exif'] = {str(k): str(v) for k, v in tags.items() if not k.startswith('Thumbnail')}
        except ImportError:
            metadata['exif'] = {'error': 'exifread library not installed'}
        except Exception as e:
            metadata['exif'] = {'error': str(e)}
    
    # Try PDF metadata
    if suffix == '.pdf':
        try:
            import PyPDF2
            with open(path, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                info = reader.metadata
                if info:
                    metadata['pdf'] = {
                        'title': info.get('/Title', ''),
                        'author': info.get('/Author', ''),
                        'creator': info.get('/Creator', ''),
                        'producer': info.get('/Producer', ''),
                        'creation_date': str(info.get('/CreationDate', '')),
                        'modification_date': str(info.get('/ModDate', '')),
                        'pages': len(reader.pages),
                    }
        except ImportError:
            metadata['pdf'] = {'error': 'PyPDF2 library not installed'}
        except Exception as e:
            metadata['pdf'] = {'error': str(e)}
    
    if json_output:
        click.echo(json_lib.dumps(metadata, indent=2, default=str))
        return
    
    click.echo(f"\n{Colors.CYAN}Metadata:{Colors.RESET} {path.name}")
    
    # File info
    print_subheader("File Info")
    click.echo(f"  Size: {metadata['file']['size']:,} bytes")
    
    import datetime
    click.echo(f"  Modified: {datetime.datetime.fromtimestamp(metadata['file']['modified'])}")
    click.echo(f"  Created: {datetime.datetime.fromtimestamp(metadata['file']['created'])}")
    
    # Type-specific metadata
    if 'exif' in metadata:
        print_subheader("EXIF Data")
        exif = metadata['exif']
        if 'error' in exif:
            click.echo(f"  Error: {exif['error']}")
        else:
            for key, value in list(exif.items())[:20]:
                click.echo(f"  {key}: {value}")
    
    if 'pdf' in metadata:
        print_subheader("PDF Metadata")
        pdf = metadata['pdf']
        if 'error' in pdf:
            click.echo(f"  Error: {pdf['error']}")
        else:
            for key, value in pdf.items():
                if value:
                    click.echo(f"  {key.title()}: {value}")


@file.command('cred-scan')
@click.argument('path', type=click.Path(exists=True))
@click.option('--recursive', '-r', is_flag=True, default=True, help='Scan recursively (default: true)')
@click.option('--no-recursive', is_flag=True, help='Disable recursive scanning')
@click.option('--include-low', '-l', is_flag=True, help='Include low-confidence findings')
@click.option('--baseline', 'baseline_path', type=click.Path(),
              help='Baseline file of known findings to suppress (see cred-baseline)')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
@click.option('--quiet', '-q', is_flag=True, help='Only output on findings (for CI)')
def cred_scan(path, recursive, no_recursive, include_low, baseline_path,
              json_output, quiet):
    """
    Scan for hardcoded credentials and secrets.

    Detects API keys, private keys, passwords, tokens, and other secrets
    in source code and configuration files. Known-acceptable findings
    (detection patterns, documented placeholders) recorded by
    `bsot file cred-baseline` are suppressed via --baseline, so only new
    findings fail the scan.

    Exit codes:
      0 - No secrets found
      1 - Secrets detected
      2 - Error

    \b
    Examples:
        bsot file cred-scan .
        bsot file cred-scan src/ --json
        bsot file cred-scan . --include-low

    CI Usage:
        bsot file cred-scan . --baseline .secret-scan-baseline.json --json || exit 1
    """
    from .secrets import (
        ScanResult, SecretScanner, fingerprint_finding, load_baseline,
    )
    from ..utils import Colors, print_header, print_subheader

    scanner = SecretScanner(include_low_confidence=include_low)

    path_obj = Path(path)

    if path_obj.is_file():
        findings = scanner.scan_file(str(path_obj))
        result = ScanResult(
            files_scanned=1,
            files_with_secrets=1 if findings else 0,
            total_findings=len(findings),
            findings=findings,
        )
    else:
        # Directory scan
        result = scanner.scan_directory(
            str(path_obj),
            recursive=recursive and not no_recursive
        )

    # Fingerprints are relative to the scan root so baselines written on one
    # machine hold in CI, which checks out to a different absolute path.
    fingerprint_root = str(path_obj if path_obj.is_dir() else path_obj.parent)

    suppressed = 0
    if baseline_path:
        if not Path(baseline_path).is_file():
            click.echo(f"Error: baseline not found: {baseline_path}", err=True)
            sys.exit(2)
        try:
            known = load_baseline(baseline_path)
        except (OSError, ValueError, KeyError, TypeError) as e:
            click.echo(f"Error: could not read baseline: {e}", err=True)
            sys.exit(2)
        kept = [
            f for f in result.findings
            if fingerprint_finding(f, fingerprint_root) not in known
        ]
        suppressed = result.total_findings - len(kept)
        result.findings = kept
        result.total_findings = len(kept)
        result.files_with_secrets = len({f.file_path for f in kept})

    if json_output:
        payload = result.to_dict()
        if baseline_path:
            payload['suppressed'] = suppressed
        click.echo(json_lib.dumps(payload, indent=2))
        if result.total_findings > 0:
            sys.exit(1)
        return
    
    if quiet and result.total_findings == 0:
        sys.exit(0)
    
    if not quiet:
        print_header("Secret Scan Results")
        click.echo(f"  Path: {path}")
        click.echo(f"  Files scanned: {result.files_scanned}")
        click.echo(f"  Files with secrets: {result.files_with_secrets}")
        click.echo(f"  Total findings: {result.total_findings}")
        if baseline_path:
            click.echo(f"  Suppressed by baseline: {suppressed}")
    
    if result.total_findings > 0:
        if not quiet:
            print_subheader("Findings")
        
        # Group by file
        findings_by_file = {}
        for finding in result.findings:
            if finding.file_path not in findings_by_file:
                findings_by_file[finding.file_path] = []
            findings_by_file[finding.file_path].append(finding)
        
        for file_path, findings in findings_by_file.items():
            rel_path = Path(file_path).relative_to(Path.cwd()) if file_path.startswith(str(Path.cwd())) else file_path
            click.echo(f"\n  {Colors.CYAN}{rel_path}{Colors.RESET}")
            
            for f in findings:
                conf_color = Colors.RED if f.confidence == 'high' else (Colors.YELLOW if f.confidence == 'medium' else Colors.RESET)
                click.echo(f"    Line {f.line_number}: {conf_color}[{f.confidence.upper()}]{Colors.RESET} {f.secret_type}")
                click.echo(f"      Match: {f.match}")
        
        click.echo()
        
        if not quiet:
            click.echo(f"  {Colors.RED}⚠️  {result.total_findings} secret(s) detected!{Colors.RESET}")
            click.echo(f"  {Colors.YELLOW}   Review and remove before committing.{Colors.RESET}")
        
        sys.exit(1)
    else:
        if not quiet:
            click.echo(f"\n  {Colors.GREEN}✓ No secrets found{Colors.RESET}")
        click.echo()


@file.command('cred-baseline')
@click.argument('path', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), required=True,
              help='Baseline file to write')
@click.option('--include-low', '-l', is_flag=True, help='Include low-confidence findings')
def cred_baseline(path, output, include_low):
    """
    Record current cred-scan findings as a baseline of accepted matches.

    Each finding is stored as a fingerprint (no secret text, redacted or
    otherwise), keyed to its file and pattern but not its line number, so
    unrelated edits don't invalidate the baseline. cred-scan --baseline then
    fails only on findings not recorded here.

    Kept separate from cred-scan itself so cred-scan never writes to disk
    (matters to the agent runtime's read-only tiering; same reasoning as
    `file baseline` vs `file diff`).

    \b
    Examples:
        bsot file cred-baseline . -o .secret-scan-baseline.json
    """
    from .secrets import SecretScanner, write_baseline
    from ..utils import Colors

    scanner = SecretScanner(include_low_confidence=include_low)
    path_obj = Path(path)

    if path_obj.is_file():
        findings = scanner.scan_file(str(path_obj))
    else:
        findings = scanner.scan_directory(str(path_obj)).findings

    root = str(path_obj if path_obj.is_dir() else path_obj.parent)
    count = write_baseline(output, findings, root)
    click.echo(f"Baseline written: {output} ({count} fingerprint(s))")


@file.command()
@click.argument('directory', type=click.Path(exists=True))
@click.option('--recursive/--no-recursive', default=True, help='Scan subdirectories (default: recursive)')
@click.option('--group-writable', is_flag=True, help='Also report group-writable files')
@click.option('--all', 'show_all', is_flag=True, help='Show every file, not just risky ones')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def permissions(directory, recursive, group_writable, show_all, json_output):
    """
    Scan for files with overly permissive permissions.

    \b
    Flags world-writable files (anyone on the host can modify them), plus
    world-writable directories missing the sticky bit. Use --group-writable
    to also report group-writable files.

    \b
    Examples:
        bsot file permissions /var/www
        bsot file permissions /etc --group-writable
        bsot file permissions /srv --json
    """
    import os
    import stat as stat_mod
    from ..utils import Colors, print_header

    root_path = Path(directory)
    findings = []
    scanned = 0
    errors = 0

    def classify(path, st):
        """Return (severity, reason) for a risky mode, or None if fine."""
        mode = st.st_mode
        is_dir = stat_mod.S_ISDIR(mode)

        if mode & stat_mod.S_IWOTH:
            # A world-writable directory is expected for shared temp dirs, but
            # only when the sticky bit stops users deleting each other's files.
            if is_dir and not (mode & stat_mod.S_ISVTX):
                return 'high', 'world-writable directory without sticky bit'
            if not is_dir:
                if mode & stat_mod.S_IXOTH:
                    return 'critical', 'world-writable executable'
                return 'high', 'world-writable file'
        if group_writable and mode & stat_mod.S_IWGRP and not is_dir:
            return 'medium', 'group-writable file'
        return None

    def record(path):
        nonlocal scanned, errors
        try:
            st = os.lstat(path)
        except OSError:
            errors += 1
            return
        # Symlink permission bits are meaningless; the target is what matters.
        if stat_mod.S_ISLNK(st.st_mode):
            return
        scanned += 1
        verdict = classify(path, st)
        if verdict:
            severity, reason = verdict
            findings.append({
                'path': str(path),
                'mode': oct(st.st_mode & 0o7777)[2:].rjust(4, '0'),
                'severity': severity,
                'reason': reason,
                'uid': st.st_uid,
                'gid': st.st_gid,
            })
        elif show_all:
            findings.append({
                'path': str(path),
                'mode': oct(st.st_mode & 0o7777)[2:].rjust(4, '0'),
                'severity': 'ok',
                'reason': 'no issue',
                'uid': st.st_uid,
                'gid': st.st_gid,
            })

    if recursive:
        for dirpath, _dirnames, filenames in os.walk(root_path, onerror=lambda e: None):
            record(Path(dirpath))
            for name in filenames:
                record(Path(dirpath) / name)
    else:
        record(root_path)
        try:
            for entry in root_path.iterdir():
                record(entry)
        except OSError:
            errors += 1

    risky = [f for f in findings if f['severity'] != 'ok']

    if json_output:
        click.echo(json_lib.dumps({
            'directory': str(root_path),
            'scanned': scanned,
            'unreadable': errors,
            'findings': findings,
            'risky_count': len(risky),
        }, indent=2))
    else:
        print_header(f"Permission Scan: {root_path}")
        colors = {
            'critical': Colors.RED + Colors.BOLD,
            'high': Colors.RED,
            'medium': Colors.YELLOW,
            'ok': Colors.GREEN,
        }
        for f in findings:
            c = colors.get(f['severity'], Colors.WHITE)
            click.echo(f"  {c}{f['mode']}{Colors.RESET}  {f['path']}")
            if f['severity'] != 'ok':
                click.echo(f"          {Colors.DIM}{f['reason']}{Colors.RESET}")
        click.echo()
        click.echo(f"  Scanned {scanned} path(s); {len(risky)} risky.")
        if errors:
            click.echo(f"  {Colors.DIM}{errors} path(s) unreadable{Colors.RESET}")
        click.echo()

    if risky:
        sys.exit(1)


@file.command('suid-finder')
@click.argument('directory', default='/usr/bin', type=click.Path(exists=True))
@click.option('--known/--no-known', default=True,
              help='Annotate binaries known to ship SUID (default: annotate)')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def suid_finder(directory, known, json_output):
    """
    Find SUID/SGID binaries (privilege escalation vectors).

    \b
    Examples:
        bsot file suid-finder
        bsot file suid-finder /usr --json
    """
    import os
    import stat as stat_mod
    from ..utils import Colors, print_header

    # Binaries that legitimately ship SUID on most systems. Anything outside
    # this set on a normal host is worth a closer look.
    EXPECTED = {
        'sudo', 'su', 'passwd', 'chsh', 'chfn', 'newgrp', 'gpasswd', 'mount',
        'umount', 'ping', 'ping6', 'pkexec', 'fusermount', 'fusermount3',
        'ksu', 'at', 'atq', 'atrm', 'batch', 'crontab', 'screen', 'wall',
        'write', 'login', 'authopen', 'traceroute', 'traceroute6', 'quota',
        'top', 'df', 'unix_chkpwd', 'utempter', 'expiry', 'chage',
    }

    results = []
    for dirpath, _dirnames, filenames in os.walk(directory, onerror=lambda e: None):
        for name in filenames:
            path = Path(dirpath) / name
            try:
                st = os.lstat(path)
            except OSError:
                continue
            if stat_mod.S_ISLNK(st.st_mode):
                continue
            mode = st.st_mode
            bits = []
            if mode & stat_mod.S_ISUID:
                bits.append('suid')
            if mode & stat_mod.S_ISGID:
                bits.append('sgid')
            if not bits:
                continue
            results.append({
                'path': str(path),
                'name': name,
                'bits': bits,
                'mode': oct(mode & 0o7777)[2:].rjust(4, '0'),
                'uid': st.st_uid,
                'gid': st.st_gid,
                'size': st.st_size,
                'expected': name in EXPECTED,
            })

    unexpected = [r for r in results if not r['expected']]

    if json_output:
        click.echo(json_lib.dumps({
            'directory': directory,
            'count': len(results),
            'unexpected_count': len(unexpected),
            'binaries': results,
        }, indent=2))
    else:
        print_header(f"SUID/SGID Scan: {directory}")
        if not results:
            click.echo(f"  {Colors.GREEN}No SUID/SGID binaries found{Colors.RESET}\n")
        else:
            for r in sorted(results, key=lambda x: (x['expected'], x['path'])):
                tag = ','.join(b.upper() for b in r['bits'])
                if known and r['expected']:
                    marker = f"{Colors.DIM}(expected){Colors.RESET}"
                    color = Colors.DIM
                else:
                    marker = f"{Colors.RED}◀ review{Colors.RESET}"
                    color = Colors.YELLOW
                click.echo(f"  {color}{r['mode']} {tag:9s}{Colors.RESET} {r['path']} {marker}")
            click.echo()
            click.echo(f"  {len(results)} SUID/SGID binary(ies); {len(unexpected)} not in the expected set.")
            click.echo()

    if unexpected:
        sys.exit(1)


def _walk_for_baseline(root: Path, exclude: tuple) -> list:
    """Yield (relative_path, absolute_path) for every regular file under root."""
    import fnmatch
    import os

    entries = []
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        # Prune excluded directories in place so os.walk skips descending.
        dirnames[:] = [
            d for d in dirnames
            if not any(fnmatch.fnmatch(d, pat) for pat in exclude)
        ]
        for name in filenames:
            if any(fnmatch.fnmatch(name, pat) for pat in exclude):
                continue
            absolute = Path(dirpath) / name
            if absolute.is_symlink() or not absolute.is_file():
                continue
            entries.append((str(absolute.relative_to(root)), absolute))
    return sorted(entries)


def _hash_file(path: Path, algo: str = 'sha256') -> str:
    import hashlib

    digest = hashlib.new(algo)
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


@file.command()
@click.argument('directory', type=click.Path(exists=True, file_okay=False))
@click.option('--output', '-o', type=click.Path(), required=True, help='Baseline file to write')
@click.option('--algo', default='sha256', show_default=True, help='Hash algorithm')
@click.option('--exclude', multiple=True,
              default=('.git', '__pycache__', '*.pyc', '.DS_Store', 'node_modules', '.venv'),
              show_default=True, help='Glob patterns to skip (repeatable)')
def baseline(directory, output, algo, exclude):
    """
    Record a hash manifest of a directory for later integrity checking.

    \b
    Examples:
        bsot file baseline /etc -o etc-baseline.json
        bsot file baseline /var/www -o www.json --exclude '*.log'
    """
    from datetime import datetime, timezone
    import platform
    from ..utils import Colors, print_header

    root = Path(directory).resolve()
    entries = _walk_for_baseline(root, exclude)

    files = {}
    unreadable = []
    for relative, absolute in entries:
        try:
            stat_result = absolute.stat()
            files[relative] = {
                'sha256' if algo == 'sha256' else algo: _hash_file(absolute, algo),
                'size': stat_result.st_size,
                'mode': oct(stat_result.st_mode & 0o7777)[2:].rjust(4, '0'),
                'mtime': int(stat_result.st_mtime),
            }
        except (OSError, PermissionError) as e:
            unreadable.append({'path': relative, 'error': str(e)})

    manifest = {
        'version': 1,
        'root': str(root),
        'algorithm': algo,
        'created_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'hostname': platform.node(),
        'exclude': list(exclude),
        'file_count': len(files),
        'files': files,
        'unreadable': unreadable,
    }

    Path(output).write_text(json_lib.dumps(manifest, indent=2))

    print_header(f"Baseline: {root}")
    click.echo(f"  Hashed {len(files)} file(s) with {algo}.")
    if unreadable:
        click.echo(f"  {Colors.YELLOW}{len(unreadable)} file(s) unreadable.{Colors.RESET}")
    click.echo(f"  Written to {output}")
    click.echo()


@file.command()
@click.argument('baseline_file', type=click.Path(exists=True, dir_okay=False))
@click.option('--directory', '-d', type=click.Path(exists=True, file_okay=False),
              help='Directory to compare (default: the path recorded in the baseline)')
@click.option('--ignore-mtime', is_flag=True, help='Ignore modification-time-only changes')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def diff(baseline_file, directory, ignore_mtime, json_output):
    """
    Compare a directory against a baseline manifest.

    \b
    Reports added, removed, and modified files. Content changes are detected
    by hash, so a file restored to its original bytes reads as unchanged even
    if its timestamps moved.

    \b
    Examples:
        bsot file diff etc-baseline.json
        bsot file diff www.json -d /var/www --json
    """
    from ..utils import Colors, print_header, print_subheader

    try:
        manifest = json_lib.loads(Path(baseline_file).read_text())
    except (json_lib.JSONDecodeError, OSError) as e:
        click.echo(f"Error: could not read baseline: {e}", err=True)
        sys.exit(2)

    if manifest.get('version') != 1:
        click.echo(f"Error: unsupported baseline version {manifest.get('version')}.", err=True)
        sys.exit(2)

    root = Path(directory).resolve() if directory else Path(manifest['root'])
    if not root.is_dir():
        click.echo(f"Error: {root} is not a directory. Pass -d to compare elsewhere.", err=True)
        sys.exit(2)

    algo = manifest.get('algorithm', 'sha256')
    hash_field = 'sha256' if algo == 'sha256' else algo
    recorded = manifest['files']
    exclude = tuple(manifest.get('exclude', ()))

    current = {}
    for relative, absolute in _walk_for_baseline(root, exclude):
        try:
            stat_result = absolute.stat()
            current[relative] = {
                hash_field: _hash_file(absolute, algo),
                'size': stat_result.st_size,
                'mode': oct(stat_result.st_mode & 0o7777)[2:].rjust(4, '0'),
                'mtime': int(stat_result.st_mtime),
            }
        except (OSError, PermissionError):
            continue

    added = sorted(set(current) - set(recorded))
    removed = sorted(set(recorded) - set(current))
    modified = []

    for path in sorted(set(recorded) & set(current)):
        before, after = recorded[path], current[path]
        changes = []
        if before.get(hash_field) != after.get(hash_field):
            changes.append('content')
        if before.get('mode') != after.get('mode'):
            changes.append('permissions')
        if not ignore_mtime and before.get('mtime') != after.get('mtime') and not changes:
            # A timestamp move with identical content is worth noting but is
            # not tampering on its own.
            changes.append('mtime only')
        if changes:
            modified.append({
                'path': path,
                'changes': changes,
                'before': before,
                'after': after,
            })

    content_changes = [m for m in modified if 'content' in m['changes']]
    drifted = bool(added or removed or content_changes
                   or [m for m in modified if 'permissions' in m['changes']])

    if json_output:
        click.echo(json_lib.dumps({
            'baseline': baseline_file,
            'root': str(root),
            'baseline_created_at': manifest.get('created_at'),
            'added': added,
            'removed': removed,
            'modified': modified,
            'summary': {
                'added': len(added),
                'removed': len(removed),
                'modified': len(modified),
                'content_changed': len(content_changes),
            },
        }, indent=2))
    else:
        print_header(f"Baseline Diff: {root}")
        click.echo(f"  Baseline taken {manifest.get('created_at', 'unknown')}\n")

        if added:
            print_subheader(f"Added ({len(added)})")
            for path in added[:50]:
                click.echo(f"  {Colors.GREEN}+ {path}{Colors.RESET}")
            if len(added) > 50:
                click.echo(f"  {Colors.DIM}... and {len(added) - 50} more{Colors.RESET}")

        if removed:
            print_subheader(f"Removed ({len(removed)})")
            for path in removed[:50]:
                click.echo(f"  {Colors.RED}- {path}{Colors.RESET}")
            if len(removed) > 50:
                click.echo(f"  {Colors.DIM}... and {len(removed) - 50} more{Colors.RESET}")

        if modified:
            print_subheader(f"Modified ({len(modified)})")
            for entry in modified[:50]:
                marker = Colors.RED if 'content' in entry['changes'] else Colors.YELLOW
                click.echo(f"  {marker}~ {entry['path']}{Colors.RESET}"
                           f" {Colors.DIM}({', '.join(entry['changes'])}){Colors.RESET}")
            if len(modified) > 50:
                click.echo(f"  {Colors.DIM}... and {len(modified) - 50} more{Colors.RESET}")

        if not (added or removed or modified):
            click.echo(f"  {Colors.GREEN}No changes detected.{Colors.RESET}")

        click.echo()
        click.echo(f"  {len(added)} added, {len(removed)} removed, "
                   f"{len(modified)} modified ({len(content_changes)} content changes).")
        click.echo()

    if drifted:
        sys.exit(1)

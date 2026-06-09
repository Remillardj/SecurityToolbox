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
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
@click.option('--quiet', '-q', is_flag=True, help='Only output on findings (for CI)')
def cred_scan(path, recursive, no_recursive, include_low, json_output, quiet):
    """
    Scan for hardcoded credentials and secrets.
    
    Detects API keys, private keys, passwords, tokens, and other secrets
    in source code and configuration files.
    
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
        bsot file cred-scan . --quiet --json > secrets.json || exit 1
    """
    from .secrets import SecretScanner
    from ..utils import Colors, print_header, print_subheader
    
    scanner = SecretScanner(include_low_confidence=include_low)
    
    path_obj = Path(path)
    
    if path_obj.is_file():
        # Single file scan
        findings = scanner.scan_file(str(path_obj))
        result = type('ScanResult', (), {
            'files_scanned': 1,
            'files_with_secrets': 1 if findings else 0,
            'total_findings': len(findings),
            'findings': findings,
            'errors': [],
            'to_dict': lambda self: {
                'files_scanned': 1,
                'files_with_secrets': 1 if findings else 0,
                'total_findings': len(findings),
                'findings': [f.to_dict() for f in findings],
                'errors': [],
            }
        })()
    else:
        # Directory scan
        result = scanner.scan_directory(
            str(path_obj),
            recursive=recursive and not no_recursive
        )
    
    if json_output:
        click.echo(json_lib.dumps(result.to_dict(), indent=2))
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


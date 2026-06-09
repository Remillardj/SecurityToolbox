"""
CLI commands for the data utilities module.
"""

import click
import sys
import json as json_lib
import hashlib


@click.group()
def data():
    """Data encoding/decoding and transformation utilities."""
    pass


@data.command()
@click.argument('encoding')
@click.argument('value', required=False)
@click.option('--file', '-f', 'input_file', type=click.Path(exists=True), help='Read from file')
@click.option('--chain', help='Chain decodings: "base64,url" decodes base64 then URL')
def decode(encoding, value, input_file, chain):
    """
    Decode encoded data.
    
    Supported encodings: base64, url, hex, html, unicode-escape, rot13, punycode
    
    \b
    Examples:
        bsot data decode base64 SGVsbG8gV29ybGQ=
        bsot data decode url "hello%20world"
        bsot data decode hex 48656c6c6f
        echo "SGVsbG8=" | bsot data decode base64 -
    """
    from .encoders import decode as do_decode, decode_chain, ENCODINGS
    
    # Get input
    if value == '-' or (not value and not input_file):
        value = sys.stdin.read().strip()
    elif input_file:
        with open(input_file, 'r') as f:
            value = f.read()
    
    if not value:
        click.echo("Error: No input provided", err=True)
        sys.exit(2)
    
    try:
        if chain:
            encodings = [e.strip() for e in chain.split(',')]
            result = decode_chain(value, encodings)
        else:
            if encoding.lower() not in ENCODINGS:
                click.echo(f"Error: Unknown encoding '{encoding}'", err=True)
                click.echo(f"Supported: {', '.join(ENCODINGS)}", err=True)
                sys.exit(2)
            result = do_decode(value, encoding)
        
        click.echo(result)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@data.command()
@click.argument('encoding')
@click.argument('value', required=False)
@click.option('--file', '-f', 'input_file', type=click.Path(exists=True), help='Read from file')
def encode(encoding, value, input_file):
    """
    Encode data.
    
    Supported encodings: base64, url, hex, html, unicode-escape, rot13, punycode
    
    \b
    Examples:
        bsot data encode base64 "Hello World"
        bsot data encode url "hello world"
        bsot data encode hex "Hello"
    """
    from .encoders import encode as do_encode, ENCODINGS
    
    # Get input
    if value == '-' or (not value and not input_file):
        value = sys.stdin.read().rstrip('\n')
    elif input_file:
        with open(input_file, 'r') as f:
            value = f.read()
    
    if not value:
        click.echo("Error: No input provided", err=True)
        sys.exit(2)
    
    if encoding.lower() not in ENCODINGS:
        click.echo(f"Error: Unknown encoding '{encoding}'", err=True)
        click.echo(f"Supported: {', '.join(ENCODINGS)}", err=True)
        sys.exit(2)
    
    try:
        result = do_encode(value, encoding)
        click.echo(result)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@data.command()
@click.argument('value', required=False)
@click.option('--to', 'output_format', 
              type=click.Choice(['unix', 'unix-ms', 'iso', 'human', 'all']),
              default='all', help='Output format')
@click.option('--timezone', '-tz', default='UTC', help='Target timezone')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def timestamp(value, output_format, timezone, json_output):
    """
    Parse and convert timestamps.
    
    Auto-detects input format:
    - Unix epoch (seconds/milliseconds)
    - ISO8601
    - Common date formats
    
    \b
    Examples:
        bsot data timestamp 1703462400
        bsot data timestamp "2024-12-25T00:00:00Z"
        bsot data timestamp "12/25/2024" --to iso
        bsot data timestamp now
    """
    from .timestamp import parse_timestamp, now_formats
    from ..utils import Colors
    
    # Handle 'now'
    if not value or value.lower() == 'now':
        if json_output:
            click.echo(json_lib.dumps(now_formats(), indent=2))
        else:
            formats = now_formats()
            click.echo(f"\n{Colors.CYAN}Current Time:{Colors.RESET}")
            for key, val in formats.items():
                click.echo(f"  {key}: {val}")
        return
    
    result = parse_timestamp(value, timezone)
    
    if json_output:
        click.echo(json_lib.dumps(result.to_dict(), indent=2))
        return
    
    if not result.valid:
        click.echo(f"Error: {result.error}", err=True)
        sys.exit(1)
    
    if output_format == 'all':
        click.echo(f"\n{Colors.CYAN}Timestamp Conversion:{Colors.RESET}")
        click.echo(f"  Original:  {result.original}")
        click.echo(f"  Unix:      {result.unix}")
        click.echo(f"  Unix (ms): {result.unix_ms}")
        click.echo(f"  ISO8601:   {result.iso8601}")
        click.echo(f"  Human:     {result.human}")
        click.echo(f"  Relative:  {result.relative}")
        click.echo(f"  Timezone:  {result.timezone_name}")
    else:
        from .timestamp import convert_timestamp
        click.echo(convert_timestamp(value, output_format, timezone))


@data.command()
@click.argument('algorithm')
@click.argument('value', required=False)
@click.option('--file', '-f', 'input_file', type=click.Path(exists=True), help='Hash file instead of string')
def hash(algorithm, value, input_file):
    """
    Calculate hash of data.
    
    Algorithms: md5, sha1, sha256, sha512
    
    \b
    Examples:
        bsot data hash sha256 "test string"
        bsot data hash md5 -f myfile.txt
        echo "test" | bsot data hash sha256 -
    """
    algorithms = ['md5', 'sha1', 'sha256', 'sha512']
    
    if algorithm.lower() not in algorithms:
        click.echo(f"Error: Unknown algorithm '{algorithm}'", err=True)
        click.echo(f"Supported: {', '.join(algorithms)}", err=True)
        sys.exit(2)
    
    if input_file:
        # Hash file
        hasher = hashlib.new(algorithm.lower())
        with open(input_file, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                hasher.update(chunk)
        click.echo(hasher.hexdigest())
    else:
        # Hash string
        if value == '-' or not value:
            value = sys.stdin.read().rstrip('\n')
        
        if not value:
            click.echo("Error: No input provided", err=True)
            sys.exit(2)
        
        result = hashlib.new(algorithm.lower(), value.encode()).hexdigest()
        click.echo(result)


@data.command()
@click.argument('pattern')
@click.option('--file', '-f', 'input_file', type=click.Path(exists=True), help='Test against file')
@click.option('--test', '-t', 'test_string', help='Test against string')
@click.option('--highlight', is_flag=True, help='Highlight matches')
def regex(pattern, input_file, test_string, highlight):
    """
    Test regex patterns.
    
    \b
    Examples:
        bsot data regex "\\d+" --test "abc123def456"
        bsot data regex "error|warning" -f logfile.txt
    """
    import re
    from ..utils import Colors
    
    try:
        compiled = re.compile(pattern)
    except re.error as e:
        click.echo(f"Invalid regex: {e}", err=True)
        sys.exit(2)
    
    # Get test data
    if input_file:
        with open(input_file, 'r') as f:
            test_data = f.read()
    elif test_string:
        test_data = test_string
    else:
        test_data = sys.stdin.read()
    
    # Find matches
    matches = list(compiled.finditer(test_data))
    
    click.echo(f"\n{Colors.CYAN}Pattern:{Colors.RESET} {pattern}")
    click.echo(f"{Colors.CYAN}Matches:{Colors.RESET} {len(matches)}")
    
    if matches:
        click.echo(f"\n{Colors.CYAN}Results:{Colors.RESET}")
        
        for i, match in enumerate(matches[:50]):
            line_start = test_data.rfind('\n', 0, match.start()) + 1
            line_end = test_data.find('\n', match.end())
            if line_end == -1:
                line_end = len(test_data)
            
            line = test_data[line_start:line_end]
            line_num = test_data[:match.start()].count('\n') + 1
            
            if highlight:
                # Highlight match in line
                match_start = match.start() - line_start
                match_end = match.end() - line_start
                highlighted = (
                    line[:match_start] +
                    Colors.RED + Colors.BOLD +
                    line[match_start:match_end] +
                    Colors.RESET +
                    line[match_end:]
                )
                click.echo(f"  {line_num}: {highlighted}")
            else:
                click.echo(f"  {line_num}:{match.start()}: {match.group()}")
            
            # Show groups if any
            if match.groups():
                for j, group in enumerate(match.groups(), 1):
                    click.echo(f"      Group {j}: {group}")
        
        if len(matches) > 50:
            click.echo(f"\n  ... and {len(matches) - 50} more matches")


@data.command()
@click.argument('type', type=click.Choice(['json', 'xml', 'html']))
@click.argument('value', required=False)
@click.option('--file', '-f', 'input_file', type=click.Path(exists=True), help='Input file')
@click.option('--minify', is_flag=True, help='Minify instead of prettify')
@click.option('--sort-keys', is_flag=True, help='Sort object keys (JSON)')
def format(type, value, input_file, minify, sort_keys):
    """
    Format/prettify data.
    
    \b
    Examples:
        bsot data format json '{"a":1}'
        bsot data format json -f data.json
        echo '{"a":1}' | bsot data format json
        bsot data format json -f data.json --minify
    """
    # Get input
    if input_file:
        with open(input_file, 'r') as f:
            data = f.read()
    elif value and value != '-':
        data = value
    else:
        data = sys.stdin.read()
    
    if not data.strip():
        click.echo("Error: No input provided", err=True)
        sys.exit(2)
    
    try:
        if type == 'json':
            parsed = json_lib.loads(data)
            if minify:
                result = json_lib.dumps(parsed, separators=(',', ':'), sort_keys=sort_keys)
            else:
                result = json_lib.dumps(parsed, indent=2, sort_keys=sort_keys)
        
        elif type == 'xml':
            try:
                import xml.dom.minidom
                dom = xml.dom.minidom.parseString(data)
                if minify:
                    result = dom.toxml()
                else:
                    result = dom.toprettyxml(indent='  ')
            except Exception as e:
                click.echo(f"XML parse error: {e}", err=True)
                sys.exit(1)
        
        elif type == 'html':
            try:
                from html.parser import HTMLParser
                # Basic HTML formatting - just output as-is for now
                result = data
            except Exception as e:
                click.echo(f"HTML parse error: {e}", err=True)
                sys.exit(1)
        
        click.echo(result)
        
    except json_lib.JSONDecodeError as e:
        click.echo(f"JSON parse error: {e}", err=True)
        sys.exit(1)


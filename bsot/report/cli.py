"""
CLI commands for the report module.
Includes case management and report generation commands.
"""

import click
import sys
import json as json_lib
from pathlib import Path
from datetime import datetime


# ============================================================================
# Case Commands
# ============================================================================

@click.group()
def case():
    """Investigation case management."""
    pass


@case.command('new')
@click.argument('name')
@click.option('--type', '-t', 'case_type', default='general',
              type=click.Choice(['general', 'phishing', 'malware', 'intrusion', 'insider', 'apt']),
              help='Case type')
@click.option('--description', '-d', default='', help='Case description')
@click.option('--analyst', '-a', default='', help='Analyst name')
@click.option('--severity', '-s', default='medium',
              type=click.Choice(['low', 'medium', 'high', 'critical']),
              help='Case severity')
@click.option('--tags', default='', help='Comma-separated tags')
def case_new(name, case_type, description, analyst, severity, tags):
    """
    Create a new investigation case.
    
    Creates a case directory with proper structure and sets it as active.
    
    \b
    Examples:
        bsot case new phishing-2025-01-15
        bsot case new "Emotet Investigation" --type malware
        bsot case new supply-chain-compromise --type apt --severity critical
    """
    from .case_manager import CaseManager
    from ..utils import Colors
    from ..config import config
    
    # Get default analyst from config
    if not analyst:
        analyst = config.get('default_analyst', '')
    
    # Parse tags
    tag_list = [t.strip() for t in tags.split(',') if t.strip()] if tags else []
    
    manager = CaseManager()
    
    try:
        case_obj = manager.create(
            name=name,
            case_type=case_type,
            description=description,
            analyst=analyst,
            tags=tag_list,
            severity=severity,
        )
        
        click.echo(f"\n📁 {Colors.GREEN}Case created:{Colors.RESET} {case_obj.name}")
        click.echo(f"   Location: {case_obj.path}")
        click.echo(f"   Status: {Colors.CYAN}active{Colors.RESET}")
        click.echo()
        click.echo("   All BSOT command outputs will be saved to this case.")
        click.echo("   Run `bsot case close` when investigation is complete.")
        click.echo()
        
    except ValueError as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@case.command('list')
@click.option('--status', '-s', type=click.Choice(['active', 'closed', 'archived']),
              help='Filter by status')
@click.option('--recent', '-r', type=int, help='Show only N most recent cases')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def case_list(status, recent, json_output):
    """
    List all cases.
    
    \b
    Examples:
        bsot case list
        bsot case list --status active
        bsot case list --recent 10
    """
    from .case_manager import CaseManager
    from ..utils import Colors
    
    manager = CaseManager()
    cases = manager.list_cases(status=status, recent=recent)
    active_case = manager.get_active()
    active_name = active_case.name if active_case else None
    
    if json_output:
        click.echo(json_lib.dumps([c.to_dict() for c in cases], indent=2))
        return
    
    if not cases:
        click.echo("\n📋 No cases found.")
        click.echo("   Create one with: bsot case new <name>")
        click.echo()
        return
    
    click.echo("\n📋 Cases\n")
    click.echo(f"   {'Name':<30} {'Status':<10} {'Created':<12} {'Artifacts':<10} {'IOCs':<6}")
    click.echo(f"   {'─' * 30} {'─' * 10} {'─' * 12} {'─' * 10} {'─' * 6}")
    
    for c in cases:
        # Format created date
        try:
            dt = datetime.fromisoformat(c.created_at.replace('Z', '+00:00'))
            created = dt.strftime('%Y-%m-%d')
        except Exception:
            created = c.created_at[:10]
        
        # Active indicator
        indicator = '→ ' if c.name == active_name else '  '
        
        # Status color
        status_color = {
            'active': Colors.GREEN,
            'closed': Colors.YELLOW,
            'archived': Colors.BRIGHT_BLACK,
        }.get(c.status, Colors.WHITE)
        
        click.echo(f" {indicator}{c.name:<30} {status_color}{c.status:<10}{Colors.RESET} "
                  f"{created:<12} {c.artifacts_count:<10} {c.iocs_count:<6}")
    
    click.echo()
    click.echo("→ = active case")
    click.echo()


@case.command('open')
@click.argument('name')
def case_open(name):
    """
    Switch to an existing case.
    
    \b
    Examples:
        bsot case open emotet-campaign-q4
    """
    from .case_manager import CaseManager
    from ..utils import Colors
    
    manager = CaseManager()
    case_obj = manager.get(name)
    
    if not case_obj:
        click.echo(f"❌ Case not found: {name}", err=True)
        click.echo("   Run `bsot case list` to see available cases.", err=True)
        sys.exit(1)
    
    manager.set_active(case_obj)
    
    click.echo(f"\n📁 Switched to case: {Colors.CYAN}{case_obj.name}{Colors.RESET}")
    click.echo(f"   Status: {case_obj.status}")
    click.echo(f"   Artifacts: {case_obj.artifacts_count}")
    click.echo(f"   IOCs: {case_obj.iocs_count}")
    click.echo()


@case.command('close')
@click.option('--force', '-f', is_flag=True, help='Close without confirmation')
def case_close(force):
    """
    Close the current case.
    
    Marks the case as closed and clears the active case.
    """
    from .case_manager import CaseManager
    from ..utils import Colors
    
    manager = CaseManager()
    case_obj = manager.get_active()
    
    if not case_obj:
        click.echo("❌ No active case to close.", err=True)
        sys.exit(1)
    
    if not force:
        click.confirm(f"Close case '{case_obj.name}'?", abort=True)
    
    manager.close(case_obj)
    
    click.echo(f"\n✅ Case closed: {Colors.CYAN}{case_obj.name}{Colors.RESET}")
    click.echo()


@case.command('add')
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--type', '-t', 'artifact_type',
              type=click.Choice(['email', 'file', 'malware', 'screenshot', 'log']),
              help='Artifact type (auto-detected if not specified)')
def case_add(file_path, artifact_type):
    """
    Add an artifact to the current case.
    
    \b
    Examples:
        bsot case add suspicious.eml
        bsot case add malware.exe --type malware
        bsot case add evidence.png --type screenshot
    """
    from .case_manager import CaseManager
    from ..utils import Colors
    
    manager = CaseManager()
    case_obj = manager.get_active()
    
    if not case_obj:
        click.echo("❌ No active case. Create one with: bsot case new <name>", err=True)
        sys.exit(1)
    
    try:
        artifact = manager.add_artifact(case_obj, Path(file_path), artifact_type)
        
        click.echo(f"\n✅ Artifact added to case: {Colors.CYAN}{case_obj.name}{Colors.RESET}")
        click.echo(f"   File: {artifact['name']}")
        click.echo(f"   Type: {artifact['type']}")
        click.echo(f"   SHA256: {artifact['hashes']['sha256'][:32]}...")
        click.echo()
        
    except FileNotFoundError as e:
        click.echo(f"❌ File not found: {file_path}", err=True)
        sys.exit(1)


@case.command('note')
@click.argument('text', required=False)
@click.option('--list', '-l', 'list_notes', is_flag=True, help='List all notes')
def case_note(text, list_notes):
    """
    Add a note or view notes.
    
    \b
    Examples:
        bsot case note "Received sample from user jdoe"
        bsot case note --list
    """
    from .case_manager import CaseManager
    from .timeline import NotesManager
    from ..utils import Colors
    
    manager = CaseManager()
    case_obj = manager.get_active()
    
    if not case_obj:
        click.echo("❌ No active case. Create one with: bsot case new <name>", err=True)
        sys.exit(1)
    
    notes = NotesManager(case_obj.path / 'notes.md')
    
    if list_notes or not text:
        # Show notes
        entries = notes.get_entries()
        if not entries:
            click.echo("\n📝 No notes yet.")
            click.echo("   Add one with: bsot case note \"Your note here\"")
        else:
            click.echo(f"\n📝 Notes for {Colors.CYAN}{case_obj.name}{Colors.RESET}\n")
            for entry in entries:
                click.echo(f"   {Colors.BLUE}[{entry['timestamp']}]{Colors.RESET}")
                click.echo(f"   {entry['text']}")
                click.echo()
    else:
        # Add note
        notes.add(text)
        click.echo(f"\n✅ Note added to case: {Colors.CYAN}{case_obj.name}{Colors.RESET}")
        click.echo()


@case.command('timeline')
@click.argument('event', required=False)
@click.option('--time', '-t', 'timestamp', help='Event timestamp (default: now)')
@click.option('--list', '-l', 'list_events', is_flag=True, help='List all events')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['table', 'markdown', 'json', 'ascii']),
              default='table', help='Output format')
def case_timeline(event, timestamp, list_events, output_format):
    """
    Add a timeline event or view timeline.
    
    \b
    Examples:
        bsot case timeline "Phishing email received" --time "2025-01-15 09:15:00"
        bsot case timeline "User clicked malicious link"
        bsot case timeline --list
    """
    from .case_manager import CaseManager
    from .timeline import TimelineManager
    from ..utils import Colors
    
    manager = CaseManager()
    case_obj = manager.get_active()
    
    if not case_obj:
        click.echo("❌ No active case. Create one with: bsot case new <name>", err=True)
        sys.exit(1)
    
    timeline = TimelineManager(case_obj.path / 'timeline.json')
    
    if list_events or not event:
        # Show timeline
        events = timeline.get_all()
        if not events:
            click.echo("\n📅 No timeline events yet.")
            click.echo("   Add one with: bsot case timeline \"Event description\"")
        else:
            if output_format == 'json':
                click.echo(json_lib.dumps([e.to_dict() for e in events], indent=2))
            elif output_format == 'markdown':
                click.echo(timeline.to_markdown())
            elif output_format == 'ascii':
                click.echo(f"\n📅 Timeline: {case_obj.name}\n")
                click.echo(timeline.to_ascii())
            else:
                click.echo(f"\n📅 Timeline: {Colors.CYAN}{case_obj.name}{Colors.RESET}\n")
                click.echo(f"   {'Time':<20} {'Event':<45} {'Source':<12}")
                click.echo(f"   {'─' * 20} {'─' * 45} {'─' * 12}")
                
                for e in events:
                    try:
                        dt = datetime.fromisoformat(e.timestamp.replace('Z', '+00:00'))
                        time_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                    except Exception:
                        time_str = e.timestamp[:19]
                    
                    event_text = e.event[:43] + '..' if len(e.event) > 45 else e.event
                    click.echo(f"   {time_str:<20} {event_text:<45} {e.source:<12}")
        click.echo()
    else:
        # Add event
        timeline.add(event, timestamp=timestamp, source='analyst')
        timeline.save()
        
        click.echo(f"\n✅ Timeline event added to case: {Colors.CYAN}{case_obj.name}{Colors.RESET}")
        click.echo()


@case.command('status')
def case_status():
    """
    Show current case summary.
    """
    from .case_manager import CaseManager
    from .ioc_store import IOCStore
    from .timeline import TimelineManager, NotesManager
    from ..utils import Colors
    
    manager = CaseManager()
    case_obj = manager.get_active()
    
    if not case_obj:
        click.echo("\n📁 No active case.")
        click.echo("   Create one with: bsot case new <name>")
        click.echo("   Or open an existing one: bsot case open <name>")
        click.echo()
        return
    
    # Load additional data
    ioc_store = IOCStore(case_obj.path / 'iocs.json')
    timeline = TimelineManager(case_obj.path / 'timeline.json')
    notes = NotesManager(case_obj.path / 'notes.md')
    
    # Count artifacts by type
    artifacts_dir = case_obj.path / 'artifacts'
    artifact_counts = {}
    if artifacts_dir.exists():
        for subdir in artifacts_dir.iterdir():
            if subdir.is_dir():
                count = sum(1 for f in subdir.glob('*') if f.is_file())
                if count > 0:
                    artifact_counts[subdir.name] = count
    
    # Count analysis outputs
    outputs_dir = case_obj.path / 'outputs'
    output_counts = {}
    if outputs_dir.exists():
        for subdir in outputs_dir.iterdir():
            if subdir.is_dir():
                count = sum(1 for f in subdir.glob('*.json'))
                if count > 0:
                    output_counts[subdir.name] = count
    
    # IOC counts by type
    ioc_counts = ioc_store.count_by_type()
    
    # Display
    status_color = Colors.GREEN if case_obj.status == 'active' else Colors.YELLOW
    
    click.echo(f"\n📁 Case: {Colors.CYAN}{case_obj.name}{Colors.RESET}")
    click.echo(f"   Status: {status_color}{case_obj.status}{Colors.RESET}")
    click.echo(f"   Type: {case_obj.type}")
    click.echo(f"   Severity: {case_obj.severity}")
    click.echo(f"   Created: {case_obj.created_at}")
    click.echo(f"   Last Updated: {case_obj.updated_at}")
    if case_obj.analyst:
        click.echo(f"   Analyst: {case_obj.analyst}")
    
    # Artifacts
    click.echo(f"\n📊 Artifacts")
    if artifact_counts:
        for atype, count in artifact_counts.items():
            click.echo(f"   {atype.title()}: {count}")
    else:
        click.echo("   No artifacts yet")
    
    # Analysis outputs
    click.echo(f"\n🔍 Analysis Outputs")
    if output_counts:
        for otype, count in output_counts.items():
            click.echo(f"   {otype.title()} analyses: {count}")
    else:
        click.echo("   No analysis outputs yet")
    
    # IOCs
    click.echo(f"\n🎯 IOCs: {ioc_store.count()}")
    if ioc_counts:
        parts = [f"{t}: {c}" for t, c in sorted(ioc_counts.items())]
        click.echo(f"   {' | '.join(parts)}")
    
    # Notes and timeline
    click.echo(f"\n📝 Notes: {notes.count()} entries")
    click.echo(f"📅 Timeline: {timeline.count()} events")
    click.echo()


# ============================================================================
# Report Commands
# ============================================================================

@click.group()
def report():
    """Report generation and export tools."""
    pass


@report.command('generate')
@click.option('--template', '-t',
              type=click.Choice(['executive', 'technical', 'ioc', 'timeline']),
              default='technical', help='Report template')
@click.option('--audience', '-a', help='Target audience (overrides template)')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['markdown', 'html']),
              default='markdown', help='Output format')
@click.option('--llm', '-l',
              type=click.Choice(['anthropic', 'openai', 'ollama']),
              help='LLM provider to use')
@click.option('--no-llm', is_flag=True, help='Generate report without AI')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--json', 'json_output', is_flag=True, help='JSON output (metadata only)')
def report_generate(template, audience, output_format, llm, no_llm, output, json_output):
    """
    Generate an AI-powered incident report.
    
    Uses case data including artifacts, IOCs, timeline, and notes
    to generate a professional incident report.
    
    \b
    Examples:
        bsot report generate
        bsot report generate --template executive
        bsot report generate --format html
        bsot report generate --llm ollama --template technical
        bsot report generate --no-llm  # Basic report without AI
    """
    from .case_manager import CaseManager
    from .generator import ReportGenerator, generate_report_without_llm
    from .llm_client import get_llm_client
    from ..utils import Colors
    
    manager = CaseManager()
    case_obj = manager.get_active()
    
    if not case_obj:
        click.echo("❌ No active case. Create one with: bsot case new <name>", err=True)
        sys.exit(1)
    
    click.echo(f"\n🤖 Generating report for: {Colors.CYAN}{case_obj.name}{Colors.RESET}")
    click.echo()
    
    if no_llm:
        # Generate without LLM
        click.echo("   Generating basic report (no AI)...")
        content = generate_report_without_llm(case_obj)
        
        # Save report
        reports_dir = case_obj.path / 'reports'
        reports_dir.mkdir(exist_ok=True)
        timestamp = datetime.utcnow().strftime('%Y-%m-%d_%H%M%S')
        report_file = reports_dir / f"report-{timestamp}.md"
        report_file.write_text(content)
        
        if json_output:
            click.echo(json_lib.dumps({
                'file_path': str(report_file),
                'format': 'markdown',
                'template': 'basic',
                'llm_used': False,
            }, indent=2))
        else:
            click.echo(f"✅ Report generated: {Colors.GREEN}{report_file}{Colors.RESET}")
            click.echo()
            click.echo("📄 Preview:")
            click.echo("   " + "─" * 50)
            lines = content.split('\n')[:10]
            for line in lines:
                click.echo(f"   {line}")
            click.echo("   " + "─" * 50)
            click.echo()
        
        return
    
    # Get LLM client
    try:
        llm_client = get_llm_client(provider=llm) if llm else get_llm_client()
    except Exception as e:
        click.echo(f"❌ Failed to initialize LLM: {e}", err=True)
        click.echo("   Try --no-llm for a basic report, or configure API keys.", err=True)
        sys.exit(1)
    
    click.echo(f"   Using: {llm_client.provider_name} / {llm_client.model_name}")
    
    # Gather stats
    from .ioc_store import IOCStore
    from .timeline import TimelineManager, NotesManager
    
    ioc_store = IOCStore(case_obj.path / 'iocs.json')
    timeline = TimelineManager(case_obj.path / 'timeline.json')
    notes = NotesManager(case_obj.path / 'notes.md')
    
    click.echo(f"\n   Analyzing case data...")
    click.echo(f"   - {case_obj.artifacts_count} artifacts")
    click.echo(f"   - {ioc_store.count()} IOCs")
    click.echo(f"   - {timeline.count()} timeline events")
    click.echo(f"   - {notes.count()} analyst notes")
    
    click.echo(f"\n   Generating report...")
    
    generator = ReportGenerator(case_obj, llm_client)
    result = generator.generate(
        template=template,
        audience=audience,
        output_format=output_format,
    )
    
    if result.error:
        click.echo(f"\n❌ Generation failed: {result.error}", err=True)
        click.echo("   Try --no-llm for a basic report.", err=True)
        sys.exit(1)
    
    # Override output path if specified
    if output:
        output_path = Path(output)
        output_path.write_text(result.content)
        result.file_path = str(output_path)
    
    if json_output:
        click.echo(json_lib.dumps({
            'file_path': result.file_path,
            'format': result.format,
            'template': result.template,
            'llm_provider': result.llm_provider,
            'llm_model': result.llm_model,
            'tokens_used': result.tokens_used,
        }, indent=2))
    else:
        click.echo(f"\n✅ Report generated: {Colors.GREEN}{result.file_path}{Colors.RESET}")
        click.echo()
        click.echo("📄 Preview:")
        click.echo("   " + "─" * 50)
        lines = result.content.split('\n')[:10]
        for line in lines:
            click.echo(f"   {line[:70]}")
        click.echo("   " + "─" * 50)
        click.echo()


@report.command('ioc')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['json', 'csv', 'stix', 'misp']),
              default='json', help='Export format')
@click.option('--type', '-t', 'ioc_types', help='Filter by IOC types (comma-separated)')
@click.option('--confidence', '-c',
              type=click.Choice(['low', 'medium', 'high']),
              help='Filter by confidence')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
def report_ioc(output_format, ioc_types, confidence, output):
    """
    Export IOCs in various formats.
    
    \b
    Examples:
        bsot report ioc --format csv
        bsot report ioc --format stix -o iocs.stix.json
        bsot report ioc --type ip,domain --format misp
    """
    from .case_manager import CaseManager
    from .ioc_store import IOCStore
    from ..utils import Colors
    
    manager = CaseManager()
    case_obj = manager.get_active()
    
    if not case_obj:
        click.echo("❌ No active case.", err=True)
        sys.exit(1)
    
    ioc_store = IOCStore(case_obj.path / 'iocs.json')
    
    # Filter IOCs
    iocs = ioc_store.get_all()
    
    if ioc_types:
        type_list = [t.strip() for t in ioc_types.split(',')]
        iocs = [i for i in iocs if i.type in type_list]
    
    if confidence:
        iocs = [i for i in iocs if i.confidence == confidence]
    
    if not iocs:
        click.echo("⚠️  No IOCs match the specified filters.")
        return
    
    # Export
    if output_format == 'json':
        content = json_lib.dumps([i.to_dict() for i in iocs], indent=2)
    elif output_format == 'csv':
        content = ioc_store.to_csv()
    elif output_format == 'stix':
        content = json_lib.dumps(ioc_store.to_stix(), indent=2)
    elif output_format == 'misp':
        content = json_lib.dumps(ioc_store.to_misp(), indent=2)
    else:
        content = json_lib.dumps([i.to_dict() for i in iocs], indent=2)
    
    if output:
        Path(output).write_text(content)
        click.echo(f"✅ Exported {len(iocs)} IOCs to: {Colors.GREEN}{output}{Colors.RESET}")
    else:
        click.echo(content)


@report.command('timeline')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['table', 'markdown', 'json', 'csv', 'ascii']),
              default='table', help='Output format')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
def report_timeline(output_format, output):
    """
    Generate formatted timeline from case data.
    
    \b
    Examples:
        bsot report timeline
        bsot report timeline --format markdown
        bsot report timeline --format csv -o timeline.csv
    """
    from .case_manager import CaseManager
    from .timeline import TimelineManager
    from ..utils import Colors
    
    manager = CaseManager()
    case_obj = manager.get_active()
    
    if not case_obj:
        click.echo("❌ No active case.", err=True)
        sys.exit(1)
    
    timeline = TimelineManager(case_obj.path / 'timeline.json')
    
    if timeline.count() == 0:
        click.echo("⚠️  No timeline events.")
        return
    
    if output_format == 'json':
        content = json_lib.dumps([e.to_dict() for e in timeline.get_all()], indent=2)
    elif output_format == 'csv':
        content = timeline.to_csv()
    elif output_format == 'markdown':
        content = timeline.to_markdown()
    elif output_format == 'ascii':
        content = timeline.to_ascii()
    else:
        # Table format
        lines = [f"📅 Timeline: {case_obj.name}", ""]
        lines.append(f"{'Time':<20} {'Event':<50} {'Source':<12}")
        lines.append("─" * 82)
        
        for e in timeline.get_all():
            try:
                dt = datetime.fromisoformat(e.timestamp.replace('Z', '+00:00'))
                time_str = dt.strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                time_str = e.timestamp[:19]
            
            event_text = e.event[:48] + '..' if len(e.event) > 50 else e.event
            lines.append(f"{time_str:<20} {event_text:<50} {e.source:<12}")
        
        content = '\n'.join(lines)
    
    if output:
        Path(output).write_text(content)
        click.echo(f"✅ Timeline exported to: {Colors.GREEN}{output}{Colors.RESET}")
    else:
        click.echo(content)


@report.command('package')
@click.option('--output', '-o', type=click.Path(), help='Output ZIP path')
@click.option('--exclude-samples', is_flag=True, help='Exclude malware samples (include only hashes)')
@click.option('--encrypt', is_flag=True, help='Encrypt package with password')
@click.option('--password', '-p', help='Encryption password (prompted if not provided)')
def report_package(output, exclude_samples, encrypt, password):
    """
    Package case for archival or sharing.
    
    Creates a ZIP archive with manifest for chain of custody.
    
    \b
    Examples:
        bsot report package
        bsot report package --exclude-samples
        bsot report package --encrypt --password mypassword
    """
    from .case_manager import CaseManager
    from .packager import CasePackager
    from ..utils import Colors, format_bytes
    
    manager = CaseManager()
    case_obj = manager.get_active()
    
    if not case_obj:
        click.echo("❌ No active case.", err=True)
        sys.exit(1)
    
    # Get password if encrypting
    if encrypt and not password:
        password = click.prompt("Enter encryption password", hide_input=True, confirmation_prompt=True)
    
    click.echo(f"\n📦 Packaging case: {Colors.CYAN}{case_obj.name}{Colors.RESET}")
    
    packager = CasePackager(case_obj.path)
    
    output_path = Path(output) if output else None
    
    result = packager.package(
        output_path=output_path,
        exclude_samples=exclude_samples,
        password=password if encrypt else None,
    )
    
    if result.error:
        click.echo(f"\n❌ Packaging failed: {result.error}", err=True)
        sys.exit(1)
    
    click.echo(f"\n✅ Package created: {Colors.GREEN}{result.package_path}{Colors.RESET}")
    click.echo(f"   Size: {format_bytes(result.package_size)}")
    click.echo(f"   Files: {result.file_count}")
    click.echo(f"   SHA256: {result.sha256[:32]}...")
    if result.encrypted:
        click.echo(f"   Encrypted: Yes")
    click.echo()
    click.echo(f"📋 Manifest: {result.manifest_path}")
    click.echo()


@report.command('template')
@click.argument('action', type=click.Choice(['list', 'show']))
@click.argument('name', required=False)
def report_template(action, name):
    """
    Manage report templates.
    
    \b
    Examples:
        bsot report template list
        bsot report template show executive
    """
    from .generator import TEMPLATES
    from ..utils import Colors
    
    if action == 'list':
        click.echo("\n📄 Available Report Templates\n")
        for tname, config in TEMPLATES.items():
            click.echo(f"   {Colors.CYAN}{tname}{Colors.RESET}")
            click.echo(f"      {config['description']}")
            click.echo(f"      Audience: {config['audience']}")
            click.echo(f"      Sections: {', '.join(config['sections'])}")
            click.echo()
    
    elif action == 'show':
        if not name:
            click.echo("❌ Template name required.", err=True)
            sys.exit(1)
        
        if name not in TEMPLATES:
            click.echo(f"❌ Template not found: {name}", err=True)
            click.echo(f"   Available: {', '.join(TEMPLATES.keys())}")
            sys.exit(1)
        
        config = TEMPLATES[name]
        click.echo(f"\n📄 Template: {Colors.CYAN}{name}{Colors.RESET}")
        click.echo(f"   Name: {config['name']}")
        click.echo(f"   Description: {config['description']}")
        click.echo(f"   Audience: {config['audience']}")
        click.echo(f"   Detail Level: {config['detail_level']}")
        click.echo(f"\n   Sections:")
        for section in config['sections']:
            click.echo(f"   - {section.replace('_', ' ').title()}")
        click.echo()



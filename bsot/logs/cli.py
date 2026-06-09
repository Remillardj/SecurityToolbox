"""
CLI commands for the log analysis module.
"""

import click
import sys
import json as json_lib
from pathlib import Path


@click.group()
def logs():
    """Log analysis and attack detection tools."""
    pass


@logs.command()
@click.option('--file', '-f', 'input_file', type=click.Path(exists=True), required=True,
              help='Log file to parse')
@click.option('--format', '-F', 'log_format', 
              type=click.Choice(['auto', 'syslog', 'json', 'clf', 'cef']),
              default='auto', help='Log format')
@click.option('--limit', '-n', default=None, type=int, help='Maximum events to parse')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
@click.option('--output', '-o', type=click.Path(), help='Output file')
def parse(input_file, log_format, limit, json_output, output):
    """
    Parse and normalize log files.
    
    \b
    Examples:
        bsot logs parse -f auth.log
        bsot logs parse -f access.log --format clf
        bsot logs parse -f events.json --json -o normalized.json
    """
    from .parsers import parse_log, detect_format
    from ..utils import Colors, print_header, print_subheader
    
    # Detect format
    if log_format == 'auto':
        log_format = detect_format(input_file)
        if not json_output:
            click.echo(f"Detected format: {log_format}")
    
    # Parse
    events = parse_log(input_file, log_format, limit)
    
    if json_output:
        output_data = [e.to_dict() for e in events]
        if output:
            with open(output, 'w') as f:
                json_lib.dump(output_data, f, indent=2)
            click.echo(f"Wrote {len(events)} events to {output}")
        else:
            click.echo(json_lib.dumps(output_data, indent=2))
        return
    
    # Display summary
    print_header(f"Parsed: {input_file}")
    click.echo(f"  Format: {log_format}")
    click.echo(f"  Events: {len(events)}")
    
    if events:
        # Show sample
        print_subheader("Sample Events (first 5)")
        for event in events[:5]:
            click.echo(f"\n  {Colors.CYAN}Timestamp:{Colors.RESET} {event.timestamp_str}")
            if event.source_ip:
                click.echo(f"  {Colors.CYAN}Source IP:{Colors.RESET} {event.source_ip}")
            if event.user:
                click.echo(f"  {Colors.CYAN}User:{Colors.RESET} {event.user}")
            if event.event_type:
                click.echo(f"  {Colors.CYAN}Type:{Colors.RESET} {event.event_type}/{event.event_action}")
            click.echo(f"  {Colors.CYAN}Message:{Colors.RESET} {event.message[:100]}...")
    
    if output:
        output_data = [e.to_dict() for e in events]
        with open(output, 'w') as f:
            json_lib.dump(output_data, f, indent=2)
        click.echo(f"\n📄 Wrote {len(events)} events to {output}")


@logs.command()
@click.option('--file', '-f', 'input_file', type=click.Path(exists=True), required=True,
              help='Log file to analyze')
@click.option('--format', '-F', 'log_format', default='auto', help='Log format')
@click.option('--checks', default='all',
              help='Checks to run: brute_force,privesc,lateral,anomaly or "all"')
@click.option('--mitre', is_flag=True, default=True, help='Include MITRE ATT&CK IDs')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
@click.option('--output', '-o', type=click.Path(), help='Output file')
def analyze(input_file, log_format, checks, mitre, json_output, output):
    """
    Analyze logs for attack patterns and security issues.
    
    Detects:
    - Brute force attacks
    - Password spraying
    - Privilege escalation attempts
    - Lateral movement
    - Off-hours activity
    
    \b
    Examples:
        bsot logs analyze -f auth.log
        bsot logs analyze -f secure.log --checks brute_force,privesc
        bsot logs analyze -f events.log --json -o findings.json
    """
    from .parsers import parse_log
    from .analyzers import analyze_logs
    from ..utils import Colors, print_header, print_subheader, print_finding
    
    # Parse checks
    check_list = None
    if checks.lower() != 'all':
        check_list = [c.strip() for c in checks.split(',')]
    
    # Parse log
    events = parse_log(input_file, log_format)
    
    if not events:
        click.echo(f"No events parsed from {input_file}")
        sys.exit(0)
    
    # Analyze
    result = analyze_logs(events, checks=check_list, include_mitre=mitre)
    
    if json_output:
        if output:
            with open(output, 'w') as f:
                json_lib.dump(result.to_dict(), f, indent=2)
            click.echo(f"Results saved to {output}")
        else:
            click.echo(json_lib.dumps(result.to_dict(), indent=2))
        return
    
    # Display results
    print_header("Log Analysis Results")
    
    click.echo(f"  {Colors.CYAN}File:{Colors.RESET} {input_file}")
    click.echo(f"  {Colors.CYAN}Events:{Colors.RESET} {result.total_events}")
    if result.time_range:
        click.echo(f"  {Colors.CYAN}Time Range:{Colors.RESET} {result.time_range.get('start', 'N/A')} - {result.time_range.get('end', 'N/A')}")
    
    # Findings
    if result.findings:
        print_subheader(f"Findings ({len(result.findings)})")
        
        for finding in result.findings:
            severity_colors = {
                'critical': Colors.RED + Colors.BOLD,
                'high': Colors.RED,
                'medium': Colors.YELLOW,
                'low': Colors.BLUE,
            }
            color = severity_colors.get(finding.severity, Colors.WHITE)
            
            click.echo(f"\n  {color}[{finding.severity.upper()}] {finding.type}{Colors.RESET}")
            click.echo(f"    {finding.description}")
            
            if finding.mitre_technique:
                click.echo(f"    MITRE: {finding.mitre_technique}")
            if finding.source_ip:
                click.echo(f"    Source IP: {finding.source_ip}")
            if finding.target_user:
                click.echo(f"    User: {finding.target_user}")
            click.echo(f"    Events: {finding.event_count}")
            
            if finding.evidence:
                click.echo(f"    Evidence:")
                for ev in finding.evidence[:3]:
                    click.echo(f"      • {ev[:80]}...")
    else:
        click.echo("\n  ✅ No security issues detected")
    
    # Statistics
    stats = result.statistics
    if stats:
        print_subheader("Statistics")
        
        if stats.get('auth_success') or stats.get('auth_failure'):
            total_auth = stats['auth_success'] + stats['auth_failure']
            fail_rate = (stats['auth_failure'] / total_auth * 100) if total_auth > 0 else 0
            click.echo(f"\n  Authentication:")
            click.echo(f"    Success: {stats['auth_success']}")
            click.echo(f"    Failure: {stats['auth_failure']} ({fail_rate:.1f}%)")
        
        if stats.get('source_ips'):
            click.echo(f"\n  Top Source IPs:")
            for ip, count in list(stats['source_ips'].items())[:5]:
                click.echo(f"    {ip}: {count}")
        
        if stats.get('users'):
            click.echo(f"\n  Top Users:")
            for user, count in list(stats['users'].items())[:5]:
                click.echo(f"    {user}: {count}")
    
    # Exit code
    if any(f.severity in ('critical', 'high') for f in result.findings):
        sys.exit(1)
    sys.exit(0)


@logs.command()
@click.option('--file', '-f', 'input_file', type=click.Path(exists=True), required=True,
              help='Log file to analyze')
@click.option('--format', '-F', 'log_format', default='auto', help='Log format')
@click.option('--user', '-u', 'filter_user', help='Filter by specific user')
@click.option('--ip', 'filter_ip', help='Filter by specific IP address')
@click.option('--verbose', '-v', is_flag=True, help='Show all events (default is concise narrative)')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
@click.option('--output', '-o', type=click.Path(), help='Output file')
def timeline(input_file, log_format, filter_user, filter_ip, verbose, json_output, output):
    """
    Build an investigative timeline from log events.
    
    Creates a concise narrative of what happened - perfect for incident reports.
    
    \b
    Examples:
        bsot logs timeline -f auth.log
        bsot logs timeline -f auth.log --user cyberjunkie
        bsot logs timeline -f auth.log --ip 65.2.161.68
        bsot logs timeline -f auth.log -v   # verbose mode
    """
    from .parsers import parse_log
    from collections import defaultdict
    import re
    from ..utils import Colors, print_header
    
    events = parse_log(input_file, log_format)
    if not events:
        click.echo(f"No events parsed from {input_file}")
        sys.exit(0)
    
    # Extract key data
    logins = []  # (timestamp, user, ip, success)
    failed_by_ip = defaultdict(lambda: {'count': 0, 'users': set(), 'first': None, 'last': None})
    user_actions = defaultdict(list)  # user -> [(timestamp, action, detail)]
    sudo_commands = []  # (timestamp, user, command)
    account_changes = []  # (timestamp, action, detail)
    
    for event in events:
        msg = (event.message or '').lower()
        raw = (event.raw or '').lower()
        ts = event.timestamp_str
        user = event.user or ''
        ip = event.source_ip or ''
        
        # Filter
        if filter_user and filter_user.lower() not in user.lower() and filter_user.lower() not in raw:
            continue
        if filter_ip and ip != filter_ip:
            continue
        
        # Successful logins
        if 'accepted password' in msg or 'accepted publickey' in msg:
            logins.append((ts, user, ip, True))
            user_actions[user].append((ts, 'LOGIN', f'from {ip}'))
        
        # Failed logins - aggregate by IP
        elif 'failed password' in msg or 'authentication failure' in msg:
            if ip:
                if not failed_by_ip[ip]['first']:
                    failed_by_ip[ip]['first'] = ts
                failed_by_ip[ip]['last'] = ts
                failed_by_ip[ip]['count'] += 1
                if user:
                    failed_by_ip[ip]['users'].add(user)
        
        # Sudo commands
        elif 'command=' in raw and 'sudo' in raw:
            cmd_match = re.search(r'COMMAND=(.+?)(?:\s*$)', event.raw or '')
            if cmd_match:
                cmd = cmd_match.group(1).strip()
                sudo_commands.append((ts, user, cmd))
                user_actions[user].append((ts, 'SUDO', cmd[:60]))
        
        # User creation
        elif 'useradd' in raw or 'new user' in msg:
            new_user_match = re.search(r"new user[:\s]+name=(\w+)", raw) or re.search(r"useradd.*?(\w+)", raw)
            new_user = new_user_match.group(1) if new_user_match else 'unknown'
            account_changes.append((ts, 'USER CREATED', new_user))
        
        # Password change
        elif 'passwd' in raw and 'password changed' in msg:
            account_changes.append((ts, 'PASSWORD SET', user))
            user_actions[user].append((ts, 'PASSWORD', 'changed'))
        
        # Privilege escalation (added to sudo group)
        elif 'usermod' in raw and ('sudo' in raw or 'wheel' in raw):
            target_match = re.search(r"'(\w+)'.*(?:sudo|wheel)", raw)
            target = target_match.group(1) if target_match else user
            account_changes.append((ts, '⚠️  PRIVESC', f'{target} added to sudo group'))
            user_actions[target].append((ts, 'PRIVESC', 'added to sudo group'))
        
        # Disconnects with sessions
        elif 'disconnect' in msg and user and ip:
            user_actions[user].append((ts, 'LOGOUT', f'from {ip}'))
    
    # JSON output
    if json_output:
        data = {
            'file': input_file,
            'logins': [{'time': l[0], 'user': l[1], 'ip': l[2], 'success': l[3]} for l in logins],
            'failed_attempts': {ip: {'count': d['count'], 'users': list(d['users']), 'first': d['first'], 'last': d['last']} 
                               for ip, d in failed_by_ip.items()},
            'sudo_commands': [{'time': s[0], 'user': s[1], 'command': s[2]} for s in sudo_commands],
            'account_changes': [{'time': a[0], 'action': a[1], 'detail': a[2]} for a in account_changes],
        }
        if output:
            with open(output, 'w') as f:
                json_lib.dump(data, f, indent=2)
            click.echo(f"Timeline saved to {output}")
        else:
            click.echo(json_lib.dumps(data, indent=2))
        return
    
    # Build the narrative story
    print_header(f"Investigation Timeline: {input_file}")
    
    # Collect ALL events into a single timeline
    all_events = []
    
    # Add logins
    for ts, user, ip, success in logins:
        all_events.append({
            'ts': ts, 'type': 'login', 'user': user, 'ip': ip,
            'desc': f"{user} logged in from {ip}"
        })
    
    # Add brute force as single events
    for ip, data in failed_by_ip.items():
        if data['count'] > 3:
            users_str = ', '.join(list(data['users'])[:3])
            all_events.append({
                'ts': data['first'], 'type': 'brute_force', 'user': None, 'ip': ip,
                'desc': f"Brute force attack from {ip} ({data['count']} attempts against {users_str})",
                'end_ts': data['last']
            })
    
    # Add account changes
    for ts, action, detail in account_changes:
        all_events.append({
            'ts': ts, 'type': 'account', 'user': detail, 'ip': None,
            'desc': f"{action}: {detail}"
        })
    
    # Add sudo commands
    for ts, user, cmd in sudo_commands:
        all_events.append({
            'ts': ts, 'type': 'sudo', 'user': user, 'ip': None,
            'desc': f"{user or 'user'} ran: {cmd}"
        })
    
    # Sort by timestamp
    def parse_ts(ts):
        """Extract sortable time from timestamp string."""
        if not ts:
            return ""
        # Handle "Mar  6 06:31:33" format
        import re
        match = re.search(r'(\d{2}):(\d{2}):(\d{2})', ts)
        if match:
            return f"{match.group(1)}{match.group(2)}{match.group(3)}"
        return ts
    
    all_events.sort(key=lambda x: parse_ts(x['ts']))
    
    # Group into sessions by IP
    sessions = []
    current_session = None
    brute_force_ips = set(failed_by_ip.keys())
    
    for event in all_events:
        if event['type'] == 'brute_force':
            # Brute force is its own "session"
            if current_session:
                sessions.append(current_session)
            sessions.append({
                'type': 'attack',
                'ip': event['ip'],
                'start': event['ts'],
                'end': event.get('end_ts', event['ts']),
                'user': None,
                'events': [event],
                'is_attacker': True
            })
            current_session = None
        elif event['type'] == 'login':
            # Start new session
            if current_session:
                sessions.append(current_session)
            is_attacker = event['ip'] in brute_force_ips
            current_session = {
                'type': 'session',
                'ip': event['ip'],
                'start': event['ts'],
                'end': None,
                'user': event['user'],
                'events': [event],
                'is_attacker': is_attacker
            }
        else:
            # Add to current session
            if current_session:
                current_session['events'].append(event)
                current_session['end'] = event['ts']
    
    if current_session:
        sessions.append(current_session)
    
    # Print the story
    click.echo()
    
    for i, sess in enumerate(sessions):
        ts_display = sess['start']
        if sess.get('end') and sess['end'] != sess['start']:
            # Extract just time portion
            start_time = sess['start'].split()[-1] if sess['start'] else ''
            end_time = sess['end'].split()[-1] if sess['end'] else ''
            if start_time and end_time and start_time != end_time:
                ts_display = f"{sess['start']} → {end_time}"
        
        if sess['type'] == 'attack':
            # Brute force attack
            click.echo(f"{Colors.RED}┌─ {ts_display}{Colors.RESET}")
            click.echo(f"{Colors.RED}│{Colors.RESET}  🚨 {Colors.RED}{Colors.BOLD}BRUTE FORCE ATTACK{Colors.RESET}")
            for evt in sess['events']:
                click.echo(f"{Colors.RED}│{Colors.RESET}  {evt['desc']}")
            # Check if attacker succeeded after this
            next_login = None
            for s in sessions[i+1:]:
                if s['type'] == 'session' and s['ip'] == sess['ip']:
                    next_login = s
                    break
            if next_login:
                click.echo(f"{Colors.RED}│{Colors.RESET}  {Colors.RED}⚠️  Attacker gained access as '{next_login['user']}'{Colors.RESET}")
            click.echo(f"{Colors.RED}└─{Colors.RESET}")
        
        elif sess['type'] == 'session':
            user = sess['user'] or 'unknown'
            ip = sess['ip'] or 'local'
            
            if sess['is_attacker']:
                color = Colors.RED
                label = "ATTACKER SESSION"
            else:
                color = Colors.GREEN
                label = "Session"
            
            click.echo(f"{color}┌─ {ts_display}{Colors.RESET}")
            click.echo(f"{color}│{Colors.RESET}  {color}{Colors.BOLD}{label}: {user}{Colors.RESET} from {ip}")
            
            # Show what happened in this session
            for evt in sess['events'][1:]:  # Skip the login event itself
                if evt['type'] == 'account':
                    if 'PRIVESC' in evt['desc']:
                        click.echo(f"{color}│{Colors.RESET}  {Colors.RED}🔺 {evt['desc']}{Colors.RESET}")
                    elif 'CREATED' in evt['desc']:
                        click.echo(f"{color}│{Colors.RESET}  {Colors.YELLOW}👤 {evt['desc']}{Colors.RESET}")
                    elif 'PASSWORD' in evt['desc']:
                        click.echo(f"{color}│{Colors.RESET}  {Colors.YELLOW}🔑 {evt['desc']}{Colors.RESET}")
                    else:
                        click.echo(f"{color}│{Colors.RESET}  {evt['desc']}")
                elif evt['type'] == 'sudo':
                    cmd = evt['desc']
                    dangerous = any(x in cmd.lower() for x in ['shadow', 'passwd', 'curl', 'wget', 'bash', 'nc ', 'chmod', 'chown'])
                    if dangerous:
                        click.echo(f"{color}│{Colors.RESET}  {Colors.RED}⚡ {cmd}{Colors.RESET}")
                    else:
                        click.echo(f"{color}│{Colors.RESET}  ⚡ {cmd}")
            
            click.echo(f"{color}└─{Colors.RESET}")
        
        click.echo()  # Blank line between sessions
    
    # Brief summary at end
    total_failed = sum(d['count'] for d in failed_by_ip.values())
    click.echo(f"{Colors.WHITE}━━━ Summary ━━━{Colors.RESET}")
    click.echo(f"  Logins: {len(logins)} | Failed attempts: {total_failed} | Sudo commands: {len(sudo_commands)} | Account changes: {len(account_changes)}")
    
    if output:
        # Save narrative to file
        with open(output, 'w') as f:
            f.write(f"# Investigation Timeline: {input_file}\n\n")
            if logins:
                f.write("## Successful Logins\n")
                for ts, user, ip, _ in logins:
                    f.write(f"- {ts} - {user} from {ip}\n")
                f.write("\n")
            if account_changes:
                f.write("## Account Changes\n")
                for ts, action, detail in account_changes:
                    f.write(f"- {ts} - {action}: {detail}\n")
                f.write("\n")
            if sudo_commands:
                f.write("## Sudo Commands\n")
                for ts, user, cmd in sudo_commands:
                    f.write(f"- {ts} [{user}] {cmd}\n")
        click.echo(f"\n📄 Saved to: {output}")


@logs.command('ai-analyze')
@click.option('--file', '-f', 'input_file', type=click.Path(exists=True), required=True,
              help='Log file to analyze')
@click.option('--format', '-F', 'log_format', default='auto', help='Log format')
@click.option('--provider', '-p', type=click.Choice(['anthropic', 'openai', 'ollama']),
              default=None, help='LLM provider (default: anthropic)')
@click.option('--model', '-m', help='Model name override')
@click.option('--focus', type=click.Choice(['attack', 'user', 'timeline', 'all']),
              default='all', help='Analysis focus area')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
@click.option('--output', '-o', type=click.Path(), help='Save analysis to file')
def ai_analyze(input_file, log_format, provider, model, focus, json_output, output):
    """
    AI-powered log analysis using LLMs.
    
    Provides intelligent analysis including:
    - Attack narrative and timeline reconstruction
    - Threat actor behavior profiling
    - MITRE ATT&CK technique mapping
    - Recommendations for response
    - Indicators of compromise summary
    
    \b
    Focus Areas:
      attack   - Focus on attack patterns and threat analysis
      user     - Focus on user behavior analysis
      timeline - Focus on event sequence and timeline
      all      - Comprehensive analysis (default)
    
    \b
    Examples:
        bsot logs ai-analyze -f auth.log
        bsot logs ai-analyze -f auth.log --focus attack
        bsot logs ai-analyze -f auth.log --provider openai
        bsot logs ai-analyze -f auth.log -o analysis.md
    
    \b
    Requires API key:
        export ANTHROPIC_API_KEY=your_key
        # or
        export OPENAI_API_KEY=your_key
    """
    from .parsers import parse_log
    from .analyzers import analyze_logs
    from ..report.llm_client import get_llm_client
    from ..utils import Colors, print_header, print_subheader
    from collections import defaultdict
    import re
    
    # Parse log file
    click.echo(f"📄 Parsing {input_file}...")
    events = parse_log(input_file, log_format)
    
    if not events:
        click.echo(f"No events parsed from {input_file}")
        sys.exit(0)
    
    click.echo(f"   Found {len(events)} events")
    
    # Run standard analysis first
    click.echo("🔍 Running pattern detection...")
    analysis_result = analyze_logs(events, include_mitre=True)
    
    # Build context for LLM
    click.echo("🧠 Preparing AI analysis...")
    
    # Extract key data points
    stats = {
        'total_events': len(events),
        'time_range': analysis_result.time_range,
        'auth_success': 0,
        'auth_failure': 0,
        'source_ips': defaultdict(int),
        'users': defaultdict(int),
        'sudo_commands': [],
        'user_modifications': [],
        'key_events': [],
    }
    
    for event in events:
        msg = (event.message or '').lower()
        raw = (event.raw or '').lower()
        
        # Count auth events
        if 'accepted' in msg:
            stats['auth_success'] += 1
        if 'failed' in msg or 'failure' in msg:
            stats['auth_failure'] += 1
        
        # Track IPs and users
        if event.source_ip:
            stats['source_ips'][event.source_ip] += 1
        if event.user:
            stats['users'][event.user] += 1
        
        # Extract sudo commands
        if 'sudo:' in raw and 'command=' in raw:
            cmd_match = re.search(r'COMMAND=(.+?)(?:\s*$|;)', event.raw or '')
            if cmd_match:
                stats['sudo_commands'].append({
                    'time': event.timestamp_str,
                    'user': event.user,
                    'command': cmd_match.group(1).strip()[:100]
                })
        
        # Track user modifications
        if any(x in raw for x in ['useradd', 'usermod', 'passwd', 'groupadd']):
            stats['user_modifications'].append({
                'time': event.timestamp_str,
                'event': event.raw[:150] if event.raw else msg[:150]
            })
        
        # Capture key events (first 50 significant ones)
        if len(stats['key_events']) < 50:
            if any(x in msg for x in ['accepted', 'failed', 'sudo', 'useradd', 'usermod', 'session opened', 'session closed']):
                stats['key_events'].append({
                    'time': event.timestamp_str,
                    'user': event.user,
                    'ip': event.source_ip,
                    'message': (event.message or event.raw or '')[:200]
                })
    
    # Convert to sorted lists
    stats['source_ips'] = dict(sorted(stats['source_ips'].items(), key=lambda x: -x[1])[:10])
    stats['users'] = dict(sorted(stats['users'].items(), key=lambda x: -x[1])[:15])
    
    # Format findings
    findings_text = ""
    for finding in analysis_result.findings:
        findings_text += f"- [{finding.severity.upper()}] {finding.type}: {finding.description}\n"
        if finding.mitre_technique:
            findings_text += f"  MITRE: {finding.mitre_technique}\n"
        if finding.source_ip:
            findings_text += f"  Source IP: {finding.source_ip}\n"
        if finding.target_user:
            findings_text += f"  User: {finding.target_user}\n"
    
    # Build the prompt based on focus
    system_prompt = """You are an expert cybersecurity analyst specializing in log analysis and incident response. 
You analyze security logs to identify attacks, threat actor behavior, and provide actionable recommendations.
Be specific, cite evidence from the logs, and map to MITRE ATT&CK where applicable.
Format your response in clear sections with markdown."""

    if focus == 'attack':
        analysis_focus = """Focus your analysis on:
1. Attack identification and classification
2. Threat actor tactics, techniques, and procedures (TTPs)
3. Attack timeline and kill chain progression
4. MITRE ATT&CK mapping
5. Indicators of Compromise (IOCs)"""
    elif focus == 'user':
        analysis_focus = """Focus your analysis on:
1. User behavior analysis and anomalies
2. Account compromise indicators
3. Privilege escalation patterns
4. Insider threat indicators
5. Session analysis"""
    elif focus == 'timeline':
        analysis_focus = """Focus your analysis on:
1. Chronological event reconstruction
2. Attack timeline with key pivot points
3. Dwell time analysis
4. Correlation of related events
5. Sequence of attacker actions"""
    else:
        analysis_focus = """Provide comprehensive analysis including:
1. Executive Summary
2. Attack Narrative (what happened, step by step)
3. Threat Actor Profile (TTPs, sophistication level)
4. MITRE ATT&CK Mapping
5. Indicators of Compromise
6. Affected Systems/Users
7. Recommendations for Response
8. Lessons Learned"""

    prompt = f"""Analyze the following security log data and provide expert incident analysis.

{analysis_focus}

## Log Summary
- **File**: {input_file}
- **Total Events**: {stats['total_events']}
- **Time Range**: {stats['time_range'].get('start', 'N/A')} to {stats['time_range'].get('end', 'N/A')}
- **Authentication**: {stats['auth_success']} successful, {stats['auth_failure']} failed

## Source IPs (by activity volume)
{json_lib.dumps(stats['source_ips'], indent=2)}

## Users (by activity volume)
{json_lib.dumps(stats['users'], indent=2)}

## Automated Detection Findings
{findings_text if findings_text else "No automated findings"}

## Sudo Commands Executed
{json_lib.dumps(stats['sudo_commands'][:20], indent=2) if stats['sudo_commands'] else "None detected"}

## User/Account Modifications
{json_lib.dumps(stats['user_modifications'][:10], indent=2) if stats['user_modifications'] else "None detected"}

## Key Events Sample
{json_lib.dumps(stats['key_events'][:30], indent=2)}

Based on this data, provide your expert security analysis."""

    # Get LLM client
    try:
        llm = get_llm_client(provider=provider, model=model)
        click.echo(f"   Using {llm.provider_name}/{llm.model_name}")
    except Exception as e:
        click.echo(f"❌ Error initializing LLM: {e}", err=True)
        sys.exit(2)
    
    # Generate analysis
    click.echo("🤖 Generating AI analysis (this may take a moment)...")
    
    response = llm.generate(
        prompt=prompt,
        system=system_prompt,
        max_tokens=4096,
        temperature=0.3
    )
    
    if response.error:
        click.echo(f"❌ LLM Error: {response.error}", err=True)
        sys.exit(2)
    
    if json_output:
        output_data = {
            'file': input_file,
            'provider': response.provider,
            'model': response.model,
            'focus': focus,
            'statistics': {
                'total_events': stats['total_events'],
                'time_range': stats['time_range'],
                'auth_success': stats['auth_success'],
                'auth_failure': stats['auth_failure'],
                'source_ips': stats['source_ips'],
                'users': stats['users'],
            },
            'automated_findings': [f.to_dict() for f in analysis_result.findings],
            'ai_analysis': response.content,
            'usage': response.usage,
        }
        
        if output:
            with open(output, 'w') as f:
                json_lib.dump(output_data, f, indent=2)
            click.echo(f"📄 Analysis saved to {output}")
        else:
            click.echo(json_lib.dumps(output_data, indent=2))
        return
    
    # Display results
    print_header(f"AI Log Analysis: {input_file}")
    click.echo(f"  {Colors.CYAN}Provider:{Colors.RESET} {response.provider}")
    click.echo(f"  {Colors.CYAN}Model:{Colors.RESET} {response.model}")
    click.echo(f"  {Colors.CYAN}Focus:{Colors.RESET} {focus}")
    if response.usage:
        click.echo(f"  {Colors.CYAN}Tokens:{Colors.RESET} {response.usage.get('input_tokens', 0)} in, {response.usage.get('output_tokens', 0)} out")
    click.echo()
    
    print_subheader("Analysis")
    click.echo(response.content)
    click.echo()
    
    if output:
        # Save as markdown
        with open(output, 'w') as f:
            f.write(f"# AI Log Analysis: {input_file}\n\n")
            f.write(f"**Provider**: {response.provider}  \n")
            f.write(f"**Model**: {response.model}  \n")
            f.write(f"**Focus**: {focus}  \n")
            f.write(f"**Events Analyzed**: {stats['total_events']}  \n\n")
            f.write("---\n\n")
            f.write(response.content)
        click.echo(f"📄 Analysis saved to: {output}")


@logs.command()
@click.option('--file', '-f', 'input_file', type=click.Path(exists=True), required=True,
              help='Log file')
@click.option('--format', '-F', 'log_format', default='auto', help='Log format')
@click.option('--top-ips', default=10, help='Show top N source IPs')
@click.option('--top-users', default=10, help='Show top N users')
@click.option('--by-hour', is_flag=True, help='Show hourly distribution')
@click.option('--json', 'json_output', is_flag=True, help='JSON output')
def stats(input_file, log_format, top_ips, top_users, by_hour, json_output):
    """
    Generate statistics from log file.
    
    \b
    Examples:
        bsot logs stats -f access.log
        bsot logs stats -f auth.log --top-ips 20 --by-hour
    """
    from .parsers import parse_log
    from collections import defaultdict
    from ..utils import Colors, print_header, print_subheader
    import re
    
    events = parse_log(input_file, log_format)
    
    if not events:
        click.echo(f"No events parsed from {input_file}")
        sys.exit(0)
    
    # Calculate stats
    stats_data = {
        'total_events': len(events),
        'source_ips': defaultdict(int),
        'users': defaultdict(int),
        'event_types': defaultdict(int),
        'hourly': defaultdict(int),
    }
    
    for event in events:
        if event.source_ip:
            stats_data['source_ips'][event.source_ip] += 1
        if event.user:
            stats_data['users'][event.user] += 1
        if event.event_type:
            stats_data['event_types'][event.event_type] += 1
        
        # Extract hour
        if event.timestamp_str:
            hour_match = re.search(r'(\d{2}):\d{2}:\d{2}', event.timestamp_str)
            if hour_match:
                stats_data['hourly'][int(hour_match.group(1))] += 1
    
    # Convert to sorted lists
    stats_data['source_ips'] = dict(sorted(stats_data['source_ips'].items(), key=lambda x: -x[1])[:top_ips])
    stats_data['users'] = dict(sorted(stats_data['users'].items(), key=lambda x: -x[1])[:top_users])
    stats_data['event_types'] = dict(stats_data['event_types'])
    stats_data['hourly'] = dict(sorted(stats_data['hourly'].items()))
    
    if json_output:
        click.echo(json_lib.dumps(stats_data, indent=2))
        return
    
    print_header(f"Log Statistics: {input_file}")
    click.echo(f"  Total Events: {stats_data['total_events']}")
    
    if stats_data['source_ips']:
        print_subheader(f"Top {top_ips} Source IPs")
        for ip, count in stats_data['source_ips'].items():
            pct = count / stats_data['total_events'] * 100
            bar = '█' * int(pct / 2)
            click.echo(f"  {ip:15} {count:6} ({pct:5.1f}%) {bar}")
    
    if stats_data['users']:
        print_subheader(f"Top {top_users} Users")
        for user, count in stats_data['users'].items():
            click.echo(f"  {user:20} {count}")
    
    if stats_data['event_types']:
        print_subheader("Event Types")
        for etype, count in stats_data['event_types'].items():
            click.echo(f"  {etype:20} {count}")
    
    if by_hour and stats_data['hourly']:
        print_subheader("Hourly Distribution")
        max_count = max(stats_data['hourly'].values()) if stats_data['hourly'] else 1
        for hour in range(24):
            count = stats_data['hourly'].get(hour, 0)
            bar_len = int(count / max_count * 40) if max_count > 0 else 0
            bar = '█' * bar_len
            click.echo(f"  {hour:02}:00 {count:5} {bar}")


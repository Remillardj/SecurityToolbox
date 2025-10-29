#!/usr/bin/env python3
"""
Log Pattern Analyzer - Security Toolbox
Analyzes log files to detect various patterns including IPs, strings, sequences, and custom patterns.
"""

import re
import argparse
import sys
import json
from collections import defaultdict, Counter
from datetime import datetime
import ipaddress
from pathlib import Path
import socket
from typing import Dict, List, Any, Optional

class LogPatternAnalyzer:
    def __init__(self, custom_patterns: Optional[Dict[str, str]] = None):
        # IP address patterns
        self.ipv4_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        self.ipv6_pattern = re.compile(
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b'
        )
        
        # General pattern detection
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.url_pattern = re.compile(r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?')
        self.phone_pattern = re.compile(r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b')
        self.credit_card_pattern = re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')
        self.ssn_pattern = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
        
        # Security-related patterns
        self.failed_login_patterns = [
            re.compile(r'(?i)(failed|invalid|incorrect|wrong).*?(login|password|authentication)', re.IGNORECASE),
            re.compile(r'(?i)(authentication failed|login failed)', re.IGNORECASE),
            re.compile(r'(?i)(access denied|permission denied)', re.IGNORECASE)
        ]
        
        # Attack sequence patterns for detecting successful attacks
        self.successful_login_patterns = [
            re.compile(r'(?i)(login successful|authentication successful|access granted)', re.IGNORECASE),
            re.compile(r'(?i)(user.*?logged in|user.*?authenticated)', re.IGNORECASE),
            re.compile(r'(?i)(session.*?established|connection.*?established)', re.IGNORECASE),
            re.compile(r'(?i)(welcome.*?user|hello.*?user)', re.IGNORECASE)
        ]
        
        # Username extraction patterns
        self.username_patterns = [
            re.compile(r'(?i)(?:user|username|login|account):\s*([a-zA-Z0-9_.-]+)', re.IGNORECASE),
            re.compile(r'(?i)(?:for|as)\s+user\s+([a-zA-Z0-9_.-]+)', re.IGNORECASE),
            re.compile(r'(?i)([a-zA-Z0-9_.-]+)\s+(?:logged in|authenticated|successful)', re.IGNORECASE),
            re.compile(r'(?i)(?:user|account)\s+([a-zA-Z0-9_.-]+)\s+(?:successful|granted)', re.IGNORECASE),
            re.compile(r'(?i)(?:failed password for|invalid user|authentication failure for)\s+([a-zA-Z0-9_.-]+)', re.IGNORECASE),
            re.compile(r'(?i)(?:for|user)\s+([a-zA-Z0-9_.-]+)\s+(?:from|port)', re.IGNORECASE)
        ]
        
        # Brute force attack indicators
        self.brute_force_patterns = [
            re.compile(r'(?i)(brute force|dictionary attack|password spray)', re.IGNORECASE),
            re.compile(r'(?i)(multiple.*?failed.*?attempts|repeated.*?failures)', re.IGNORECASE),
            re.compile(r'(?i)(too many.*?attempts|excessive.*?attempts)', re.IGNORECASE)
        ]
        
        self.suspicious_url_patterns = [
            re.compile(r'(?i)(admin|login|phpmyadmin|wp-admin)', re.IGNORECASE),
            re.compile(r'(?i)(\.php\?|\.asp\?|\.jsp\?)', re.IGNORECASE),
            re.compile(r'(?i)(union|select|insert|delete|drop|exec)', re.IGNORECASE)
        ]
        
        self.attack_patterns = [
            re.compile(r'(?i)(sql injection|xss|csrf)', re.IGNORECASE),
            re.compile(r'(?i)(brute force|dictionary attack)', re.IGNORECASE),
            re.compile(r'(?i)(malware|virus|trojan)', re.IGNORECASE),
            re.compile(r'(?i)(exploit|vulnerability|cve-)', re.IGNORECASE)
        ]
        
        # Custom patterns from user
        self.custom_patterns = {}
        if custom_patterns:
            for name, pattern in custom_patterns.items():
                try:
                    self.custom_patterns[name] = re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    print(f"Warning: Invalid regex pattern '{pattern}' for '{name}': {e}")
        
        # Common log formats
        self.log_formats = {
            'apache': re.compile(r'^(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+|-)'),
            'nginx': re.compile(r'^(\S+) - (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)"'),
            'syslog': re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s*(.*)')
        }
        
        # Results storage
        self.results = {
            'ip_addresses': defaultdict(int),
            'emails': defaultdict(int),
            'urls': defaultdict(int),
            'phone_numbers': defaultdict(int),
            'credit_cards': defaultdict(int),
            'ssns': defaultdict(int),
            'custom_patterns': defaultdict(lambda: defaultdict(int)),
            'string_frequency': defaultdict(int),
            'failed_logins': [],
            'successful_logins': [],
            'usernames': defaultdict(int),
            'brute_force_attempts': [],
            'attack_sequences': [],
            'suspicious_urls': [],
            'attack_patterns': [],
            'private_ips': defaultdict(int),
            'public_ips': defaultdict(int),
            'timeline': defaultdict(list),
            'statistics': {},
            'sequence_patterns': defaultdict(list),
            'repeated_strings': defaultdict(int),
            'attack_scenarios': [],
            'suspicious_logins': [],
            'login_correlations': defaultdict(list)
        }

    def is_private_ip(self, ip_str):
        """Check if an IP address is private"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False

    def get_ip_info(self, ip_str):
        """Get basic information about an IP address"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return {
                'version': ip.version,
                'is_private': ip.is_private,
                'is_loopback': ip.is_loopback,
                'is_multicast': ip.is_multicast,
                'is_reserved': ip.is_reserved
            }
        except ValueError:
            return None

    def analyze_line(self, line, line_number):
        """Analyze a single log line for patterns"""
        # Extract IP addresses
        ipv4_matches = self.ipv4_pattern.findall(line)
        ipv6_matches = self.ipv6_pattern.findall(line)
        
        for ip in ipv4_matches + ipv6_matches:
            self.results['ip_addresses'][ip] += 1
            
            # Categorize IPs
            if self.is_private_ip(ip):
                self.results['private_ips'][ip] += 1
            else:
                self.results['public_ips'][ip] += 1
        
        # Extract emails
        email_matches = self.email_pattern.findall(line)
        for email in email_matches:
            self.results['emails'][email] += 1
        
        # Extract URLs
        url_matches = self.url_pattern.findall(line)
        for url in url_matches:
            self.results['urls'][url] += 1
        
        # Extract phone numbers
        phone_matches = self.phone_pattern.findall(line)
        for phone in phone_matches:
            phone_str = '-'.join(phone) if isinstance(phone, tuple) else phone
            self.results['phone_numbers'][phone_str] += 1
        
        # Extract credit card numbers
        cc_matches = self.credit_card_pattern.findall(line)
        for cc in cc_matches:
            self.results['credit_cards'][cc] += 1
        
        # Extract SSNs
        ssn_matches = self.ssn_pattern.findall(line)
        for ssn in ssn_matches:
            self.results['ssns'][ssn] += 1
        
        # Check custom patterns
        for pattern_name, pattern in self.custom_patterns.items():
            matches = pattern.findall(line)
            for match in matches:
                self.results['custom_patterns'][pattern_name][match] += 1
        
        # String frequency analysis - extract common words/phrases
        words = re.findall(r'\b\w{3,}\b', line.lower())
        for word in words:
            self.results['string_frequency'][word] += 1
        
        # Look for repeated strings (sequences of characters)
        repeated_pattern = re.compile(r'(.{3,})\1+')
        repeated_matches = repeated_pattern.findall(line)
        for match in repeated_matches:
            self.results['repeated_strings'][match] += 1
        
        # Check for failed login attempts
        for pattern in self.failed_login_patterns:
            if pattern.search(line):
                username = self.extract_username(line)
                self.results['failed_logins'].append({
                    'line_number': line_number,
                    'line': line.strip(),
                    'timestamp': self.extract_timestamp(line),
                    'username': username
                })
                break
        
        # Check for successful login attempts
        for pattern in self.successful_login_patterns:
            if pattern.search(line):
                username = self.extract_username(line)
                self.results['successful_logins'].append({
                    'line_number': line_number,
                    'line': line.strip(),
                    'timestamp': self.extract_timestamp(line),
                    'username': username
                })
                if username:
                    self.results['usernames'][username] += 1
                break
        
        # Detect attack sequences
        attack_sequence = self.detect_attack_sequence(line, line_number)
        if attack_sequence:
            self.results['attack_sequences'].append(attack_sequence)
            if attack_sequence['type'] == 'brute_force_indicator':
                self.results['brute_force_attempts'].append(attack_sequence)
        
        # Check for suspicious URLs
        for pattern in self.suspicious_url_patterns:
            if pattern.search(line):
                self.results['suspicious_urls'].append({
                    'line_number': line_number,
                    'line': line.strip(),
                    'pattern_matched': pattern.pattern
                })
                break
        
        # Check for attack patterns
        for pattern in self.attack_patterns:
            if pattern.search(line):
                self.results['attack_patterns'].append({
                    'line_number': line_number,
                    'line': line.strip(),
                    'pattern_matched': pattern.pattern
                })
                break
        
        # Extract timestamp for timeline analysis
        timestamp = self.extract_timestamp(line)
        if timestamp:
            self.results['timeline'][timestamp].append(line_number)

    def extract_timestamp(self, line):
        """Extract timestamp from log line"""
        # Common timestamp patterns
        timestamp_patterns = [
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',
            r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})',
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        return None

    def extract_username(self, line):
        """Extract username from log line"""
        for pattern in self.username_patterns:
            match = pattern.search(line)
            if match:
                username = match.group(1).strip()
                # Basic validation - usernames shouldn't be too long or contain special chars
                if 3 <= len(username) <= 32 and re.match(r'^[a-zA-Z0-9_.-]+$', username):
                    return username
        return None

    def detect_attack_sequence(self, line, line_number):
        """Detect if this line is part of an attack sequence"""
        # Check for brute force indicators
        for pattern in self.brute_force_patterns:
            if pattern.search(line):
                return {
                    'type': 'brute_force_indicator',
                    'line_number': line_number,
                    'line': line.strip(),
                    'timestamp': self.extract_timestamp(line)
                }
        
        # Check for successful login after failed attempts
        for pattern in self.successful_login_patterns:
            if pattern.search(line):
                username = self.extract_username(line)
                return {
                    'type': 'successful_login',
                    'line_number': line_number,
                    'line': line.strip(),
                    'timestamp': self.extract_timestamp(line),
                    'username': username
                }
        
        return None

    def analyze_file(self, file_path):
        """Analyze a log file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_number, line in enumerate(f, 1):
                    self.analyze_line(line, line_number)
        except FileNotFoundError:
            print(f"Error: File '{file_path}' not found.")
            return False
        except PermissionError:
            print(f"Error: Permission denied accessing '{file_path}'.")
            return False
        except Exception as e:
            print(f"Error reading file '{file_path}': {e}")
            return False
        
        return True

    def analyze_attack_scenarios(self):
        """Analyze attack scenarios by correlating failed and successful logins"""
        # Group failed logins by username and IP
        failed_by_user = defaultdict(list)
        failed_by_ip = defaultdict(list)
        
        for attempt in self.results['failed_logins']:
            if attempt.get('username'):
                failed_by_user[attempt['username']].append(attempt)
            # Extract IP from line if possible
            ip_matches = self.ipv4_pattern.findall(attempt['line'])
            if ip_matches:
                failed_by_ip[ip_matches[0]].append(attempt)
        
        # Check for successful logins after failed attempts
        for success in self.results['successful_logins']:
            username = success.get('username')
            if username and username in failed_by_user:
                # Found successful login after failed attempts for same user
                failed_attempts = failed_by_user[username]
                scenario = {
                    'type': 'brute_force_success',
                    'username': username,
                    'successful_login': success,
                    'failed_attempts': failed_attempts,
                    'total_failed_attempts': len(failed_attempts),
                    'time_range': {
                        'first_failed': min(attempt['timestamp'] for attempt in failed_attempts if attempt['timestamp']),
                        'last_failed': max(attempt['timestamp'] for attempt in failed_attempts if attempt['timestamp']),
                        'successful': success['timestamp']
                    } if all(attempt['timestamp'] for attempt in failed_attempts) and success['timestamp'] else None
                }
                self.results['attack_scenarios'].append(scenario)
        
        # Check for brute force patterns by IP
        for ip, attempts in failed_by_ip.items():
            if len(attempts) >= 5:  # Threshold for brute force
                usernames_attempted = set(attempt.get('username') for attempt in attempts if attempt.get('username'))
                scenario = {
                    'type': 'brute_force_by_ip',
                    'source_ip': ip,
                    'attempts': attempts,
                    'usernames_attempted': list(usernames_attempted),
                    'total_attempts': len(attempts)
                }
                self.results['attack_scenarios'].append(scenario)

    def detect_suspicious_logins(self):
        """Detect successful logins that are tied to suspicious activity"""
        # Group logins by IP address
        logins_by_ip = defaultdict(list)
        
        # Collect all login attempts (both failed and successful) by IP
        for attempt in self.results['failed_logins']:
            ip_matches = self.ipv4_pattern.findall(attempt['line'])
            if ip_matches:
                ip = ip_matches[0]
                logins_by_ip[ip].append({
                    'type': 'failed',
                    'line_number': attempt['line_number'],
                    'timestamp': attempt['timestamp'],
                    'username': attempt.get('username'),
                    'line': attempt['line']
                })
        
        for success in self.results['successful_logins']:
            ip_matches = self.ipv4_pattern.findall(success['line'])
            if ip_matches:
                ip = ip_matches[0]
                logins_by_ip[ip].append({
                    'type': 'successful',
                    'line_number': success['line_number'],
                    'timestamp': success['timestamp'],
                    'username': success.get('username'),
                    'line': success['line']
                })
        
        # Analyze each IP's login patterns
        for ip, attempts in logins_by_ip.items():
            if len(attempts) < 2:  # Need at least 2 attempts to be suspicious
                continue
            
            # Sort by line number to maintain chronological order
            attempts.sort(key=lambda x: x['line_number'])
            
            # Check for suspicious patterns
            suspicious_patterns = []
            
            # Pattern 1: Multiple failed attempts followed by success
            failed_count = sum(1 for attempt in attempts if attempt['type'] == 'failed')
            successful_count = sum(1 for attempt in attempts if attempt['type'] == 'successful')
            
            if failed_count >= 3 and successful_count >= 1:
                # Find the successful login after failures
                successful_attempts = [a for a in attempts if a['type'] == 'successful']
                failed_attempts = [a for a in attempts if a['type'] == 'failed']
                
                for success in successful_attempts:
                    # Check if this success came after multiple failures
                    failed_before = [f for f in failed_attempts if f['line_number'] < success['line_number']]
                    
                    if len(failed_before) >= 3:
                        suspicious_patterns.append({
                            'pattern': 'brute_force_success',
                            'severity': 'high',
                            'description': f'Successful login after {len(failed_before)} failed attempts',
                            'successful_login': success,
                            'failed_attempts': failed_before,
                            'source_ip': ip
                        })
            
            # Pattern 2: Rapid successive logins (potential automated attack)
            if len(attempts) >= 5:
                rapid_logins = []
                for i in range(len(attempts) - 4):
                    # Check if 5 attempts happened within 10 lines (rapid succession)
                    if attempts[i+4]['line_number'] - attempts[i]['line_number'] <= 10:
                        rapid_logins = attempts[i:i+5]
                        break
                
                if rapid_logins:
                    suspicious_patterns.append({
                        'pattern': 'rapid_succession',
                        'severity': 'medium',
                        'description': f'Rapid succession of {len(rapid_logins)} login attempts',
                        'attempts': rapid_logins,
                        'source_ip': ip
                    })
            
            # Pattern 3: Multiple usernames from same IP (username enumeration)
            usernames = set(attempt.get('username') for attempt in attempts if attempt.get('username'))
            if len(usernames) >= 3:
                suspicious_patterns.append({
                    'pattern': 'username_enumeration',
                    'severity': 'medium',
                    'description': f'Attempted login with {len(usernames)} different usernames',
                    'usernames': list(usernames),
                    'attempts': attempts,
                    'source_ip': ip
                })
            
            # Pattern 4: Successful login from IP with high failure rate
            failure_rate = failed_count / len(attempts)
            if failure_rate >= 0.7 and successful_count >= 1:
                successful_attempts = [a for a in attempts if a['type'] == 'successful']
                suspicious_patterns.append({
                    'pattern': 'high_failure_rate_success',
                    'severity': 'high',
                    'description': f'Successful login despite {failure_rate:.1%} failure rate',
                    'successful_logins': successful_attempts,
                    'failure_rate': failure_rate,
                    'source_ip': ip
                })
            
            # Add all suspicious patterns found for this IP
            for pattern in suspicious_patterns:
                self.results['suspicious_logins'].append(pattern)

    def generate_statistics(self):
        """Generate summary statistics"""
        total_lines = sum(len(lines) for lines in self.results['timeline'].values())
        
        self.results['statistics'] = {
            'total_ip_addresses': len(self.results['ip_addresses']),
            'unique_private_ips': len(self.results['private_ips']),
            'unique_public_ips': len(self.results['public_ips']),
            'unique_emails': len(self.results['emails']),
            'unique_urls': len(self.results['urls']),
            'unique_phone_numbers': len(self.results['phone_numbers']),
            'unique_credit_cards': len(self.results['credit_cards']),
            'unique_ssns': len(self.results['ssns']),
            'unique_custom_patterns': {name: len(patterns) for name, patterns in self.results['custom_patterns'].items()},
            'unique_strings': len(self.results['string_frequency']),
            'unique_repeated_strings': len(self.results['repeated_strings']),
            'unique_usernames': len(self.results['usernames']),
            'failed_login_attempts': len(self.results['failed_logins']),
            'successful_login_attempts': len(self.results['successful_logins']),
            'brute_force_attempts': len(self.results['brute_force_attempts']),
            'attack_sequences': len(self.results['attack_sequences']),
            'attack_scenarios': len(self.results['attack_scenarios']),
            'suspicious_logins': len(self.results['suspicious_logins']),
            'suspicious_urls_found': len(self.results['suspicious_urls']),
            'attack_patterns_found': len(self.results['attack_patterns']),
            'total_log_lines': total_lines,
            'most_frequent_ip': max(self.results['ip_addresses'].items(), key=lambda x: x[1]) if self.results['ip_addresses'] else None,
            'most_frequent_email': max(self.results['emails'].items(), key=lambda x: x[1]) if self.results['emails'] else None,
            'most_frequent_url': max(self.results['urls'].items(), key=lambda x: x[1]) if self.results['urls'] else None,
            'most_frequent_string': max(self.results['string_frequency'].items(), key=lambda x: x[1]) if self.results['string_frequency'] else None,
            'most_frequent_repeated_string': max(self.results['repeated_strings'].items(), key=lambda x: x[1]) if self.results['repeated_strings'] else None,
            'most_frequent_username': max(self.results['usernames'].items(), key=lambda x: x[1]) if self.results['usernames'] else None,
            'most_frequent_private_ip': max(self.results['private_ips'].items(), key=lambda x: x[1]) if self.results['private_ips'] else None,
            'most_frequent_public_ip': max(self.results['public_ips'].items(), key=lambda x: x[1]) if self.results['public_ips'] else None
        }

    def print_results(self, output_format='text', focus=None, query=None):
        """Print analysis results with optional focus or query"""
        if output_format == 'json':
            print(json.dumps(self.results, indent=2, default=str))
            return
        
        # Handle specific queries
        if query:
            self.handle_query(query)
            return
        
        # Handle focused output
        if focus:
            self.print_focused_results(focus)
            return
        
        print("=" * 80)
        print("LOG PATTERN ANALYSIS RESULTS")
        print("=" * 80)
        
        # Statistics
        stats = self.results['statistics']
        print(f"\nSUMMARY STATISTICS:")
        print(f"Total log lines analyzed: {stats['total_log_lines']}")
        print(f"Unique IP addresses found: {stats['total_ip_addresses']}")
        print(f"Private IPs: {stats['unique_private_ips']}")
        print(f"Public IPs: {stats['unique_public_ips']}")
        print(f"Unique emails: {stats['unique_emails']}")
        print(f"Unique URLs: {stats['unique_urls']}")
        print(f"Unique phone numbers: {stats['unique_phone_numbers']}")
        print(f"Unique credit cards: {stats['unique_credit_cards']}")
        print(f"Unique SSNs: {stats['unique_ssns']}")
        print(f"Unique strings: {stats['unique_strings']}")
        print(f"Unique repeated strings: {stats['unique_repeated_strings']}")
        print(f"Unique usernames: {stats['unique_usernames']}")
        print(f"Failed login attempts: {stats['failed_login_attempts']}")
        print(f"Successful login attempts: {stats['successful_login_attempts']}")
        print(f"Brute force attempts: {stats['brute_force_attempts']}")
        print(f"Attack sequences: {stats['attack_sequences']}")
        print(f"Attack scenarios: {stats['attack_scenarios']}")
        print(f"Suspicious logins: {stats['suspicious_logins']}")
        print(f"Suspicious URLs: {stats['suspicious_urls_found']}")
        print(f"Attack patterns: {stats['attack_patterns_found']}")
        
        # Most frequent items
        if stats['most_frequent_ip']:
            print(f"\nMost frequent IP: {stats['most_frequent_ip'][0]} ({stats['most_frequent_ip'][1]} occurrences)")
        
        if stats['most_frequent_email']:
            print(f"Most frequent email: {stats['most_frequent_email'][0]} ({stats['most_frequent_email'][1]} occurrences)")
        
        if stats['most_frequent_url']:
            print(f"Most frequent URL: {stats['most_frequent_url'][0]} ({stats['most_frequent_url'][1]} occurrences)")
        
        if stats['most_frequent_string']:
            print(f"Most frequent string: '{stats['most_frequent_string'][0]}' ({stats['most_frequent_string'][1]} occurrences)")
        
        if stats['most_frequent_repeated_string']:
            print(f"Most frequent repeated string: '{stats['most_frequent_repeated_string'][0]}' ({stats['most_frequent_repeated_string'][1]} occurrences)")
        
        # Top IP addresses
        if self.results['ip_addresses']:
            print(f"\nTOP 10 IP ADDRESSES:")
            sorted_ips = sorted(self.results['ip_addresses'].items(), key=lambda x: x[1], reverse=True)
            for ip, count in sorted_ips[:10]:
                ip_type = "Private" if self.is_private_ip(ip) else "Public"
                print(f"  {ip:<15} {count:>6} occurrences ({ip_type})")
        
        # Top emails
        if self.results['emails']:
            print(f"\nTOP 10 EMAIL ADDRESSES:")
            sorted_emails = sorted(self.results['emails'].items(), key=lambda x: x[1], reverse=True)
            for email, count in sorted_emails[:10]:
                print(f"  {email:<30} {count:>6} occurrences")
        
        # Top URLs
        if self.results['urls']:
            print(f"\nTOP 10 URLs:")
            sorted_urls = sorted(self.results['urls'].items(), key=lambda x: x[1], reverse=True)
            for url, count in sorted_urls[:10]:
                print(f"  {url:<50} {count:>6} occurrences")
        
        # Top strings
        if self.results['string_frequency']:
            print(f"\nTOP 20 MOST FREQUENT STRINGS:")
            sorted_strings = sorted(self.results['string_frequency'].items(), key=lambda x: x[1], reverse=True)
            for string, count in sorted_strings[:20]:
                print(f"  '{string:<20}' {count:>6} occurrences")
        
        # Repeated strings
        if self.results['repeated_strings']:
            print(f"\nREPEATED STRING PATTERNS:")
            sorted_repeated = sorted(self.results['repeated_strings'].items(), key=lambda x: x[1], reverse=True)
            for pattern, count in sorted_repeated[:10]:
                print(f"  '{pattern:<20}' {count:>6} occurrences")
        
        # Custom patterns
        if self.results['custom_patterns']:
            print(f"\nCUSTOM PATTERN RESULTS:")
            for pattern_name, patterns in self.results['custom_patterns'].items():
                if patterns:
                    print(f"\n{pattern_name.upper()}:")
                    sorted_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)
                    for match, count in sorted_patterns[:10]:
                        print(f"  '{match:<30}' {count:>6} occurrences")
        
        # Sensitive data warnings
        if self.results['credit_cards'] or self.results['ssns']:
            print(f"\n⚠️  SENSITIVE DATA DETECTED:")
            if self.results['credit_cards']:
                print(f"  Credit card numbers found: {len(self.results['credit_cards'])} unique")
            if self.results['ssns']:
                print(f"  SSNs found: {len(self.results['ssns'])} unique")
        
        # Failed logins
        if self.results['failed_logins']:
            print(f"\nFAILED LOGIN ATTEMPTS ({len(self.results['failed_logins'])} found):")
            for attempt in self.results['failed_logins'][:10]:  # Show first 10
                timestamp_info = f" at {attempt.get('timestamp', 'Unknown')}" if attempt.get('timestamp') else ""
                username_info = f" (user: {attempt.get('username', 'Unknown')})" if attempt.get('username') else ""
                print(f"  Line {attempt['line_number']}{timestamp_info}{username_info}: {attempt['line'][:100]}...")
        
        # Suspicious URLs
        if self.results['suspicious_urls']:
            print(f"\nSUSPICIOUS URLs ({len(self.results['suspicious_urls'])} found):")
            for url in self.results['suspicious_urls'][:10]:  # Show first 10
                print(f"  Line {url['line_number']}: {url['line'][:100]}...")
        
        # Attack patterns
        if self.results['attack_patterns']:
            print(f"\nATTACK PATTERNS ({len(self.results['attack_patterns'])} found):")
            for attack in self.results['attack_patterns'][:10]:  # Show first 10
                print(f"  Line {attack['line_number']}: {attack['line'][:100]}...")
        
        # Attack scenarios - this is the key section for your question!
        if self.results['attack_scenarios']:
            print(f"\n🚨 ATTACK SCENARIOS DETECTED ({len(self.results['attack_scenarios'])} found):")
            for i, scenario in enumerate(self.results['attack_scenarios'], 1):
                if scenario['type'] == 'brute_force_success':
                    print(f"\n  SCENARIO {i}: SUCCESSFUL BRUTE FORCE ATTACK")
                    print(f"    🎯 COMPROMISED USERNAME: {scenario['username']}")
                    print(f"    📊 Failed attempts before success: {scenario['total_failed_attempts']}")
                    print(f"    ✅ Successful login at line {scenario['successful_login']['line_number']}")
                    print(f"    📝 Success log: {scenario['successful_login']['line'][:80]}...")
                    print(f"    ⏰ Success timestamp: {scenario['successful_login'].get('timestamp', 'Unknown')}")
                    if scenario.get('time_range'):
                        print(f"    ⏰ Time range: {scenario['time_range']['first_failed']} → {scenario['time_range']['successful']}")
                
                elif scenario['type'] == 'brute_force_by_ip':
                    print(f"\n  SCENARIO {i}: BRUTE FORCE ATTACK BY IP")
                    print(f"    🌐 Source IP: {scenario['source_ip']}")
                    print(f"    📊 Total attempts: {scenario['total_attempts']}")
                    print(f"    👥 Usernames targeted: {', '.join(scenario['usernames_attempted'])}")
        
        # Top usernames
        if self.results['usernames']:
            print(f"\nTOP 10 USERNAMES:")
            sorted_usernames = sorted(self.results['usernames'].items(), key=lambda x: x[1], reverse=True)
            for username, count in sorted_usernames[:10]:
                print(f"  {username:<20} {count:>6} occurrences")
        
        # Successful logins
        if self.results['successful_logins']:
            print(f"\nSUCCESSFUL LOGINS ({len(self.results['successful_logins'])} found):")
            for login in self.results['successful_logins'][:10]:  # Show first 10
                username_info = f" (user: {login['username']})" if login.get('username') else ""
                timestamp_info = f" at {login.get('timestamp', 'Unknown')}" if login.get('timestamp') else ""
                print(f"  Line {login['line_number']}{timestamp_info}{username_info}: {login['line'][:100]}...")
        
        # Suspicious logins - this is the key section for your question!
        if self.results['suspicious_logins']:
            print(f"\n🚨 SUSPICIOUS LOGINS DETECTED ({len(self.results['suspicious_logins'])} found):")
            for i, suspicious in enumerate(self.results['suspicious_logins'], 1):
                print(f"\n  SUSPICIOUS LOGIN {i}:")
                print(f"    🔍 Pattern: {suspicious['pattern']}")
                print(f"    ⚠️  Severity: {suspicious['severity'].upper()}")
                print(f"    📝 Description: {suspicious['description']}")
                print(f"    🌐 Source IP: {suspicious['source_ip']}")
                
                if suspicious['pattern'] == 'brute_force_success':
                    success = suspicious['successful_login']
                    print(f"    ✅ Successful login:")
                    print(f"      - Username: {success.get('username', 'Unknown')}")
                    print(f"      - Line: {success['line_number']}")
                    print(f"      - Timestamp: {success.get('timestamp', 'Unknown')}")
                    print(f"      - Log: {success['line'][:80]}...")
                    print(f"    ❌ Failed attempts before success: {len(suspicious['failed_attempts'])}")
                    if suspicious['failed_attempts']:
                        first_failed = suspicious['failed_attempts'][0]
                        last_failed = suspicious['failed_attempts'][-1]
                        print(f"      - First failed: {first_failed.get('timestamp', 'Unknown')} (line {first_failed['line_number']})")
                        print(f"      - Last failed: {last_failed.get('timestamp', 'Unknown')} (line {last_failed['line_number']})")
                
                elif suspicious['pattern'] == 'rapid_succession':
                    print(f"    ⚡ Rapid attempts:")
                    for attempt in suspicious['attempts'][:3]:  # Show first 3
                        timestamp_info = f" at {attempt.get('timestamp', 'Unknown')}" if attempt.get('timestamp') else ""
                        print(f"      - Line {attempt['line_number']}{timestamp_info}: {attempt['type']} ({attempt.get('username', 'Unknown')})")
                
                elif suspicious['pattern'] == 'username_enumeration':
                    print(f"    👥 Usernames attempted: {', '.join(suspicious['usernames'])}")
                
                elif suspicious['pattern'] == 'high_failure_rate_success':
                    print(f"    📊 Failure rate: {suspicious['failure_rate']:.1%}")
                    for success in suspicious['successful_logins']:
                        timestamp_info = f" at {success.get('timestamp', 'Unknown')}" if success.get('timestamp') else ""
                        print(f"      - Successful login: {success.get('username', 'Unknown')} at line {success['line_number']}{timestamp_info}")

    def print_focused_results(self, focus):
        """Print only the requested information"""
        focus_lower = focus.lower()
        
        if focus_lower in ['ip', 'ips', 'ip_addresses']:
            if self.results['ip_addresses']:
                sorted_ips = sorted(self.results['ip_addresses'].items(), key=lambda x: x[1], reverse=True)
                print("Most frequent IP addresses:")
                for ip, count in sorted_ips[:10]:
                    ip_type = "Private" if self.is_private_ip(ip) else "Public"
                    print(f"{ip} ({count} occurrences, {ip_type})")
            else:
                print("No IP addresses found.")
        
        elif focus_lower in ['brute_force', 'brute', 'attack']:
            if self.results['attack_scenarios']:
                print("Brute force attacks detected:")
                for i, scenario in enumerate(self.results['attack_scenarios'], 1):
                    if scenario['type'] == 'brute_force_success':
                        print(f"Successful brute force attack on username: {scenario['username']}")
                    elif scenario['type'] == 'brute_force_by_ip':
                        print(f"Brute force from IP: {scenario['source_ip']} ({scenario['total_attempts']} attempts)")
            else:
                print("No brute force attacks detected.")
        
        elif focus_lower in ['username', 'usernames', 'users']:
            if self.results['usernames']:
                sorted_users = sorted(self.results['usernames'].items(), key=lambda x: x[1], reverse=True)
                print("Most frequent usernames:")
                for username, count in sorted_users[:10]:
                    print(f"{username} ({count} occurrences)")
            else:
                print("No usernames found.")
        
        elif focus_lower in ['compromised', 'successful_login', 'successful']:
            if self.results['attack_scenarios']:
                compromised_users = []
                for scenario in self.results['attack_scenarios']:
                    if scenario['type'] == 'brute_force_success':
                        compromised_users.append(scenario['username'])
                
                if compromised_users:
                    print("Compromised usernames:")
                    for user in compromised_users:
                        print(f"- {user}")
                else:
                    print("No compromised accounts detected.")
            else:
                print("No compromised accounts detected.")
        
        elif focus_lower in ['email', 'emails']:
            if self.results['emails']:
                sorted_emails = sorted(self.results['emails'].items(), key=lambda x: x[1], reverse=True)
                print("Most frequent email addresses:")
                for email, count in sorted_emails[:10]:
                    print(f"{email} ({count} occurrences)")
            else:
                print("No email addresses found.")
        
        elif focus_lower in ['url', 'urls']:
            if self.results['urls']:
                sorted_urls = sorted(self.results['urls'].items(), key=lambda x: x[1], reverse=True)
                print("Most frequent URLs:")
                for url, count in sorted_urls[:10]:
                    print(f"{url} ({count} occurrences)")
            else:
                print("No URLs found.")
        
        elif focus_lower in ['suspicious', 'suspicious_logins', 'suspicious_login']:
            if self.results['suspicious_logins']:
                print("Suspicious logins detected:")
                for i, suspicious in enumerate(self.results['suspicious_logins'], 1):
                    print(f"{i}. {suspicious['pattern']} - {suspicious['description']}")
                    print(f"   Source IP: {suspicious['source_ip']} (Severity: {suspicious['severity']})")
                    if suspicious['pattern'] == 'brute_force_success':
                        print(f"   Compromised username: {suspicious['successful_login'].get('username', 'Unknown')}")
            else:
                print("No suspicious logins detected.")
        
        elif focus_lower in ['timeline', 'time', 'timestamps']:
            print("Timeline of events:")
            timeline_events = []
            
            # Collect all events with timestamps
            for attempt in self.results['failed_logins']:
                if attempt.get('timestamp'):
                    timeline_events.append({
                        'timestamp': attempt['timestamp'],
                        'type': 'failed_login',
                        'line': attempt['line_number'],
                        'username': attempt.get('username', 'Unknown'),
                        'description': 'Failed login attempt'
                    })
            
            for success in self.results['successful_logins']:
                if success.get('timestamp'):
                    timeline_events.append({
                        'timestamp': success['timestamp'],
                        'type': 'successful_login',
                        'line': success['line_number'],
                        'username': success.get('username', 'Unknown'),
                        'description': 'Successful login'
                    })
            
            # Sort by timestamp
            timeline_events.sort(key=lambda x: x['timestamp'])
            
            if timeline_events:
                for event in timeline_events[:20]:  # Show first 20 events
                    print(f"  {event['timestamp']} - {event['description']} by {event['username']} (line {event['line']})")
            else:
                print("No timestamped events found.")
        
        else:
            print(f"Unknown focus option: {focus}")
            print("Available options: ip, brute_force, username, compromised, email, url, suspicious, timeline")

    def handle_query(self, query):
        """Handle specific queries like 'What is the username of the compromised account?'"""
        query_lower = query.lower()
        
        # Handle brute force compromise questions
        if any(word in query_lower for word in ['brute', 'force', 'compromised', 'successful', 'attack']):
            if any(word in query_lower for word in ['username', 'user', 'account']):
                compromised_users = []
                for scenario in self.results['attack_scenarios']:
                    if scenario['type'] == 'brute_force_success':
                        compromised_users.append(scenario['username'])
                
                if compromised_users:
                    if len(compromised_users) == 1:
                        print(f"Answer: {compromised_users[0]}")
                    else:
                        print(f"Answer: {', '.join(compromised_users)}")
                else:
                    print("Answer: No compromised accounts found.")
                return
        
        # Handle most frequent IP questions
        if any(word in query_lower for word in ['most', 'frequent', 'common']) and any(word in query_lower for word in ['ip', 'address']):
            if self.results['ip_addresses']:
                most_frequent = max(self.results['ip_addresses'].items(), key=lambda x: x[1])
                print(f"Answer: {most_frequent[0]} ({most_frequent[1]} occurrences)")
            else:
                print("Answer: No IP addresses found.")
            return
        
        # Handle brute force IP questions
        if any(word in query_lower for word in ['brute', 'force']) and any(word in query_lower for word in ['ip', 'address']):
            brute_force_ips = []
            for scenario in self.results['attack_scenarios']:
                if scenario['type'] == 'brute_force_by_ip':
                    brute_force_ips.append(scenario['source_ip'])
            
            if brute_force_ips:
                print(f"Answer: {', '.join(brute_force_ips)}")
            else:
                print("Answer: No brute force IPs detected.")
            return
        
        # Handle suspicious login questions
        if any(word in query_lower for word in ['suspicious', 'login', 'activity']):
            if self.results['suspicious_logins']:
                print("Answer: Suspicious logins detected:")
                for i, suspicious in enumerate(self.results['suspicious_logins'], 1):
                    print(f"  {i}. {suspicious['pattern']} from IP {suspicious['source_ip']}")
                    if suspicious['pattern'] == 'brute_force_success':
                        print(f"     Compromised username: {suspicious['successful_login'].get('username', 'Unknown')}")
            else:
                print("Answer: No suspicious logins detected.")
            return
        
        # Default response for unrecognized queries
        print("Query not recognized. Try asking about:")
        print("- 'What is the username of the compromised account?'")
        print("- 'What is the most frequent IP address?'")
        print("- 'What IP performed brute force attacks?'")
        print("- 'Are there any suspicious logins?'")

def main():
    parser = argparse.ArgumentParser(description='Analyze log files for patterns and security indicators')
    parser.add_argument('log_file', help='Path to the log file to analyze')
    parser.add_argument('-o', '--output', choices=['text', 'json'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('-p', '--patterns', type=str,
                       help='JSON file containing custom patterns to search for')
    parser.add_argument('-f', '--focus', type=str,
                       help='Focus on specific information: ip, brute_force, username, compromised, email, url')
    parser.add_argument('-q', '--query', type=str,
                       help='Ask a specific question (e.g., "What is the username of the compromised account?")')
    
    args = parser.parse_args()
    
    if not Path(args.log_file).exists():
        print(f"Error: Log file '{args.log_file}' does not exist.")
        sys.exit(1)
    
    # Load custom patterns if provided
    custom_patterns = None
    if args.patterns:
        if not Path(args.patterns).exists():
            print(f"Error: Pattern file '{args.patterns}' does not exist.")
            sys.exit(1)
        
        try:
            with open(args.patterns, 'r') as f:
                custom_patterns = json.load(f)
            if args.verbose:
                print(f"Loaded {len(custom_patterns)} custom patterns from {args.patterns}")
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in pattern file: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading pattern file: {e}")
            sys.exit(1)
    
    analyzer = LogPatternAnalyzer(custom_patterns)
    
    if args.verbose:
        print(f"Analyzing log file: {args.log_file}")
        if custom_patterns:
            print(f"Custom patterns loaded: {list(custom_patterns.keys())}")
    
    if analyzer.analyze_file(args.log_file):
        analyzer.analyze_attack_scenarios()  # Analyze attack scenarios
        analyzer.detect_suspicious_logins()   # Detect suspicious logins
        analyzer.generate_statistics()
        analyzer.print_results(args.output, focus=args.focus, query=args.query)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()

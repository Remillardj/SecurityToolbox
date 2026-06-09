"""
Report Generator Module
Generates comprehensive phishing analysis reports.
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class PhishingVerdict:
    """Final verdict for phishing analysis."""
    is_phishing: bool
    confidence: float  # 0.0 to 1.0
    verdict: str  # "phishing", "suspicious", "legitimate", "inconclusive"
    risk_level: str  # "critical", "high", "medium", "low", "none"
    
    summary: str = ""
    key_findings: List[str] = None
    recommendations: List[str] = None
    
    def __post_init__(self):
        if self.key_findings is None:
            self.key_findings = []
        if self.recommendations is None:
            self.recommendations = []


class ReportGenerator:
    """
    Generates comprehensive phishing analysis reports.
    """
    
    def __init__(self):
        self.analysis_timestamp = datetime.utcnow()
    
    def generate_verdict(
        self,
        header_result,
        iocs,
        reputation_results: Dict = None,
        llm_result = None
    ) -> PhishingVerdict:
        """
        Generate final verdict based on all analysis components.
        
        Args:
            header_result: HeaderAnalysisResult object
            iocs: ExtractedIOCs object
            reputation_results: Results from reputation checker
            llm_result: LLMAnalysisResult object (optional)
            
        Returns:
            PhishingVerdict with final determination
        """
        findings = []
        score = 0.0
        max_score = 0.0
        
        # Score authentication results
        max_score += 30
        if header_result:
            if header_result.spf_result:
                if header_result.spf_result.result == 'fail':
                    score += 15
                    findings.append("SPF authentication failed")
                elif header_result.spf_result.result == 'pass':
                    score -= 5
            
            if header_result.dkim_result:
                if header_result.dkim_result.result == 'fail':
                    score += 10
                    findings.append("DKIM signature verification failed")
                elif header_result.dkim_result.result == 'pass':
                    score -= 5
            
            if header_result.dmarc_result:
                if header_result.dmarc_result.result == 'fail':
                    score += 15
                    findings.append("DMARC check failed")
                elif header_result.dmarc_result.result == 'pass':
                    score -= 10
            
            # From domain mismatch
            if header_result.from_domain_mismatch:
                score += 20
                findings.append("Sender envelope and header domains do not match")
            
            # Suspicious indicators from headers
            for indicator in header_result.suspicious_indicators:
                score += 10
                findings.append(indicator)
        
        # Score IOC findings
        max_score += 20
        if iocs and iocs.total_count > 0:
            # Suspicious number of URLs
            if len(iocs.urls) > 5:
                score += 5
                findings.append(f"Email contains {len(iocs.urls)} URLs")
            
            # Direct IP links (common in phishing)
            for url in iocs.urls:
                if any(c.isdigit() for c in url.split('/')[2]) and '.' in url.split('/')[2]:
                    score += 10
                    findings.append(f"URL uses IP address instead of domain: {url[:50]}...")
                    break
        
        # Score reputation results
        max_score += 30
        if reputation_results:
            summary = reputation_results if isinstance(reputation_results, dict) else {}
            
            malicious_count = summary.get('malicious_count', 0)
            suspicious_count = summary.get('suspicious_count', 0)
            
            if malicious_count > 0:
                score += 25
                findings.append(f"{malicious_count} IOCs flagged as malicious by reputation services")
            
            if suspicious_count > 0:
                score += 10
                findings.append(f"{suspicious_count} IOCs flagged as suspicious")
        
        # Score LLM analysis
        max_score += 20
        if llm_result:
            if llm_result.is_phishing:
                score += 15
                if llm_result.summary:
                    findings.append(f"AI Analysis: {llm_result.summary}")
            
            # Add LLM-identified tactics
            for tactic in llm_result.social_engineering_tactics[:3]:
                findings.append(f"Social engineering: {tactic}")
            
            for indicator in llm_result.impersonation_indicators[:2]:
                findings.append(f"Impersonation: {indicator}")
            
            for urgency in llm_result.urgency_pressure_tactics[:2]:
                findings.append(f"Pressure tactic: {urgency}")
        
        # Normalize score to 0-1 range
        normalized_score = max(0, min(score / max(max_score, 1), 1.0))
        
        # Determine verdict
        if normalized_score >= 0.7:
            verdict_str = "phishing"
            risk_level = "critical" if normalized_score >= 0.85 else "high"
            is_phishing = True
        elif normalized_score >= 0.4:
            verdict_str = "suspicious"
            risk_level = "high" if normalized_score >= 0.55 else "medium"
            is_phishing = True
        elif normalized_score >= 0.2:
            verdict_str = "inconclusive"
            risk_level = "low"
            is_phishing = False
        else:
            verdict_str = "legitimate"
            risk_level = "none"
            is_phishing = False
        
        # Generate recommendations
        recommendations = self._generate_recommendations(verdict_str, findings)
        
        # Generate summary
        summary = self._generate_summary(verdict_str, normalized_score, findings)
        
        return PhishingVerdict(
            is_phishing=is_phishing,
            confidence=normalized_score,
            verdict=verdict_str,
            risk_level=risk_level,
            summary=summary,
            key_findings=findings[:10],  # Top 10 findings
            recommendations=recommendations
        )
    
    def _generate_recommendations(self, verdict: str, findings: List[str]) -> List[str]:
        """Generate actionable recommendations based on verdict."""
        recommendations = []
        
        if verdict == "phishing":
            recommendations = [
                "Do NOT click any links or download attachments from this email",
                "Do NOT reply to this email or provide any personal information",
                "Report this email to your IT security team immediately",
                "Mark as spam/phishing in your email client",
                "If you clicked any links, change passwords for affected accounts",
                "Consider enabling additional security measures like MFA",
            ]
        elif verdict == "suspicious":
            recommendations = [
                "Exercise extreme caution with this email",
                "Verify the sender through an alternative communication channel",
                "Do not click links - hover to verify URLs before clicking",
                "Report to IT security for further investigation",
                "Do not provide any sensitive information",
            ]
        elif verdict == "inconclusive":
            recommendations = [
                "Treat with caution - verify sender independently",
                "Check if you were expecting this email",
                "Verify any links by hovering before clicking",
                "When in doubt, contact IT security",
            ]
        else:
            recommendations = [
                "Email appears legitimate, but always exercise caution",
                "Verify unexpected requests through official channels",
            ]
        
        return recommendations
    
    def _generate_summary(self, verdict: str, score: float, findings: List[str]) -> str:
        """Generate human-readable summary."""
        pct = int(score * 100)
        
        if verdict == "phishing":
            return (
                f"This email is highly likely to be a phishing attempt "
                f"(confidence: {pct}%). {len(findings)} suspicious indicators were identified."
            )
        elif verdict == "suspicious":
            return (
                f"This email shows multiple suspicious characteristics "
                f"(risk score: {pct}%). Further investigation recommended."
            )
        elif verdict == "inconclusive":
            return (
                f"Analysis is inconclusive (score: {pct}%). "
                f"The email has some suspicious elements but lacks definitive indicators."
            )
        else:
            return (
                f"This email appears to be legitimate (score: {pct}%). "
                f"No significant phishing indicators detected."
            )
    
    def generate_report(
        self,
        parsed_email,
        header_result,
        iocs,
        reputation_results: Dict = None,
        llm_result = None,
        verdict: PhishingVerdict = None
    ) -> Dict[str, Any]:
        """
        Generate comprehensive analysis report.
        
        Args:
            parsed_email: ParsedEmail object
            header_result: HeaderAnalysisResult object
            iocs: ExtractedIOCs object
            reputation_results: Reputation check results
            llm_result: LLM analysis result
            verdict: Final verdict (generates if not provided)
            
        Returns:
            Complete report as dictionary
        """
        if verdict is None:
            verdict = self.generate_verdict(
                header_result, iocs, reputation_results, llm_result
            )
        
        report = {
            'metadata': {
                'analysis_timestamp': self.analysis_timestamp.isoformat(),
                'analyzer_version': '1.0.0',
                'file_analyzed': parsed_email.file_path if parsed_email else '',
            },
            'verdict': {
                'is_phishing': verdict.is_phishing,
                'verdict': verdict.verdict,
                'confidence': verdict.confidence,
                'risk_level': verdict.risk_level,
                'summary': verdict.summary,
            },
            'key_findings': verdict.key_findings,
            'recommendations': verdict.recommendations,
            'email_details': {},
            'authentication': {},
            'iocs': {},
            'reputation': {},
            'ai_analysis': {},
        }
        
        # Email details
        if parsed_email:
            report['email_details'] = {
                'subject': parsed_email.subject,
                'from_address': parsed_email.from_address,
                'from_name': parsed_email.from_name,
                'to_addresses': parsed_email.to_addresses,
                'reply_to': parsed_email.reply_to,
                'date': str(parsed_email.date) if parsed_email.date else '',
                'message_id': parsed_email.message_id,
                'attachment_count': len(parsed_email.attachments),
                'attachments': [
                    {
                        'filename': att.filename,
                        'content_type': att.content_type,
                        'size': att.size,
                        'sha256': att.sha256,
                    }
                    for att in parsed_email.attachments
                ]
            }
        
        # Authentication results
        if header_result:
            report['authentication'] = {
                'score': header_result.auth_score,
                'is_authenticated': header_result.is_authenticated,
                'spf': {
                    'result': header_result.spf_result.result if header_result.spf_result else 'none',
                    'details': header_result.spf_result.details if header_result.spf_result else '',
                } if header_result.spf_result else None,
                'dkim': {
                    'result': header_result.dkim_result.result if header_result.dkim_result else 'none',
                    'domain': header_result.dkim_result.domain if header_result.dkim_result else '',
                } if header_result.dkim_result else None,
                'dmarc': {
                    'result': header_result.dmarc_result.result if header_result.dmarc_result else 'none',
                } if header_result.dmarc_result else None,
                'from_domain_mismatch': header_result.from_domain_mismatch,
                'warnings': header_result.warnings,
                'suspicious_indicators': header_result.suspicious_indicators,
            }
        
        # IOCs
        if iocs:
            report['iocs'] = iocs.to_dict()
            report['iocs']['total_count'] = iocs.total_count
        
        # Reputation results
        if reputation_results:
            if isinstance(reputation_results, dict):
                report['reputation'] = reputation_results
        
        # LLM analysis
        if llm_result:
            report['ai_analysis'] = llm_result.to_dict()
        
        return report
    
    def print_console_report(
        self,
        report: Dict[str, Any],
        verbose: bool = False
    ):
        """
        Print formatted report to console.
        
        Args:
            report: Report dictionary from generate_report()
            verbose: Include all details
        """
        from ..utils import (
            Colors, print_header, print_subheader, 
            print_finding, print_kv, defang_url
        )
        
        verdict_data = report.get('verdict', {})
        
        # Header with verdict
        print_header("PHISHING ANALYSIS REPORT")
        
        # Verdict box
        verdict = verdict_data.get('verdict', 'unknown')
        confidence = verdict_data.get('confidence', 0)
        risk = verdict_data.get('risk_level', 'unknown')
        
        verdict_colors = {
            'phishing': Colors.RED + Colors.BOLD,
            'suspicious': Colors.YELLOW + Colors.BOLD,
            'legitimate': Colors.GREEN + Colors.BOLD,
            'inconclusive': Colors.BLUE,
        }
        color = verdict_colors.get(verdict, Colors.WHITE)
        
        print(f"  {color}▌ VERDICT: {verdict.upper()}{Colors.RESET}")
        print(f"  {color}▌ CONFIDENCE: {int(confidence * 100)}%{Colors.RESET}")
        print(f"  {color}▌ RISK LEVEL: {risk.upper()}{Colors.RESET}")
        print()
        
        # Summary
        summary = verdict_data.get('summary', '')
        if summary:
            print(f"  {summary}")
            print()
        
        # Email details
        print_subheader("Email Details")
        email = report.get('email_details', {})
        print_kv("Subject", email.get('subject', 'N/A'))
        print_kv("From", f"{email.get('from_address', 'N/A')} ({email.get('from_name', '')})")
        print_kv("To", ', '.join(email.get('to_addresses', [])) or 'N/A')
        if email.get('reply_to'):
            print_kv("Reply-To", email.get('reply_to'))
        print_kv("Date", email.get('date', 'N/A'))
        print_kv("Attachments", email.get('attachment_count', 0))
        
        # Authentication
        print_subheader("Email Authentication")
        auth = report.get('authentication', {})
        if auth:
            spf = auth.get('spf', {})
            dkim = auth.get('dkim', {})
            dmarc = auth.get('dmarc', {})
            
            spf_result = spf.get('result', 'none') if spf else 'none'
            dkim_result = dkim.get('result', 'none') if dkim else 'none'
            dmarc_result = dmarc.get('result', 'none') if dmarc else 'none'
            
            def auth_color(result):
                if result == 'pass':
                    return Colors.GREEN
                elif result in ('fail', 'softfail'):
                    return Colors.RED
                return Colors.YELLOW
            
            print(f"  SPF:   {auth_color(spf_result)}{spf_result.upper()}{Colors.RESET}")
            print(f"  DKIM:  {auth_color(dkim_result)}{dkim_result.upper()}{Colors.RESET}")
            print(f"  DMARC: {auth_color(dmarc_result)}{dmarc_result.upper()}{Colors.RESET}")
            print(f"  Score: {auth.get('score', 0)}/100")
            
            if auth.get('from_domain_mismatch'):
                print_finding('high', 'From domain mismatch detected')
        
        # Key Findings
        findings = report.get('key_findings', [])
        if findings:
            print_subheader("Key Findings")
            for finding in findings:
                severity = 'high' if any(w in finding.lower() for w in ['fail', 'malicious', 'phishing']) else 'medium'
                print_finding(severity, finding)
        
        # IOCs
        iocs = report.get('iocs', {})
        if iocs.get('total_count', 0) > 0:
            print_subheader("Indicators of Compromise (IOCs)")
            
            if iocs.get('urls'):
                print(f"\n  {Colors.CYAN}URLs ({len(iocs['urls'])}){Colors.RESET}")
                for url in iocs['urls'][:5]:
                    print(f"    • {defang_url(url)}")
                if len(iocs['urls']) > 5:
                    print(f"    ... and {len(iocs['urls']) - 5} more")
            
            if iocs.get('ip_addresses'):
                print(f"\n  {Colors.CYAN}IP Addresses ({len(iocs['ip_addresses'])}){Colors.RESET}")
                for ip in iocs['ip_addresses'][:5]:
                    print(f"    • {ip}")
            
            if iocs.get('domains'):
                print(f"\n  {Colors.CYAN}Domains ({len(iocs['domains'])}){Colors.RESET}")
                for domain in iocs['domains'][:5]:
                    print(f"    • {domain}")
        
        # Reputation results
        rep = report.get('reputation', {})
        if rep:
            print_subheader("Reputation Analysis")
            mal_count = rep.get('malicious_count', 0)
            sus_count = rep.get('suspicious_count', 0)
            clean_count = rep.get('clean_count', 0)
            
            if mal_count > 0:
                print_finding('critical', f'{mal_count} IOCs flagged as MALICIOUS')
            if sus_count > 0:
                print_finding('medium', f'{sus_count} IOCs flagged as suspicious')
            if clean_count > 0:
                print_finding('safe', f'{clean_count} IOCs are clean')
        
        # AI Analysis
        ai = report.get('ai_analysis', {})
        if ai and ai.get('summary'):
            print_subheader("AI Analysis")
            print(f"  {ai.get('summary', '')}")
            
            if ai.get('social_engineering_tactics'):
                print(f"\n  {Colors.YELLOW}Social Engineering:{Colors.RESET}")
                for tactic in ai['social_engineering_tactics'][:3]:
                    print(f"    • {tactic}")
        
        # Recommendations
        recs = report.get('recommendations', [])
        if recs:
            print_subheader("Recommendations")
            for i, rec in enumerate(recs, 1):
                print(f"  {i}. {rec}")
        
        print()
    
    def export_json(self, report: Dict[str, Any], output_path: str):
        """Export report to JSON file."""
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
    
    def export_html(self, report: Dict[str, Any], output_path: str):
        """Export report to HTML file."""
        html = self._generate_html(report)
        with open(output_path, 'w') as f:
            f.write(html)
    
    def _generate_html(self, report: Dict[str, Any]) -> str:
        """Generate HTML report."""
        verdict = report.get('verdict', {})
        verdict_str = verdict.get('verdict', 'unknown')
        
        verdict_colors = {
            'phishing': '#dc3545',
            'suspicious': '#ffc107',
            'legitimate': '#28a745',
            'inconclusive': '#6c757d',
        }
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Phishing Analysis Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .verdict-box {{ background: {verdict_colors.get(verdict_str, '#6c757d')}; color: white; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .verdict-box h2 {{ color: white; margin: 0; }}
        .findings {{ background: #fff3cd; padding: 15px; border-radius: 4px; margin: 10px 0; }}
        .finding {{ margin: 5px 0; padding: 5px 10px; background: #ffeeba; border-radius: 4px; }}
        .ioc {{ font-family: monospace; background: #e9ecef; padding: 2px 6px; border-radius: 3px; }}
        .recommendation {{ margin: 10px 0; padding: 10px; background: #d4edda; border-radius: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; }}
        .auth-pass {{ color: #28a745; font-weight: bold; }}
        .auth-fail {{ color: #dc3545; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Phishing Analysis Report</h1>
        <p>Generated: {report.get('metadata', {}).get('analysis_timestamp', '')}</p>
        
        <div class="verdict-box">
            <h2>VERDICT: {verdict_str.upper()}</h2>
            <p>Confidence: {int(verdict.get('confidence', 0) * 100)}% | Risk Level: {verdict.get('risk_level', 'unknown').upper()}</p>
            <p>{verdict.get('summary', '')}</p>
        </div>
        
        <h2>📧 Email Details</h2>
        <table>
            <tr><th>Subject</th><td>{report.get('email_details', {}).get('subject', 'N/A')}</td></tr>
            <tr><th>From</th><td>{report.get('email_details', {}).get('from_address', 'N/A')}</td></tr>
            <tr><th>To</th><td>{', '.join(report.get('email_details', {}).get('to_addresses', []))}</td></tr>
            <tr><th>Date</th><td>{report.get('email_details', {}).get('date', 'N/A')}</td></tr>
        </table>
        
        <h2>🔐 Authentication</h2>
        <table>
            <tr><th>SPF</th><td class="auth-{'pass' if report.get('authentication', {}).get('spf', {}).get('result') == 'pass' else 'fail'}">{report.get('authentication', {}).get('spf', {}).get('result', 'N/A').upper() if report.get('authentication', {}).get('spf') else 'N/A'}</td></tr>
            <tr><th>DKIM</th><td class="auth-{'pass' if report.get('authentication', {}).get('dkim', {}).get('result') == 'pass' else 'fail'}">{report.get('authentication', {}).get('dkim', {}).get('result', 'N/A').upper() if report.get('authentication', {}).get('dkim') else 'N/A'}</td></tr>
            <tr><th>DMARC</th><td class="auth-{'pass' if report.get('authentication', {}).get('dmarc', {}).get('result') == 'pass' else 'fail'}">{report.get('authentication', {}).get('dmarc', {}).get('result', 'N/A').upper() if report.get('authentication', {}).get('dmarc') else 'N/A'}</td></tr>
        </table>
        
        <h2>⚠️ Key Findings</h2>
        <div class="findings">
            {''.join(f'<div class="finding">{f}</div>' for f in report.get('key_findings', []))}
        </div>
        
        <h2>✅ Recommendations</h2>
        {''.join(f'<div class="recommendation">{r}</div>' for r in report.get('recommendations', []))}
    </div>
</body>
</html>'''
        
        return html


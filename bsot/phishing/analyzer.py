"""
Main Phishing Analyzer Module
Orchestrates all analysis components for comprehensive phishing detection.
"""

from typing import Dict, Any
from dataclasses import dataclass, field

from .email_parser import EmailParser, ParsedEmail
from .ioc_extractor import IOCExtractor, ExtractedIOCs, extract_iocs_from_email
from .header_analyzer import HeaderAnalyzer, HeaderAnalysisResult, analyze_email_headers
from .llm_analyzer import LLMAnalyzer, LLMAnalysisResult, analyze_email_with_llm
from .reputation import ReputationChecker
from .report import ReportGenerator, PhishingVerdict


@dataclass
class PhishingAnalysisResult:
    """Complete phishing analysis result."""
    # Source
    file_path: str = ""
    
    # Parsed email
    email: ParsedEmail = None
    
    # Analysis components
    iocs: ExtractedIOCs = None
    header_analysis: HeaderAnalysisResult = None
    reputation_results: Dict = None
    llm_analysis: LLMAnalysisResult = None
    
    # Final verdict
    verdict: PhishingVerdict = None
    
    # Full report
    report: Dict[str, Any] = field(default_factory=dict)


class PhishingAnalyzer:
    """
    Comprehensive phishing email analyzer.
    
    Orchestrates:
    - Email parsing (.eml/.msg)
    - IOC extraction (URLs, IPs, domains, hashes)
    - Header analysis (SPF/DKIM/DMARC)
    - Reputation checks (VirusTotal, AbuseIPDB)
    - LLM-powered analysis (OpenAI/Anthropic)
    - Verdict generation and reporting
    """
    
    def __init__(
        self,
        openai_api_key: str = None,
        anthropic_api_key: str = None,
        virustotal_api_key: str = None,
        abuseipdb_api_key: str = None,
        urlscan_api_key: str = None,
        llm_provider: str = "openai"
    ):
        """
        Initialize the phishing analyzer with API keys.
        
        Args:
            openai_api_key: OpenAI API key for LLM analysis
            anthropic_api_key: Anthropic API key for LLM analysis
            virustotal_api_key: VirusTotal API key
            abuseipdb_api_key: AbuseIPDB API key
            urlscan_api_key: URLScan.io API key
            llm_provider: LLM provider to use ("openai" or "anthropic")
        """
        self.email_parser = EmailParser()
        self.ioc_extractor = IOCExtractor()
        self.header_analyzer = HeaderAnalyzer()
        self.report_generator = ReportGenerator()
        
        # Set up LLM analyzer
        self.llm_provider = llm_provider
        if llm_provider == "anthropic" and anthropic_api_key:
            self.llm_analyzer = LLMAnalyzer(
                api_key=anthropic_api_key,
                provider="anthropic"
            )
        elif openai_api_key:
            self.llm_analyzer = LLMAnalyzer(
                api_key=openai_api_key,
                provider="openai"
            )
        else:
            self.llm_analyzer = None
        
        # Set up reputation checker
        if virustotal_api_key or abuseipdb_api_key or urlscan_api_key:
            self.reputation_checker = ReputationChecker(
                virustotal_key=virustotal_api_key,
                abuseipdb_key=abuseipdb_api_key,
                urlscan_key=urlscan_api_key
            )
        else:
            self.reputation_checker = None
    
    def analyze(
        self,
        email_path: str,
        skip_reputation: bool = False,
        skip_llm: bool = False,
        max_iocs_per_type: int = 10,
        verbose: bool = False
    ) -> PhishingAnalysisResult:
        """
        Perform comprehensive phishing analysis on an email file.
        
        Args:
            email_path: Path to the email file (.eml or .msg)
            skip_reputation: Skip reputation checks (faster, no API calls)
            skip_llm: Skip LLM analysis (faster, no API calls)
            max_iocs_per_type: Max IOCs to check against reputation services
            verbose: Print progress during analysis
            
        Returns:
            PhishingAnalysisResult with complete analysis
        """
        result = PhishingAnalysisResult(file_path=email_path)
        
        # Step 1: Parse email
        if verbose:
            print("📧 Parsing email...")
        result.email = self.email_parser.parse(email_path)
        
        if result.email.parse_errors:
            for error in result.email.parse_errors:
                if verbose:
                    print(f"  ⚠️  Parse warning: {error}")
        
        # Step 2: Extract IOCs
        if verbose:
            print("🔍 Extracting IOCs...")
        result.iocs = extract_iocs_from_email(result.email)
        
        if verbose:
            print(f"  Found {result.iocs.total_count} IOCs: "
                  f"{len(result.iocs.urls)} URLs, "
                  f"{len(result.iocs.domains)} domains, "
                  f"{len(result.iocs.ip_addresses)} IPs")
        
        # Step 3: Analyze headers
        if verbose:
            print("🔐 Analyzing email headers...")
        result.header_analysis = analyze_email_headers(result.email)
        
        if verbose:
            spf = result.header_analysis.spf_result
            dkim = result.header_analysis.dkim_result
            dmarc = result.header_analysis.dmarc_result
            print(f"  SPF: {spf.result if spf else 'none'}, "
                  f"DKIM: {dkim.result if dkim else 'none'}, "
                  f"DMARC: {dmarc.result if dmarc else 'none'}")
        
        # Step 4: Reputation checks
        if not skip_reputation and self.reputation_checker:
            if verbose:
                print("🌐 Checking IOC reputation...")
            
            rep_results = self.reputation_checker.check_all_iocs(
                result.iocs,
                max_per_type=max_iocs_per_type
            )
            result.reputation_results = self.reputation_checker.get_summary(rep_results)
            
            if verbose:
                mal = result.reputation_results.get('malicious_count', 0)
                sus = result.reputation_results.get('suspicious_count', 0)
                print(f"  {mal} malicious, {sus} suspicious IOCs detected")
        elif verbose:
            print("⏭️  Skipping reputation checks")
        
        # Step 5: LLM analysis
        if not skip_llm and self.llm_analyzer:
            if verbose:
                print("🤖 Running AI analysis...")
            
            result.llm_analysis = analyze_email_with_llm(
                result.email,
                result.iocs,
                api_key=self.llm_analyzer.api_key,
                provider=self.llm_provider
            )
            
            if verbose and result.llm_analysis.summary:
                print(f"  AI verdict: {result.llm_analysis.verdict}")
        elif verbose:
            print("⏭️  Skipping AI analysis")
        
        # Step 6: Generate verdict
        if verbose:
            print("📊 Generating verdict...")
        
        result.verdict = self.report_generator.generate_verdict(
            result.header_analysis,
            result.iocs,
            result.reputation_results,
            result.llm_analysis
        )
        
        # Step 7: Generate full report
        result.report = self.report_generator.generate_report(
            result.email,
            result.header_analysis,
            result.iocs,
            result.reputation_results,
            result.llm_analysis,
            result.verdict
        )
        
        return result
    
    def analyze_quick(self, email_path: str) -> PhishingAnalysisResult:
        """
        Quick analysis without API calls (reputation/LLM).
        Useful for offline analysis or rate limit concerns.
        
        Args:
            email_path: Path to the email file
            
        Returns:
            PhishingAnalysisResult
        """
        return self.analyze(
            email_path,
            skip_reputation=True,
            skip_llm=True,
            verbose=False
        )
    
    def print_report(self, result: PhishingAnalysisResult, verbose: bool = False):
        """
        Print analysis report to console.
        
        Args:
            result: PhishingAnalysisResult from analyze()
            verbose: Include all details
        """
        self.report_generator.print_console_report(result.report, verbose)
    
    def export_report(
        self,
        result: PhishingAnalysisResult,
        output_path: str,
        format: str = "json"
    ):
        """
        Export analysis report to file.
        
        Args:
            result: PhishingAnalysisResult from analyze()
            output_path: Output file path
            format: "json" or "html"
        """
        if format == "html":
            self.report_generator.export_html(result.report, output_path)
        else:
            self.report_generator.export_json(result.report, output_path)


def analyze_email(
    email_path: str,
    openai_key: str = None,
    virustotal_key: str = None,
    quick: bool = False,
    verbose: bool = True
) -> PhishingAnalysisResult:
    """
    Convenience function for quick phishing analysis.
    
    Args:
        email_path: Path to email file
        openai_key: OpenAI API key (optional)
        virustotal_key: VirusTotal API key (optional)
        quick: Skip API calls for faster analysis
        verbose: Print progress
        
    Returns:
        PhishingAnalysisResult
    
    Example:
        >>> result = analyze_email("suspicious_email.eml", verbose=True)
        >>> print(result.verdict.verdict)
        'phishing'
    """
    analyzer = PhishingAnalyzer(
        openai_api_key=openai_key,
        virustotal_api_key=virustotal_key
    )
    
    if quick:
        return analyzer.analyze_quick(email_path)
    
    return analyzer.analyze(
        email_path,
        skip_reputation=not virustotal_key,
        skip_llm=not openai_key,
        verbose=verbose
    )


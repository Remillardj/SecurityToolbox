"""
LLM-Powered Phishing Analyzer Module
Uses OpenAI or Anthropic APIs for intelligent phishing detection.
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
import re


@dataclass
class LLMAnalysisResult:
    """Results from LLM phishing analysis."""
    is_phishing: bool = False
    confidence: float = 0.0  # 0.0 to 1.0
    verdict: str = "unknown"  # phishing, suspicious, legitimate, unknown
    
    # Detailed findings
    social_engineering_tactics: List[str] = field(default_factory=list)
    impersonation_indicators: List[str] = field(default_factory=list)
    urgency_pressure_tactics: List[str] = field(default_factory=list)
    suspicious_requests: List[str] = field(default_factory=list)
    language_anomalies: List[str] = field(default_factory=list)
    
    # Summary
    summary: str = ""
    risk_factors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Raw response
    raw_response: str = ""
    model_used: str = ""
    tokens_used: int = 0
    
    def to_dict(self) -> dict:
        return {
            'is_phishing': self.is_phishing,
            'confidence': self.confidence,
            'verdict': self.verdict,
            'social_engineering_tactics': self.social_engineering_tactics,
            'impersonation_indicators': self.impersonation_indicators,
            'urgency_pressure_tactics': self.urgency_pressure_tactics,
            'suspicious_requests': self.suspicious_requests,
            'language_anomalies': self.language_anomalies,
            'summary': self.summary,
            'risk_factors': self.risk_factors,
            'recommendations': self.recommendations,
            'model_used': self.model_used,
        }


class LLMAnalyzer:
    """
    Uses LLM APIs to perform intelligent phishing analysis.
    Supports OpenAI and Anthropic Claude.
    """
    
    ANALYSIS_PROMPT = '''You are a cybersecurity expert specialized in phishing detection and email security analysis.

Analyze the following email for phishing indicators and social engineering tactics.

EMAIL DETAILS:
Subject: {subject}
From: {from_address} ({from_name})
To: {to_addresses}
Reply-To: {reply_to}
Date: {date}

EMAIL BODY:
{body}

URLS FOUND IN EMAIL:
{urls}

ATTACHMENTS:
{attachments}

Perform a comprehensive phishing analysis and respond in the following JSON format:
{{
    "verdict": "phishing" | "suspicious" | "legitimate",
    "confidence": 0.0-1.0,
    "is_phishing": true | false,
    "summary": "Brief summary of findings",
    "social_engineering_tactics": ["list of social engineering tactics used"],
    "impersonation_indicators": ["any brand/person impersonation attempts"],
    "urgency_pressure_tactics": ["urgency or pressure tactics identified"],
    "suspicious_requests": ["suspicious requests like credentials, payments, personal info"],
    "language_anomalies": ["grammar issues, unusual phrasing, etc."],
    "risk_factors": ["key risk factors identified"],
    "recommendations": ["recommended actions for the recipient"]
}}

Be thorough but avoid false positives. Consider context carefully.
'''

    def __init__(self, api_key: str = None, provider: str = "openai", model: str = None):
        """
        Initialize the LLM analyzer.
        
        Args:
            api_key: API key for the LLM provider
            provider: "openai" or "anthropic"
            model: Model name to use (defaults to gpt-4o or claude-3-5-sonnet)
        """
        self.api_key = api_key
        self.provider = provider.lower()
        
        # Set default models
        if model:
            self.model = model
        elif self.provider == "anthropic":
            self.model = "claude-sonnet-4-20250514"
        else:
            self.model = "gpt-4o"
    
    def analyze(
        self,
        subject: str,
        from_address: str,
        from_name: str,
        to_addresses: List[str],
        reply_to: str,
        date: str,
        body: str,
        urls: List[str] = None,
        attachments: List[str] = None
    ) -> LLMAnalysisResult:
        """
        Analyze email content using LLM for phishing detection.
        
        Args:
            subject: Email subject
            from_address: Sender email address
            from_name: Sender display name
            to_addresses: List of recipient addresses
            reply_to: Reply-to address
            date: Email date
            body: Email body (plain text preferred)
            urls: List of URLs found in email
            attachments: List of attachment filenames
            
        Returns:
            LLMAnalysisResult with detailed findings
        """
        result = LLMAnalysisResult()
        
        if not self.api_key:
            result.summary = "No API key configured - LLM analysis skipped"
            result.verdict = "unknown"
            return result
        
        # Prepare the prompt
        prompt = self.ANALYSIS_PROMPT.format(
            subject=subject or "(No subject)",
            from_address=from_address or "(Unknown)",
            from_name=from_name or "(No name)",
            to_addresses=", ".join(to_addresses) if to_addresses else "(Unknown)",
            reply_to=reply_to or "(Same as From)",
            date=date or "(Unknown)",
            body=self._truncate_body(body),
            urls="\n".join(urls) if urls else "(None found)",
            attachments=", ".join(attachments) if attachments else "(None)"
        )
        
        try:
            if self.provider == "anthropic":
                response = self._call_anthropic(prompt)
            else:
                response = self._call_openai(prompt)
            
            result = self._parse_response(response)
            result.model_used = self.model
            
        except Exception as e:
            result.summary = f"LLM analysis failed: {str(e)}"
            result.verdict = "unknown"
        
        return result
    
    def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API."""
        import requests
        
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert. Always respond with valid JSON."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": 0.1,
                "max_tokens": 2000
            },
            timeout=60
        )
        
        response.raise_for_status()
        data = response.json()
        
        return data['choices'][0]['message']['content']
    
    def _call_anthropic(self, prompt: str) -> str:
        """Call Anthropic Claude API."""
        import requests
        
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            },
            json={
                "model": self.model,
                "max_tokens": 2000,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            },
            timeout=60
        )
        
        response.raise_for_status()
        data = response.json()
        
        return data['content'][0]['text']
    
    def _parse_response(self, response: str) -> LLMAnalysisResult:
        """Parse LLM response into structured result."""
        result = LLMAnalysisResult()
        result.raw_response = response
        
        # Try to extract JSON from response
        try:
            # Handle markdown code blocks
            json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', response)
            if json_match:
                json_str = json_match.group(1)
            else:
                # Try to find JSON object directly
                json_match = re.search(r'\{[\s\S]*\}', response)
                if json_match:
                    json_str = json_match.group(0)
                else:
                    json_str = response
            
            data = json.loads(json_str)
            
            result.verdict = data.get('verdict', 'unknown')
            result.confidence = float(data.get('confidence', 0.5))
            result.is_phishing = data.get('is_phishing', result.verdict == 'phishing')
            result.summary = data.get('summary', '')
            
            result.social_engineering_tactics = data.get('social_engineering_tactics', [])
            result.impersonation_indicators = data.get('impersonation_indicators', [])
            result.urgency_pressure_tactics = data.get('urgency_pressure_tactics', [])
            result.suspicious_requests = data.get('suspicious_requests', [])
            result.language_anomalies = data.get('language_anomalies', [])
            
            result.risk_factors = data.get('risk_factors', [])
            result.recommendations = data.get('recommendations', [])
            
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            # If JSON parsing fails, extract what we can
            result.summary = f"Failed to parse LLM response: {str(e)}"
            result.raw_response = response
            
            # Try to determine verdict from text
            response_lower = response.lower()
            if 'phishing' in response_lower and 'not phishing' not in response_lower:
                result.verdict = 'suspicious'
                result.is_phishing = True
                result.confidence = 0.6
            elif 'legitimate' in response_lower or 'safe' in response_lower:
                result.verdict = 'legitimate'
                result.is_phishing = False
                result.confidence = 0.6
        
        return result
    
    def _truncate_body(self, body: str, max_length: int = 4000) -> str:
        """Truncate body to fit within token limits."""
        if not body:
            return "(Empty body)"
        
        if len(body) <= max_length:
            return body
        
        return body[:max_length] + "\n\n[... TRUNCATED ...]"


def analyze_email_with_llm(
    parsed_email,
    extracted_iocs,
    api_key: str = None,
    provider: str = "openai"
) -> LLMAnalysisResult:
    """
    Convenience function to analyze a parsed email with LLM.
    
    Args:
        parsed_email: ParsedEmail object
        extracted_iocs: ExtractedIOCs object
        api_key: LLM API key
        provider: "openai" or "anthropic"
        
    Returns:
        LLMAnalysisResult
    """
    analyzer = LLMAnalyzer(api_key=api_key, provider=provider)
    
    return analyzer.analyze(
        subject=parsed_email.subject,
        from_address=parsed_email.from_address,
        from_name=parsed_email.from_name,
        to_addresses=parsed_email.to_addresses,
        reply_to=parsed_email.reply_to,
        date=str(parsed_email.date) if parsed_email.date else "",
        body=parsed_email.body_text or parsed_email.body_html,
        urls=extracted_iocs.urls,
        attachments=[att.filename for att in parsed_email.attachments]
    )


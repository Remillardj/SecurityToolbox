"""
Report Generator
AI-powered incident report generation from case data.
"""

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict
from dataclasses import dataclass

from .case_manager import Case
from .ioc_store import IOCStore
from .timeline import TimelineManager, NotesManager
from .llm_client import get_llm_client, LLMClient


# Report templates
TEMPLATES = {
    'executive': {
        'name': 'Executive Summary',
        'description': 'High-level summary for leadership',
        'audience': 'executives',
        'sections': ['executive_summary', 'incident_overview', 'impact', 'recommendations'],
        'detail_level': 'low',
    },
    'technical': {
        'name': 'Technical Report',
        'description': 'Detailed technical incident report',
        'audience': 'security team',
        'sections': ['executive_summary', 'incident_overview', 'timeline', 'technical_analysis', 
                    'iocs', 'impact', 'recommendations', 'appendix'],
        'detail_level': 'high',
    },
    'ioc': {
        'name': 'IOC Report',
        'description': 'Focused on indicators of compromise',
        'audience': 'security operations',
        'sections': ['summary', 'iocs', 'context', 'detection'],
        'detail_level': 'medium',
    },
    'timeline': {
        'name': 'Timeline Report',
        'description': 'Chronological incident analysis',
        'audience': 'investigators',
        'sections': ['summary', 'timeline', 'analysis', 'conclusions'],
        'detail_level': 'medium',
    },
}


@dataclass
class ReportResult:
    """Result of report generation."""
    content: str
    format: str  # markdown, html
    template: str
    file_path: Optional[str] = None
    llm_provider: str = ""
    llm_model: str = ""
    tokens_used: int = 0
    error: str = ""


class ReportGenerator:
    """
    Generates incident reports from case data using AI.
    """
    
    SYSTEM_PROMPT = """You are an expert cybersecurity incident report writer. 
Your task is to analyze investigation data and generate professional, 
well-structured incident reports.

Key guidelines:
- Be factual and precise
- Use clear, professional language
- Include specific technical details when available
- Organize information logically
- Highlight critical findings
- Provide actionable recommendations
- Format output in clean Markdown"""
    
    def __init__(self, case: Case, llm_client: LLMClient = None):
        """
        Initialize report generator.
        
        Args:
            case: Case to generate report for
            llm_client: LLM client to use (default: auto-configure)
        """
        self.case = case
        self.llm_client = llm_client
        
        # Load case data
        self.ioc_store = IOCStore(case.path / 'iocs.json')
        self.timeline = TimelineManager(case.path / 'timeline.json')
        self.notes = NotesManager(case.path / 'notes.md')
    
    def generate(
        self,
        template: str = 'technical',
        audience: str = None,
        detail_level: str = None,
        custom_instructions: str = None,
        output_format: str = 'markdown'
    ) -> ReportResult:
        """
        Generate an incident report.
        
        Args:
            template: Report template to use
            audience: Target audience (overrides template)
            detail_level: Detail level (overrides template)
            custom_instructions: Additional instructions for LLM
            output_format: Output format (markdown, html)
            
        Returns:
            ReportResult object
        """
        result = ReportResult(
            content="",
            format=output_format,
            template=template,
        )
        
        # Get template config
        template_config = TEMPLATES.get(template, TEMPLATES['technical'])
        
        if audience is None:
            audience = template_config['audience']
        if detail_level is None:
            detail_level = template_config['detail_level']
        
        # Get LLM client
        if self.llm_client is None:
            try:
                self.llm_client = get_llm_client()
            except Exception as e:
                result.error = f"Failed to initialize LLM client: {e}"
                return result
        
        result.llm_provider = self.llm_client.provider_name
        result.llm_model = self.llm_client.model_name
        
        # Build prompt
        prompt = self._build_prompt(template_config, audience, detail_level, custom_instructions)
        
        # Generate report
        response = self.llm_client.generate(
            prompt=prompt,
            system=self.SYSTEM_PROMPT,
            max_tokens=8192,
            temperature=0.3
        )
        
        if response.error:
            result.error = response.error
            return result
        
        result.content = response.content
        result.tokens_used = response.usage.get('output_tokens', 0)
        
        # Convert to HTML if requested
        if output_format == 'html':
            result.content = self._to_html(response.content)
        
        # Save report
        try:
            report_file = self._save_report(result.content, output_format)
            result.file_path = str(report_file)
        except Exception:
            pass  # Don't fail if save fails
        
        return result
    
    def _build_prompt(
        self,
        template_config: dict,
        audience: str,
        detail_level: str,
        custom_instructions: str = None
    ) -> str:
        """Build the LLM prompt from case data."""
        sections = []
        
        # Case information
        sections.append("## Case Information")
        sections.append(f"```json\n{json.dumps(self.case.to_dict(), indent=2)}\n```")
        
        # Timeline
        if self.timeline.count() > 0:
            sections.append("\n## Investigation Timeline")
            for event in self.timeline.get_all():
                sections.append(f"- **{event.timestamp}**: {event.event} (source: {event.source})")
        
        # Analyst notes
        notes_entries = self.notes.get_entries()
        if notes_entries:
            sections.append("\n## Analyst Notes")
            for entry in notes_entries:
                sections.append(f"### {entry['timestamp']}")
                sections.append(entry['text'])
        
        # IOCs
        iocs = self.ioc_store.get_all()
        if iocs:
            sections.append("\n## Indicators of Compromise")
            sections.append(f"Total IOCs: {len(iocs)}")
            
            # Group by type
            by_type = {}
            for ioc in iocs:
                if ioc.type not in by_type:
                    by_type[ioc.type] = []
                by_type[ioc.type].append(ioc)
            
            for ioc_type, type_iocs in by_type.items():
                sections.append(f"\n### {ioc_type.upper()} ({len(type_iocs)})")
                for ioc in type_iocs[:20]:  # Limit per type
                    sections.append(f"- {ioc.value}")
                if len(type_iocs) > 20:
                    sections.append(f"- ... and {len(type_iocs) - 20} more")
        
        # Analysis outputs
        outputs_section = self._gather_analysis_outputs()
        if outputs_section:
            sections.append("\n## Analysis Results")
            sections.append(outputs_section)
        
        # Build instructions
        instructions = [
            "\n## Report Generation Instructions",
            "Generate a professional incident report based on the above investigation data.",
            "",
            f"**Template**: {template_config['name']}",
            f"**Audience**: {audience}",
            f"**Detail Level**: {detail_level}",
            "",
            "**Required Sections**:",
        ]
        
        for section in template_config['sections']:
            section_name = section.replace('_', ' ').title()
            instructions.append(f"- {section_name}")
        
        instructions.append("")
        instructions.append("**Formatting**:")
        instructions.append("- Use Markdown format")
        instructions.append("- Include tables for IOCs where appropriate")
        instructions.append("- Use clear headings and subheadings")
        instructions.append("- Be concise but thorough")
        
        if custom_instructions:
            instructions.append("")
            instructions.append("**Additional Instructions**:")
            instructions.append(custom_instructions)
        
        sections.extend(instructions)
        
        return '\n'.join(sections)
    
    def _gather_analysis_outputs(self) -> str:
        """Gather and summarize analysis outputs from the case."""
        outputs_dir = self.case.path / 'outputs'
        if not outputs_dir.exists():
            return ""
        
        sections = []
        
        for category in ['phishing', 'malware', 'intel', 'network', 'file']:
            category_dir = outputs_dir / category
            if not category_dir.exists():
                continue
            
            files = list(category_dir.glob('*.json'))
            if not files:
                continue
            
            sections.append(f"\n### {category.title()} Analysis ({len(files)} outputs)")
            
            for output_file in files[:5]:  # Limit per category
                try:
                    data = json.loads(output_file.read_text())
                    # Summarize the output (truncate if too large)
                    summary = json.dumps(data, indent=2)
                    if len(summary) > 2000:
                        summary = summary[:2000] + "\n... (truncated)"
                    sections.append(f"\n#### {output_file.name}")
                    sections.append(f"```json\n{summary}\n```")
                except Exception:
                    pass
            
            if len(files) > 5:
                sections.append(f"\n... and {len(files) - 5} more outputs")
        
        return '\n'.join(sections)
    
    def _to_html(self, markdown_content: str) -> str:
        """Convert Markdown to HTML."""
        try:
            import markdown
            html_body = markdown.markdown(
                markdown_content,
                extensions=['tables', 'fenced_code', 'toc']
            )
        except ImportError:
            # Fallback: basic conversion
            html_body = f"<pre>{markdown_content}</pre>"
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Incident Report: {self.case.name}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            line-height: 1.6;
            max-width: 900px;
            margin: 0 auto;
            padding: 2rem;
            color: #333;
        }}
        h1 {{ color: #1a1a1a; border-bottom: 2px solid #e63946; padding-bottom: 0.5rem; }}
        h2 {{ color: #1d3557; margin-top: 2rem; }}
        h3 {{ color: #457b9d; }}
        table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
        th, td {{ border: 1px solid #ddd; padding: 0.5rem; text-align: left; }}
        th {{ background: #f8f9fa; }}
        code {{ background: #f4f4f4; padding: 0.2rem 0.4rem; border-radius: 3px; }}
        pre {{ background: #f8f9fa; padding: 1rem; border-radius: 5px; overflow-x: auto; }}
        .warning {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 1rem; }}
        .critical {{ background: #f8d7da; border-left: 4px solid #dc3545; padding: 1rem; }}
    </style>
</head>
<body>
{html_body}
<footer style="margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #ddd; color: #666; font-size: 0.9rem;">
    Generated by BSOT Report Module | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
</footer>
</body>
</html>"""
        
        return html
    
    def _save_report(self, content: str, output_format: str) -> Path:
        """Save report to case directory."""
        reports_dir = self.case.path / 'reports'
        reports_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d_%H%M%S')
        extension = 'html' if output_format == 'html' else 'md'
        
        report_file = reports_dir / f"report-{timestamp}.{extension}"
        report_file.write_text(content)
        
        return report_file
    
    @staticmethod
    def get_templates() -> Dict[str, dict]:
        """Get available report templates."""
        return TEMPLATES.copy()


def generate_report_without_llm(case: Case) -> str:
    """
    Generate a basic report without using an LLM.
    
    Useful when no API keys are configured.
    
    Args:
        case: Case to generate report for
        
    Returns:
        Markdown report content
    """
    ioc_store = IOCStore(case.path / 'iocs.json')
    timeline = TimelineManager(case.path / 'timeline.json')
    notes = NotesManager(case.path / 'notes.md')
    
    sections = []
    
    # Header
    sections.append(f"# Incident Report: {case.name}")
    sections.append("")
    sections.append(f"**Case ID**: {case.id}")
    sections.append(f"**Type**: {case.type}")
    sections.append(f"**Status**: {case.status}")
    sections.append(f"**Severity**: {case.severity}")
    sections.append(f"**Created**: {case.created_at}")
    sections.append(f"**Last Updated**: {case.updated_at}")
    sections.append(f"**Analyst**: {case.analyst}")
    sections.append("")
    
    if case.description:
        sections.append("## Description")
        sections.append(case.description)
        sections.append("")
    
    # Timeline
    if timeline.count() > 0:
        sections.append("## Timeline")
        sections.append("")
        sections.append("| Time | Event | Source |")
        sections.append("|------|-------|--------|")
        for event in timeline.get_all():
            sections.append(f"| {event.timestamp} | {event.event} | {event.source} |")
        sections.append("")
    
    # IOCs
    iocs = ioc_store.get_all()
    if iocs:
        sections.append("## Indicators of Compromise")
        sections.append(f"Total: {len(iocs)} IOCs")
        sections.append("")
        
        counts = ioc_store.count_by_type()
        for ioc_type, count in sorted(counts.items()):
            sections.append(f"### {ioc_type.upper()} ({count})")
            for ioc in ioc_store.get_by_type(ioc_type)[:10]:
                sections.append(f"- `{ioc.value}`")
            if count > 10:
                sections.append(f"- ... and {count - 10} more")
            sections.append("")
    
    # Notes
    notes_entries = notes.get_entries()
    if notes_entries:
        sections.append("## Analyst Notes")
        sections.append("")
        for entry in notes_entries:
            sections.append(f"**{entry['timestamp']}**")
            sections.append(entry['text'])
            sections.append("")
    
    # Footer
    sections.append("---")
    sections.append(f"*Report generated by BSOT on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*")
    
    return '\n'.join(sections)



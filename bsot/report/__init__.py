"""
BSOT Report Module
Case management, artifact collection, and AI-powered report generation.
"""

from .case_manager import CaseManager, Case, get_active_case, save_output, add_iocs
from .ioc_store import IOCStore, IOC
from .timeline import TimelineManager, TimelineEvent
from .generator import ReportGenerator
from .llm_client import get_llm_client, LLMClient

__all__ = [
    # Case management
    'CaseManager',
    'Case',
    'get_active_case',
    'save_output',
    'add_iocs',
    # IOC storage
    'IOCStore',
    'IOC',
    # Timeline
    'TimelineManager',
    'TimelineEvent',
    # Report generation
    'ReportGenerator',
    'get_llm_client',
    'LLMClient',
]



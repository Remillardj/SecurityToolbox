#!/usr/bin/env python3
"""
Setup script for BSOT - Blue Security Ops Toolkit
"""

from setuptools import setup, find_packages
from pathlib import Path

readme_file = Path(__file__).parent / 'README.md'
long_description = readme_file.read_text() if readme_file.exists() else ''

setup(
    name='bsot',
    version='2.0.1',
    description='Blue Security Ops Toolkit - Comprehensive security CLI for blue team operations',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Security Team',
    url='https://github.com/Remillardj/SecurityToolbox',
    python_requires='>=3.8',
    packages=find_packages(include=['bsot', 'bsot.*']),
    install_requires=[
        'click>=8.0.0',
        'requests>=2.25.0',
        'dnspython>=2.1.0',
        'python-dateutil>=2.8.0',
        'psutil>=5.9.0',
    ],
    extras_require={
        'full': [
            'python-whois>=0.8.0',
            'PyPDF2>=3.0.0',
            'exifread>=3.0.0',
            'python-magic>=0.4.24',
            'extract-msg>=0.36.0',
            'rich>=10.0.0',
        ],
        'malware': [
            'pefile>=2023.2.7',       # PE file analysis
            'yara-python>=4.3.0',     # YARA rule scanning
            # Note: ssdeep requires libfuzzy-dev system package
            # Install with: apt-get install libfuzzy-dev (Debian/Ubuntu)
            #              brew install ssdeep (macOS)
            # 'ssdeep>=3.4',          # Fuzzy hashing (optional, requires libfuzzy)
            'py-tlsh>=4.7.2',         # TLSH fuzzy hashing
        ],
        'report': [
            'anthropic>=0.40.0',      # Anthropic Claude API
            'openai>=1.10.0',         # OpenAI API
            'markdown>=3.5.0',        # Markdown to HTML conversion
            # 'pyzipper>=0.3.6',      # Encrypted ZIP (optional)
        ],
    },
    entry_points={
        'console_scripts': [
            'bsot=bsot.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Topic :: Security',
        'Topic :: System :: Monitoring',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
    keywords=[
        'security', 'phishing', 'threat-intelligence', 'blue-team',
        'incident-response', 'forensics', 'secrets-detection',
        'malware-analysis', 'yara', 'pe-analysis', 'ioc-extraction',
    ],
)

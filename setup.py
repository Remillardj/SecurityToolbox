#!/usr/bin/env python3
"""
Setup script for BSOT - Blue Security Ops Toolkit
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_file = Path(__file__).parent / 'README.md'
long_description = ''
if readme_file.exists():
    long_description = readme_file.read_text()

setup(
    name='bsot',
    version='1.0.0',
    description='Blue Security Ops Toolkit - Comprehensive security tools for file analysis, network scanning, and log analysis',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Security Team',
    python_requires='>=3.7',
    packages=find_packages(),
    install_requires=[
        'click>=8.0.0',
        'requests>=2.25.0',
        'dnspython>=2.1.0',
    ],
    entry_points={
        'console_scripts': [
            'bsot=bsot:cli',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'Topic :: System :: Monitoring',
        'Topic :: System :: Networking :: Monitoring',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
)

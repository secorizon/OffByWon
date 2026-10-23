#!/usr/bin/env python3
"""
OffByWon Framework - Setup Script
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="offbywon",
    version="2.0.1",
    author="Laurent Gaffié",
    description="Declarative Protocol Fuzzing Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/secorizon/OffByWon",
    project_urls={
        "Source": "https://github.com/secorizon/OffByWon",
        "Issues": "https://github.com/secorizon/OffByWon/issues",
    },
    license="MIT",
    packages=find_packages(exclude=("tests", "tests.*", "examples", "examples.*")),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.8",
    install_requires=[],  # No external dependencies
    extras_require={
        "dev": ["pytest>=7", "pytest-cov>=4", "build>=1"],
        "quic": ["cryptography>=41"],
        "smb": ["pycryptodome>=3.18"],
        "examples": ["cryptography>=41", "pycryptodome>=3.18"],
    },
)

"""Setup script for Canary - Anti-Forensics Detector."""

from setuptools import setup, find_packages

setup(
    name="canary",
    version="1.0.0",
    description="Anti-Forensics Detector - Detects evidence tampering, log manipulation, and anti-forensic activity",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[],
    extras_require={
        "full": [
            "python-evtx>=0.7.4",
            "python-registry>=1.4.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "canary=canary.cli:main",
        ],
    },
)

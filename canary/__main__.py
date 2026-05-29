"""
Allow running Canary as a module: python -m canary
"""

import sys
from canary.cli import main

if __name__ == "__main__":
    sys.exit(main() or 0)

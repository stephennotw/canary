#!/bin/bash
# Canary - Anti-Forensics Detector - One-Click Run Script (Linux/Mac)
# ===================================================================

echo ""
echo "  Canary - Anti-Forensics Detector"
echo "  ================================="
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 not found. Please install Python 3.9+"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -q -r requirements.txt 2>/dev/null

# Run Canary
if [ $# -eq 0 ]; then
    echo ""
    echo "Usage: ./run.sh [OPTIONS]"
    echo ""
    echo "Quick Start:"
    echo "  ./run.sh --live                          # Scan live system (root required)"
    echo "  ./run.sh --mft-csv MFT.csv               # Analyze MFT export"
    echo "  ./run.sh --evtx-path ./logs/             # Analyze event logs"
    echo "  ./run.sh --help                          # Show all options"
    echo ""
    python3 -m canary --help
else
    python3 -m canary "$@"
fi

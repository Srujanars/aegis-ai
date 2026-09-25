#!/usr/bin/env bash
cd "$(dirname "$0")"

echo "========================================================================"
echo "🛡️  AegisAI: Enterprise Shadow AI Data Leak Gateway"
echo "   Zero-Knowledge Reversible Tokenizer for LLMs & Copilots"
echo "========================================================================"
echo "Starting backend REST API & Web Dashboard on http://localhost:5050"
echo "Press Ctrl+C to terminate."
echo "========================================================================"

python3 backend/server.py

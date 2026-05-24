#!/bin/bash
echo "==================================================="
echo "  正在啟動 PQC 混合自動化審計系統 (macOS 綠色版)..."
echo "==================================================="
# 確保腳本在當前目錄執行
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

# 呼叫封包內自帶的 streamlit 來執行你的程式碼
./venv/bin/python3 -m streamlit run src/website.py --server.port 8501
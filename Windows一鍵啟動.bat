@echo off
title PQC Hybrid Auditor
echo ===================================================
echo   正在啟動 PQC 混合自動化審計系統 (Windows 綠色版)...
echo ===================================================
cd /d "%~dp0"

:: 呼叫封包內的 Python 執行 Streamlit
env\python.exe -m streamlit run src\website.py --server.port 8501

@echo off
cd /d "%~dp0"
venv\Scripts\python -m streamlit run src\website.py --server.port 8501

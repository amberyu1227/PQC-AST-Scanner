import os
from scanner_py import PythonScanner
from scanner_java import JavaScanner
from scanner_cpp import CppScanner

def scan_file(filepath):
    """
    根據檔案副檔名自動選擇對應的掃描器 (處理單一檔案)
    """
    ext = os.path.splitext(filepath)[-1].lower()
    
    # 掃描器映射表
    scanners = {
        '.py': PythonScanner,
        '.java': JavaScanner,
        '.cpp': CppScanner,
        '.c': CppScanner,
        '.h': CppScanner,
        '.cc': CppScanner
    }

    scanner_class = scanners.get(ext)
    
    # 1. 檢查是否支援該副檔名
    if not scanner_class:
        print(f"⚠️ 不支援的檔案格式: {ext}")
        return []
        
    # 2. 統一實例化邏輯
    try:
        if scanner_class == CppScanner:
            scanner = scanner_class()  # 朋友的版本：__init__(self)
        else:
            scanner = scanner_class(filepath) # 你的版本：__init__(self, filename)
            
        return scanner.scan(filepath)
    except Exception as e:
        print(f"❌ 掃描過程出錯 ({filepath}): {e}")
        return []

def scan_project_recursive(root_dir):
    """
    遞迴掃描整個資料夾 (對應原本 V2 的目錄掃描邏輯)
    """
    all_findings = []
    # 定義目前支援的副檔名
    SUPPORTED_EXTENSIONS = ('.py', '.java', '.c', '.cpp', '.h')

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # 排除掉不需要掃描的資料夾 (維持原本 V2 的排除邏輯)
        if any(x in dirpath for x in ['venv', '.git', '__pycache__', 'pqc_venv']):
            continue
            
        for filename in filenames:
            if filename.endswith(SUPPORTED_EXTENSIONS):
                filepath = os.path.join(dirpath, filename)
                try:
                    # 直接呼叫上面的 scan_file 進行處理
                    findings = scan_file(filepath)
                    all_findings.extend(findings)
                except Exception as e:
                    print(f"❌ 檔案 {filepath} 掃描失敗: {e}")
                    
    return all_findings
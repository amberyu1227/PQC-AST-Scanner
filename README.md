# ⚛️ PQC-AST-Scanner

![Python Version](https://img.shields.io/badge/Python-3.11-blue.svg)
![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B.svg)
![Gemini AI](https://img.shields.io/badge/AI-Gemini_3.5_Flash-8E75B2.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

**PQC Hybrid Auditor** 是一款專為後量子密碼學（PQC）遷移與傳統密碼學漏洞檢測所設計的靜態代碼分析（SAST）工具。本系統採用高度解耦的模組化架構，支援 `Python`、`Java` 及 `C/C++` 的語法樹級別清查，並無縫整合大語言模型（LLM）與符合國際最新標準的加密軟體物料清單（CBOM）產出，為企業提供自動化的密碼資產盤點、風險評級與遷移代碼修復建議。

---

# 📊 系統架構

```
                ┌─────────────────────┐
                │   Streamlit Web UI  │
                │     website.py      │
                └──────────┬──────────┘
                           │
                    Scan Request
                           │
                ┌──────────▼──────────┐
                │     Scanner Core    │
                │      scanner.py     │
                │   AST Static Scan   │
                └──────────┬──────────┘
                           │
             ┌─────────────┼─────────────┐
             │             │             │
        Python AST      Java AST        C AST
         (ast)         (javalang)     (pycparser)
             │
             ▼
      Cryptographic Findings
             │
   ┌─────────┴─────────┐
   │                   │
Plotly Visualization   AI Analysis
       │                   │
       ▼                   ▼
 Interactive Dashboard   Gemini Chat
```

---

## ✨ 核心功能 (Key Features)

* 🔍 **多語言 AST 深度掃描**：支援 `Python`, `Java`, `C/C++` 的語法樹（Abstract Syntax Tree）級別解析，精準定位加密資產。
* 💻 **Web Dashboard**：使用 **Streamlit** 提供互動式介面：提供多檔案掃描、資料夾掃描、風險統計圖、掃描結果表、AI 分析助手功能。
* 🧠 **AI 智能修復 (BYOK 模式)**：內建 Gemini 3.5-flash / 3.1-pro 模型。採用「自攜金鑰 (Bring Your Own Key)」設計，金鑰僅存於本地記憶體，確保企業級原始碼與金鑰的絕對安全。
* 📊 **視覺化資安儀表板**：使用 Plotly 動態生成 PQC 遷移與弱點風險分佈圓餅圖，風險層級一目了然。
* 📝 **CBOM 報告生成**：一鍵匯出符合標準的加密資產軟體物料清單（Cryptographic Bill of Materials, CBOM）JSON 報表。
* 🚀 **極致的可攜性**：提供 **Windows & macOS 雙系統免安裝綠色包**，隨插即用，徹底告別 C++ 編譯環境與 Python 相依性地獄。

---

## ⚡ 快速上手 (Quick Start)

對於一般使用者、稽核人員或評委，**完全不需要設定 Python 環境**，請直接使用我們準備好的免安裝版本：

### 📥 1. 下載綠色免安裝包
請前往本專案的 [Releases 頁面](../../releases) 下載對應您作業系統的壓縮檔：
* **🍎 macOS 使用者**：下載 PQC-Scanner-MacOS.tar.gz
* **💻 Windows 使用者**：下載 PQC-Scanner-Windows.zip

### 🚀 2. 一鍵啟動
1. 將下載的檔案解壓縮。
2. 進入資料夾，雙擊啟動腳本：
   * **Mac**: 雙擊 🚀啟動-Mac.command
   * **Windows**: 雙擊 🚀啟動-Windows.bat
3. 系統將自動打開預設瀏覽器並載入掃描器介面 (預設為 `http://localhost:8501`)。

### 🔑 3. 啟用 AI 助手
本系統的 AI 諮詢功能需使用 Google Gemini API：
1. 於系統左側欄點擊「🔑 如何獲取免費的 Gemini API Key？」查看申請教學。
2. 將獲取的金鑰貼入系統設定欄位中。
3. 選擇您欲使用的 AI 模型（推薦使用預設的 `gemini-3.5-flash`），即可開始進行代碼對話與漏洞修復諮詢！

---

## 🛠️ 開發與建置指南 (For Developers)

若您希望參與本專案開發，或自行從原始碼建置系統，請參考以下說明。

### 系統需求
* **Python 3.11** (強烈建議，以確保 tree-sitter-cpp 的預編譯套件相容性)
* Git

### 1. 取得程式碼與安裝依賴包

#### 複製專案原始碼

```
git clone https://github.com/your-repo/PQC-AST-Scanner.git
cd PQC-AST-Scanner
```

#### 建立虛擬環境 (以 Mac/Linux 為例)
```
python3.11 -m venv venv
source venv/bin/activate
```

#### 安裝依賴套件
```
pip install -r requirements.txt
```

### 2. 啟動開發伺服器
```
streamlit run src/website.py
```

### 3. 自動化跨平台打包
本專案提供了一鍵打包腳本 `build.sh`。當開發完成準備發佈新版本時，只需在根目錄執行：
```
./build.sh
```
腳本將會自動過濾環境暫存檔，組裝 src/ 程式碼與對應的系統環境，並在目錄下生成 PQC-Scanner-MacOS.tar.gz 與 PQC-Scanner-Windows.zip 供發布使用。

---

## 🎯 檢測項目與規則 (Supported Rules)

本系統目前可精準識別以下安全風險：
* **硬編碼機密 (Hardcoded Secrets)**：包含 API Tokens, Cloud Credentials, Passwords (對應 B702, B708 規範)
* **弱加密演算法 (Weak Crypto)**：檢測明文使用的 DES, MD5, SHA1 等過時演算法
* **PQC 遷移目標盤體 (PQC Transition)**：全面盤點傳統 RSA, ECC 等不具備抗量子能力的加密資產
* **不良安全實作 (Insecure Implementation)**：弱隨機數生成源 (Weak Random)、不足的 Salt 長度、高風險 GCM Nonce 重複使用風險

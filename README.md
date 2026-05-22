# 🛡️ PQC Hybrid Auditor (後量子密碼學混合自動化審計系統)

![Python Version](https://img.shields.io/badge/Python-3.11-blue.svg)
![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B.svg)
![Gemini AI](https://img.shields.io/badge/AI-Gemini_3.5_Flash-8E75B2.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

**PQC Hybrid Auditor** 是一款專為後量子密碼學（PQC）遷移與傳統密碼學漏洞檢測所設計的靜態代碼分析（SAST）工具。本系統採用高度解耦的模組化架構，支援 `Python`、`Java` 及 `C/C++` 的語法樹級別清查，並無縫整合大語言模型（LLM）與符合國際最新標準的加密軟體物料清單（CBOM）產出，為企業提供自動化的密碼資產盤點、風險評級與遷移代碼修復建議。

---

## ✨ 核心功能 (Key Features)

* 🔍 **跨語言 AST 深度清查**：支援 Python (`ast`)、Java (`javalang`) 及 C/C++ (**Tree-sitter 雙階段語義解析**)，精準鎖定加密資產，徹底告別傳統 `grep` 的高誤報率。
* 📝 **對標國際標準之 CBOM 輸出**：100% 對標 **IBM CBOM 治理框架** 與最新 **CycloneDX 1.6 加密延伸擴充規範**。報告內建國際標準 **OID（物件識別碼）**、`cryptoProperties`（加密物理特性）、靜態分析原始碼證據鏈，以及資產拓撲相依關係圖譜 (`dependencies`)。
* 🧠 **AI 驅動遷移決策 (BYOK 模式)**：深度整合 Google Gemini API，不僅提供弱點成因分析，更能讀取漏洞上下文（Context），自動產出符合 NIST 規範的後量子密碼（如 ML-KEM/ML-DSA）修復代碼。
* 📊 **動態資安儀表板**：結合 Streamlit 與 Plotly 動態圖表，即時渲染「PQC 遷移與弱點風險分佈圓餅圖」，一目了然傳統脆弱、量子脆弱與後量子就緒資產。
* 🚀 **極致的可攜性與部署**：提供 **Windows & macOS 雙系統免安裝綠色包**，免去編譯環境與 Python 相依性地獄，隨插即用。

---

## 📊 系統模組化架構 (Architecture)

本系統正式從「單一腳本」轉型為專業的 **「四層過濾與執行架構」**，實作主程式與偵測邏輯的徹底解耦：


```

```
            ┌───────────────────────────────────┐
            │    第 1 層：互動與顯示層 (Web UI)   │
            │    (website.py / Streamlit & LLM) │
            └─────────────────┬─────────────────┘
                              │ 上傳檔案 / 目錄掃描
                              ▼
            ┌───────────────────────────────────┐
            │    第 2 層：路由與派發層 (Factory)  │
            │  (scanner_factory.py 工廠模式介面) │
            └─────────────────┬─────────────────┘
                              │ 依副檔名動態分發 (.py, .java, .cpp)
                              ▼
            ┌───────────────────────────────────┐
            │    第 3 層：核心偵測引擎層 (Engine) │
            │  [PythonScanner] [Java] [CppScanner]│
            └─────────────────┬─────────────────┘
                              │ 呼叫標準化介面與向基類查表
                              ▼
            ┌───────────────────────────────────┐
            │    第 4 層：基礎設施與規則層 (Base) │
            │     (scanner_base.py 統一知識庫)   │
            └───────────────────────────────────┘

```

```
1. **第一層：互動與顯示層**：負責 Streamlit 介面渲染、Plotly 風險圖表展示及與 Gemini 專家助手進行上下文感知對話。
2. **第二層：路由與派發層**：導入 **工廠模式 (Factory Pattern)**，自動識別副檔名並指派任務，UI 層完全不需要知道後端如何解析 AST。
3. **第三層：語言特定引擎**：執行專項開發與技術隔離。其中 C++ 引擎實作**雙階段掃描**（第一階段 `_collect_alias` 收集 `typedef`/`using` 別名；第二階段 `_traverse` 進行 DFS 特徵匹配）。
4. **第四層：基礎設施與規則層**：由 `BaseScanner` 類別定義標準化回報方法；`PQC_KNOWLEDGE_BASE` 集中管理所有加密弱點與 OID 映射，確保跨語言偵測結果的技術一致性。

---

## ⚡ 快速上手 (Quick Start)

### 📥 方法 1：使用免安裝綠色包 (一般使用者/稽核評委推薦)
完全不需要設定 Python 環境或安裝任何套件，徹底告別環境地獄：
1. 前往本專案的 [Releases 頁面](../../releases) 下載作業系統對應的壓縮檔（`PQC-Scanner-Windows.zip` 或 `PQC-Scanner-MacOS.tar.gz`）。
2. 解壓縮檔案後，進入資料夾雙擊啟動腳本：
   * **Windows 系統**：雙擊 `🚀啟動-Windows.bat`
   * **macOS 系統**：雙擊 `🚀啟動-Mac.command`
3. 系統將自動打開預設瀏覽器並載入介面 (`http://localhost:8501`)。

### 🛠️ 方法 2：原始碼建置與開發 (For Developers)
* **系統需求**：強烈建議使用 **Python 3.11** (以確保 Tree-sitter 預編譯套件相容性)。

1. **取得程式碼與建立虛擬環境**：
   ```bash
   git clone [https://github.com/your-repo/PQC-AST-Scanner.git](https://github.com/your-repo/PQC-AST-Scanner.git)
   cd PQC-AST-Scanner
   
   # Windows 建立與啟用虛擬環境
   python -m venv venv
   venv\Scripts\activate
   
   # Mac / Linux 建立與啟用虛擬環境
   python3.11 -m venv venv
   source venv/bin/activate

```

2. **安裝相依套件**：
```bash
pip install streamlit pandas plotly javalang tree-sitter tree-sitter-cpp google-generativeai numpy

```


3. **啟動 Web UI**：
```bash
streamlit run website.py

```



---

## 🎯 檢測項目、對標規格與 PQC 風險狀態

系統嚴格遵循 **IBM CBOM 治理指標**與 **NIST/CycloneDX 規範**，將清查出的加密資產進行自動化風險狀態權重評級：

| PQC 遷移防禦狀態 (PQC_Status) | 涵蓋規則 (RuleID) | 工業級 OID 識別標準 | 檢測項目與安全治理範疇 |
| --- | --- | --- | --- |
| **VULNERABLE (CLASSIC)** | B303, B324, B304 | 1.3.14.3.2.26 / 1.2.840.113549.2.5 | 傳統弱雜湊與對稱加密（如 MD5, SHA-1, DES/3DES）。 |
| **VULNERABLE (QUANTUM)** | B413_RSA, B413_ECC | 1.2.840.113549.1.1.1 / 1.2.840.10045.2.1 | 量子脆弱非對稱演算法（傳統 RSA 密鑰、ECC 橢圓曲線資產）。 |
| **VULNERABLE (QUANTUM)** | B413_RSA_WEAK_SIZE | 1.2.840.113549.1.1.1 | 進階參數風險：RSA 密鑰長度小於 2048 bits（如 1024-bit 密鑰）。 |
| **VULNERABLE (QUANTUM)** | B415_ECC_WEAK_CURVE | 1.3.132.0.33 | 進階參數風險：不安全的弱橢圓曲線（如 SECP192R1, P-192）。 |
| **VULNERABLE (QUANTUM)** | B413_AES_WEAK | 2.16.840.1.101.3.4.1.1 | 不安全實作：使用了易受頻率分析攻擊的 AES-ECB 模式。 |
| **VULNERABLE (QUANTUM)** | B413_IV_WEAK | 2.16.840.1.101.3.4.1.2 | 使用樣式風險：AES-CBC 或 CFB 模式中缺失隨機 IV / Nonce。 |
| **CRITICAL_SECRET_LEAK** | B702, B706, B707, B708 | N/A | 硬編碼秘密與憑證洩漏（硬編碼密鑰、Password、AWS Cloud Key、API Token）。 |
| **CRITICAL_SECRET_LEAK** | B709_HARDCODED_PQC_SK | N/A | 後量子致命漏洞：寫死在代碼中的 PQC 私鑰（Secret Key）洩漏。 |
| **SAFE (QUANTUM-RESISTANT)** | B413_AES_SAFE | 2.16.840.1.101.3.4.1.46 | 過渡期抗量子資產：合規的對稱加密（如標準 AES-GCM, AES-CBC 搭配合規 IV）。 |
| **PQC_READY** | B501_KYBER, B502_DILITHIUM | 2.16.840.1.101.3.4.4.1 / 2.16.840.1.101.3.4.3.17 | 正面識別：NIST 官方 FIPS 203/204 標準後量子演算法（ML-KEM / ML-DSA）。 |

---

## 📂 專案核心目錄結構

```
PQC-AST-Scanner
│
├─ build.sh                    # 自動化跨平台過濾與打包腳本 (免安裝包製作)
├─ requirements.txt            # Python 相依性套件清單
├─ run_benchmark.py            # 自動化基準測試、混淆矩陣與 QA 數據評估腳本
│
└─ main-code / new-structure   # 核心結構化原始碼目錄
    ├─ website.py              # Streamlit Web UI 主程式與 Gemini AI 對話層
    ├─ scanner_factory.py      # 工廠模式路由，負責解耦分發多語言檔案
    ├─ scanner_base.py         # 基礎設施層：統一知識庫、BaseScanner 與標準 CBOM 生成引擎
    ├─ scanner_py.py           # Python 偵測引擎 (基於原生 ast 遍歷)
    ├─ scanner_java.py         # Java 偵測引擎 (基於 javalang 解析)
    ├─ scanner_cpp.py          # C++ 偵測引擎 (基於 Tree-sitter 雙階段語義分析)
    └─ parser_cpp.py           # Tree-sitter-cpp 解析器封裝

```

---

## 📜 授權條款 (License)

本專案採用 [MIT License](https://www.google.com/search?q=LICENSE) 授權。歡迎自由使用、修改與散佈，唯需保留原作者與專題團隊聲明。
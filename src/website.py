import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from google import genai     # 🚀 升級：改用新版官方 SDK
import json
import os
from datetime import datetime
import tempfile

# --- 【核心調度：工廠模式接口】 ---
from scanner_factory import scan_file, scan_project_recursive
from scanner_base import _determine_pqc_status, generate_cbom_json

def get_pqc_context():
    if 'findings' in st.session_state and not st.session_state['findings'].empty:
        df_mini = st.session_state['findings'].head(10)
        context = "當前掃描到的前 10 項加密資產：\n"
        for _, row in df_mini.iterrows():
            context += f"- [{row['Type']}] 位於 {row['Location']}\n"
        return context
    return "尚無掃描結果。"

# 初始化對話紀錄
if "messages" not in st.session_state:
    st.session_state.messages = []

# 1. 頁面配置
st.set_page_config(page_title="PQC Scanner", layout="wide", initial_sidebar_state="expanded")

# --- 2. 最左側：來源區與設定區 (Sidebar) ---
with st.sidebar:
    # 新增安全的金鑰輸入框，型態為 password (隱碼顯示)
    st.markdown("### ⚙️ 系統設定")
    user_api_key = st.text_input(
        "請輸入 Gemini API Key", 
        type="password",
        placeholder="AIzaSy...",
        help="請輸入來自 Google AI Studio 的有效金鑰。此金鑰僅保存在瀏覽器記憶體中，絕不上傳或外洩。"
    )
    # 新增API Key 獲取操作指南摺疊選單
    with st.expander("🔑 如何獲取免費的 Gemini API Key？"):
        st.markdown("""
        請按照以下 5 個步驟免費申請：
        
        1. **前往官網**：  
           點擊訪問 [Google AI Studio](https://aistudio.google.com/) 平台。
        2. **帳號登入**：  
           使用您常用的 Google 帳號進行登入。
        3. **進入金鑰頁面**：  
           點擊左側選單最下方的 **「Get API key」**。
        4. **建立全新金鑰**：  
           點擊右上方藍色的 **「Create API key」** 按鈕，系統會彈出視窗引導，直接點選建立新專案金鑰即可。
        5. **複製與使用**：  
           複製畫面上產生的那一長串亂碼（通常是以 `AIzaSy` 開頭），並將其完整貼回上方的輸入框中。
        
        ---
        *💡 提示：目前 Google 提供的免費額度已完全足夠支援本專報所使用的所有最新模型（含 3.5 系列）！*
        """)
    # 讓使用者自由切換模型
    selected_model = st.selectbox(
        "🧠 選擇 AI 推理模型",
        [
            "gemini-3.5-flash",       # 兼具極速與最新架構 (預設首選)
            "gemini-3.1-pro",         # 處理複雜 C++ 邏輯與深度除錯的最強大腦
            "gemini-3.1-flash-lite"   # 輕量級、極低延遲的快速分析
        ],
        help="Flash 適合快速掃描分析，Pro 適合深度的複雜代碼邏輯推理。"
    )
    st.divider()

    st.markdown("### 來源")
    # 檔案上傳器 - 支援 Python, Java, C/C++
    uploaded_files = st.file_uploader(
        "上傳程式碼進行 PQC 掃描", 
        accept_multiple_files=True,
        type=["py", "java", "c", "cpp", "h", "cc"] 
    )
    st.divider()
    
    if uploaded_files:
        st.success(f"已載入 {len(uploaded_files)} 個檔案")
        
        if st.button("開始掃描", use_container_width=True):
            all_findings = []
            
            for i, file in enumerate(uploaded_files):
                # 建立暫存檔，保留原始副檔名以利 Factory 判斷
                with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.name)[1]) as tmp:
                    tmp.write(file.getvalue())
                    tmp_path = tmp.name

                try:
                    # 統一呼叫新的 scan_file 接口
                    findings = scan_file(tmp_path)
                    
                    for f in findings:
                        f['Location'] = f['Location'].replace(tmp_path, file.name)
                    
                    all_findings.extend(findings)
                finally:
                    os.unlink(tmp_path)

            if all_findings:
                df = pd.DataFrame(all_findings)
                # 使用從 scanner_base 匯入的狀態判斷
                df['PQC_Status'] = df['RuleID'].apply(_determine_pqc_status)
                st.session_state['findings'] = df
                st.session_state['last_file'] = f"多檔案掃描 ({len(uploaded_files)} 檔案)"
            else:
                st.session_state['findings'] = pd.DataFrame()

    # 資料夾掃描
    st.divider()
    st.markdown("### 資料夾掃描")
    raw_path = st.text_input("輸入本機資料夾路徑:", placeholder="C:/Users/Project/src")
    clean_path = raw_path.strip().strip('"').strip("'")
    
    if st.button("直接掃描該目錄"):
        if clean_path and os.path.isdir(clean_path):
            with st.spinner(f"正在掃描：{clean_path}"):
                results = scan_project_recursive(clean_path)
                
                if results:
                    df = pd.DataFrame(results)
                    df['PQC_Status'] = df['RuleID'].apply(_determine_pqc_status)
                    st.session_state['findings'] = df
                    st.session_state['last_file'] = f"目錄掃描: {os.path.basename(clean_path)}"
                    st.success("掃描完成！")
                else:
                    st.warning("該目錄下未發現支援的程式碼檔案。")
        elif not clean_path:
            st.warning("請輸入路徑。")
        else:
            st.error(f"路徑無效，請檢查：{clean_path}")
                
# --- 3. 主內容區：對話與圖表 (6:4 比例) ---
chat_col, chart_col = st.columns([6, 4], gap="medium")

# 【中間：對話區】
with chat_col:
    with st.container(border=True):
        st.markdown("#### 💬 AI 漏洞修復專家建議")

    chat_container = st.container(height=500)

    with chat_container:
        for m in st.session_state.messages:
            with st.chat_message(m["role"]):
                st.markdown(m["content"])

    if prompt := st.chat_input("詢問有關掃描結果的建議..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with chat_container:
            with st.chat_message("user"):
                st.markdown(prompt)

        with chat_container:
            with st.chat_message("assistant"):
                # 🚀 變更點 2：檢查使用者有沒有填寫 API Key
                if not user_api_key:
                    st.error("⚠️ 請先在左側「系統設定」中輸入您的 Gemini API Key，才能啟用 AI 專家諮詢功能。")
                else:
                    try:
                        context = get_pqc_context()
                        full_prompt = f"你是 PQC 專家。請根據數據回答：\n{context}\n\n問題：{prompt}"
                        
                        with st.spinner(f"AI ({selected_model}) 正在深度分析中..."):
                            # 🚀 變更點 3：動態實例化新版 SDK 的 Client
                            client = genai.Client(api_key=user_api_key)
                            
                            # 🚀 變更點 4：使用新版語法呼叫最新穩定模型 gemini-2.5-flash
                            response = client.models.generate_content(
                                model=selected_model,
                                contents=full_prompt
                            )
                            answer = response.text
                            st.markdown(answer)
                            st.session_state.messages.append({"role": "assistant", "content": answer})
                    except Exception as e:
                        if "429" in str(e) or "quota" in str(e).lower():
                            st.error("⚠️ 觸發 Gemini 免費版流量限制或 API 額度不足。請稍候再試。")
                        else:
                            st.error(f"連線 AI 失敗，請確認 Key 是否正確：{e}")

# 【右側：圖表區】
def generate_risk_pie_chart_object(findings):
    if not findings:
        return None
        
    df = pd.DataFrame(findings)
    
    color_map = {
        'WEAK_HASH_SHA1': '#D35400', 'WEAK_HASH_MD5': '#C0392B', 
        'WEAK_CIPHER_DES': '#C0392B', 'WEAK_ASSET_RSA': '#D35400', 
        'WEAK_CIPHER_MODE': '#C0392B', 'WEAK_IV_NONCE': '#D35400', 
        'PQC_TARGET_RSA': '#2980B9', 'PQC_TARGET_ECC': '#2980B9', 
        'TRADITIONAL_AES_ASSET': '#27AE60', 'SECRET_LEAKAGE': '#C0392B',    
        'PQC_KEM_ML_KEM': '#2980B9', 'PQC_SIGN_ML_DSA': '#2980B9', 
        'HARDCODED_SECRET_KEY': '#C0392B', 'HARDCODED_PASSWORD': '#C0392B', 
        'HARDCODED_CLOUD_CREDENTIAL': '#C0392B', 'HARDCODED_API_TOKEN': '#C0392B', 
        'HARDCODED_PQC_PRIVATE_KEY': '#C0392B', 'WEAK_RANDOM_SOURCE': '#C0392B', 
        'WEAK_ECC_CURVE': '#D35400', 'WEAK_KDF_ITERATION_COUNT': '#D35400', 
        'INSUFFICIENT_SALT_LENGTH': '#D35400', 'RISKY_GCM_NONCE_LENGTH': '#D35400',
    }
    
    stats = df['Type'].value_counts().reset_index()
    stats.columns = ['Type', 'Count']
    stats['Color'] = stats['Type'].map(color_map).fillna('#95A5A6')
    stats = stats.sort_values(by=['Color', 'Count'], ascending=[True, False])

    fig = go.Figure(data=[go.Pie(
        labels=stats['Type'],
        values=stats['Count'],
        hole=.4, 
        marker=dict(colors=stats['Color']),
        hovertemplate='%{label}<br>數量: %{value}<extra></extra>',
        sort=False 
    )])
    
    fig.update_layout(
        title={'text': "PQC 遷移與弱點風險分佈 (總資產數: {})".format(len(findings)),'y': 0.95,'x': 0.5,'xanchor': 'center','yanchor': 'top'},
        font_color="#E0E0E0",
        margin=dict(l=20, r=20, t=80, b=20),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        showlegend=False
    )
    return fig

# 右側顯示區
with chart_col:
    with st.container(border=True): 
        st.markdown("#### 📊 數據視覺化")
        
        if 'findings' in st.session_state and not st.session_state['findings'].empty:
            current_findings = st.session_state['findings'].to_dict('records')
            fig = generate_risk_pie_chart_object(current_findings)
            if fig:
                st.plotly_chart(fig, use_container_width=True)
            
            st.divider()
            
            # 表格部分
            df_display = st.session_state['findings'][['Location', 'Type', 'CodeSnippet', 'FixSuggestion']].copy()    
            df_display.columns = ['位置', '類型', '代碼片段', '修補建議']
            df_display.index = df_display.index + 1
            st.dataframe(df_display, use_container_width=True)
        else:
            st.info("💡 請在左側上傳檔案並點擊「開始掃描」以生成風險圖表。")

        st.divider()
        
        # 下載按鈕
        if 'findings' in st.session_state and not st.session_state['findings'].empty:
            current_findings = st.session_state['findings'].to_dict('records')
            cbom_dict = generate_cbom_json(current_findings)
            json_string = json.dumps(cbom_dict, indent=4, ensure_ascii=False)
            
            st.download_button(
                label="📝 下載 CBOM 報告",
                data=json_string,
                file_name=f"PQC_Analysis_{datetime.now().strftime('%Y%m%d_%H%M')}.json",
                mime="application/json",
                use_container_width=True 
            )
        else:
            st.button("📝 產生報告 (請先完成掃描)", disabled=True, use_container_width=True)
import streamlit as st      # 需要安裝: pip install streamlit
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import google.generativeai as genai     # 需要安裝: pip install google-generativeai
import json
import os
from datetime import datetime
import tempfile

# --- 【核心變動：改用工廠模式接口】 ---
from scanner_factory import scan_file, scan_project_recursive
from scanner_base import _determine_pqc_status, generate_cbom_json

# 配置 Gemini (維持原樣)
genai.configure(api_key="Gemini key")
try:
    available_models = [m.name for m in genai.list_models() if 'generateContent' in m.supported_generation_methods]
    target_model = next((m for m in available_models if "flash" in m), available_models[0])
    model = genai.GenerativeModel(target_model)
    print(f"成功連線至可用模型: {target_model}")
except Exception as e:
    st.error(f"無法獲取模型清單，請檢查 API Key 是否正確：{e}")
    
def get_pqc_context():
    if 'findings' in st.session_state and not st.session_state['findings'].empty:
        df_mini = st.session_state['findings'].head(10)
        context = "當前掃描到的前 10 項加密資產：\n"
        for _, row in df_mini.iterrows():
            context += f"- [{row['Type']}] 位於 {row['Location']}\n"
        return context
    return "尚無掃描結果。"

# 初始化對話紀錄 (維持原樣)
if "messages" not in st.session_state:
    st.session_state.messages = []

# 1. 頁面配置 (維持原樣)
st.set_page_config(page_title="PQC Scanner", layout="wide", initial_sidebar_state="expanded")

# --- 2. 最左側：來源區 (Sidebar) (維持原樣排版) ---
with st.sidebar:
    st.markdown("### 來源")
    
    # 檔案上傳器 - 增加 C/C++ 支援
    uploaded_files = st.file_uploader(
        "上傳程式碼進行 PQC 掃描", 
        accept_multiple_files=True,
        type=["py", "java", "c", "cpp", "h"] 
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

    # 資料夾掃描 (維持原樣)
    st.divider()
    st.markdown("### 資料夾掃描")
    raw_path = st.text_input("輸入本機資料夾路徑:", placeholder="C:/Users/Project/src")
    clean_path = raw_path.strip().strip('"').strip("'")
    
    if st.button("直接掃描該目錄"):
        if clean_path and os.path.isdir(clean_path):
            with st.spinner(f"正在掃描：{clean_path}"):
                # 統一呼叫新架構的遞迴掃描
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
                
# --- 3. 主內容區：對話與圖表 (維持原樣 6:4 比例) ---
chat_col, chart_col = st.columns([6, 4], gap="medium")

# 【中間：對話區】 (完全保留原本容器與歷史訊息邏輯)
with chat_col:
    with st.container(border=True):
        st.markdown("#### 對話 ")

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
                try:
                    context = get_pqc_context()
                    full_prompt = f"你是 PQC 專家。請根據數據回答：\n{context}\n\n問題：{prompt}"
                    
                    with st.spinner("AI 正在思考中..."):
                        response = model.generate_content(full_prompt)
                        answer = response.text
                        st.markdown(answer)
                        st.session_state.messages.append({"role": "assistant", "content": answer})
                except Exception as e:
                    if "429" in str(e):
                        st.error("⚠️ 觸發 Gemini 免費版流量限制。請等待約 1 分鐘後再試。")
                    else:
                        st.error(f"連線 AI 失敗：{e}")

# 【右側：圖表區】 (完全保留原本的顏色地圖與 Plotly 配置)
def generate_risk_pie_chart_object(findings):
    if not findings:
        return None
        
    df = pd.DataFrame(findings)
    
    # 這裡 100% 保留你原本定義的顏色
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

# 右側顯示區 (維持原樣排版)
with chart_col:
    with st.container(border=True): 
        st.markdown("#### 數據視覺化")
        
        if 'findings' in st.session_state and not st.session_state['findings'].empty:
            current_findings = st.session_state['findings'].to_dict('records')
            fig = generate_risk_pie_chart_object(current_findings)
            if fig:
                st.plotly_chart(fig, use_container_width=True)
            
            st.divider()
            
            # 表格部分 (維持原樣)
            df_display = st.session_state['findings'][['Location', 'Type', 'CodeSnippet', 'FixSuggestion']].copy()    
            df_display.columns = ['位置', '類型', '代碼片段', '修補建議']
            df_display.index = df_display.index + 1
            st.dataframe(df_display, use_container_width=True)
        else:
            st.info("💡 請在左側上傳檔案並點擊「開始掃描」以生成風險圖表。")

        st.divider()
        
        # 下載按鈕 (維持原樣)
        if 'findings' in st.session_state and not st.session_state['findings'].empty:
            current_findings = st.session_state['findings'].to_dict('records')
            # 呼叫從 scanner_base 匯入的報告生成函數
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
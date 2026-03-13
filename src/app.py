import streamlit as st
import pandas as pd
import os
import sys

# Ensure src is in the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from parser import PacketParser
from intel import IntelValidator
from ai_engine import AIEngine
from cache import LocalCache
import plotly.express as px

# Set page config
st.set_page_config(layout="wide", page_title="PacketCopilot | Unified Desk")

# Initialize Cache
cache = LocalCache()

# --- UI Header ---
st.title("🛡️ PacketCopilot: Mission Control")
st.markdown("---")

# --- Sidebar: Configuration & Global Actions ---
with st.sidebar:
    st.header("📂 Data Ingestion")
    uploaded_file = st.file_uploader("Upload PCAP/PCAPNG", type=["pcap", "pcapng"])
    
    st.divider()
    st.header("⚙️ Configuration")
    vt_key = st.text_input("VirusTotal API Key", value="", type="password")
    google_key = st.text_input("Google Gemini API Key", value="", type="password")
    
    selected_model = st.selectbox("Gemini Model", ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"])

    st.divider()
    if st.button("🗑️ Reset Investigation"):
        st.session_state.clear()
        st.rerun()
    
    if st.button("🔥 Clear Local Database"):
        if os.path.exists("data_cache.db"):
            os.remove("data_cache.db")
            st.sidebar.warning("Database deleted. Please restart app.")
            st.session_state.clear()
            st.rerun()

# --- Main Logic ---
if uploaded_file:
    temp_dir = os.path.abspath("temp_uploads")
    if not os.path.exists(temp_dir): os.makedirs(temp_dir)
    
    safe_filename = os.path.basename(uploaded_file.name)
    pcap_temp_path = os.path.join(temp_dir, safe_filename)
    with open(pcap_temp_path, "wb") as f: f.write(uploaded_file.getbuffer())
    
    # 1. Loading/Parsing Logic
    if "session_data" not in st.session_state or st.session_state.get("last_uploaded") != safe_filename:
        cached_session = cache.get_session(pcap_temp_path)
        if cached_session:
            st.session_state.session_data = cached_session
            st.sidebar.success("✨ Analysis loaded from cache.")
        else:
            with st.status("🕵️‍♂️ Analyzing Attack Patterns...") as status:
                # A. Reputation Check First (to feed the parser heuristics)
                parser = PacketParser()
                # Basic run to get IPs
                initial_results = parser.extract_iocs(pcap_temp_path)
                validator = IntelValidator(api_key=vt_key if vt_key else None)
                
                reputations = {}
                triage_data = []
                
                all_indicators = []
                for ip in initial_results['unique_ips']: all_indicators.append((ip, True))
                for dns in initial_results['dns_queries']: all_indicators.append((dns, False))

                total_ioc = len(all_indicators)
                for i, (indicator, is_ip) in enumerate(all_indicators):
                    status.update(label=f"🔍 Scanning indicator {i+1}/{total_ioc}: {indicator} (API Rate Limiting Active...)")
                    
                    if is_ip:
                        report = validator.get_ip_report(indicator)
                    else:
                        report = validator.get_domain_report(indicator)
                    
                    whois_data = validator.get_whois_data(indicator, is_ip=is_ip)
                    reputations[indicator] = report['status']
                    mal_count = report.get('malicious_count', 0)
                    total_eng = report.get('total_engines', 0)
                    
                    triage_data.append({
                        "Indicator": indicator, 
                        "Type": "IP" if is_ip else "DNS", 
                        "VT Score": f"{mal_count}/{total_eng}", 
                        "Status": report['status'],
                        "Provider": whois_data['Provider'],
                        "WHOIS Link": whois_data['Link']
                    })

                # B. Forensic Heuristics Run
                status.update(label="🧪 Running Forensic Heuristics...")
                results = parser.extract_iocs(pcap_temp_path, ip_reputations=reputations)
                
                st.session_state.session_data = {
                    "triage_data": triage_data,
                    "ip_counts": results.get('ip_counts', {}),
                    "streams": results.get('streams', {}),
                    "timeline": results.get('timeline', []),
                    "unique_ips": results.get('unique_ips', [])
                }
                cache.save_session(pcap_temp_path, triage_data, results['ip_counts'], results['streams'], results['timeline'], results['unique_ips'])
                status.update(label="Analysis complete!", state="complete")
        st.session_state.last_uploaded = safe_filename

    # --- UNIFIED DASHBOARD LAYOUT ---
    data = st.session_state.session_data
    
    # Row 1: High-Level Metrics
    m1, m2, m3 = st.columns(3)
    m1.metric("Total IOCs", len(data['triage_data']))
    m2.metric("Critical Threats", len([x for x in data['triage_data'] if x['Status'] == 'Malicious']))
    # Safety fallback for Risk field
    m3.metric("High-Risk Packets", len([x for x in data['timeline'] if "LOW" not in x.get('Risk', '🟢 LOW')]))
    
    # Display full copyable SHA-256 hash
    full_hash = cache._generate_file_hash(pcap_temp_path)
    st.caption(f"📄 **File:** `{safe_filename}`")
    st.code(full_hash, language="text")

    st.markdown("---")

    # Row 2: Split Investigation Pane
    col_nav, col_desk = st.columns([1, 2])

    with col_nav:
        st.subheader("🚩 1. Triage Navigator")
        df_triage = pd.DataFrame(data['triage_data'])
        
        # Search Box
        search_query = st.text_input("🔍 Filter Indicators", placeholder="IP or Domain...")
        if search_query:
            df_triage = df_triage[df_triage['Indicator'].str.contains(search_query, case=False)]

        event = st.dataframe(
            df_triage,
            column_config={
                "Status": st.column_config.TextColumn("Verdict"),
                "Provider": st.column_config.TextColumn("Registrar/ASN"),
                "WHOIS Link": st.column_config.LinkColumn("Full Record")
            },
            use_container_width=True,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
            key="nav_table"
        )
        
        with st.expander("📊 Traffic Distribution", expanded=False):
            if data['ip_counts']:
                df_counts = pd.DataFrame(list(data['ip_counts'].items()), columns=['IP', 'Pkts']).sort_values('Pkts', ascending=False).head(5)
                fig = px.bar(df_counts, x='IP', y='Pkts', height=250, color_discrete_sequence=['#ff4b4b'])
                st.plotly_chart(fig, use_container_width=True)

    with col_desk:
        if event and event.selection.rows:
            selected_idx = event.selection.rows[0]
            selected_indicator = df_triage.iloc[selected_idx]["Indicator"]
            selected_provider = df_triage.iloc[selected_idx].get("Provider", "Unknown")
            selected_whois_link = df_triage.iloc[selected_idx].get("WHOIS Link", "#")
            
            st.subheader(f"🛠️ Investigation Desk: {selected_indicator}")
            st.markdown(f"**Provider/Registrar:** `{selected_provider}` | [🌐 View Full WHOIS Record]({selected_whois_link})")
            
            # Sub-Pane: Contextual Attack Flow
            st.markdown("##### 🕒 Attack Flow Timeline")
            
            # Global Filter for Harmful traffic
            only_harmful = st.checkbox("🔥 Show only harmful payloads/files", value=False)
            
            df_tl = pd.DataFrame(data['timeline'])
            
            # Safety: Ensure 'Risk' column exists in DataFrame
            if 'Risk' not in df_tl.columns:
                df_tl['Risk'] = "🟢 LOW"

            # Filter logic: Selected IP AND (optionally) Harmful only
            mask = (df_tl['Source'] == selected_indicator) | (df_tl['Destination'] == selected_indicator)
            if only_harmful:
                mask = mask & (df_tl['Risk'].str.contains("HIGH|CRITICAL", case=False))
            
            df_filtered_tl = df_tl[mask]
            
            if not df_filtered_tl.empty:
                # Color code the timeline by Risk
                def color_risk(row):
                    if "CRITICAL" in row.Risk: return ['background-color: #ff4b4b'] * len(row)
                    if "HIGH" in row.Risk: return ['background-color: #ffbd45'] * len(row)
                    return [''] * len(row)

                # Ensure Date/Time columns exist for old cache data
                for col in ["Date", "Time", "SrcPort", "DstPort"]:
                    if col not in df_filtered_tl.columns:
                        df_filtered_tl[col] = ""

                flow_event = st.dataframe(
                    df_filtered_tl[["Date", "Time", "Source", "SrcPort", "Destination", "DstPort", "Protocol", "Risk", "Info"]],
                    use_container_width=True,
                    hide_index=True,
                    on_select="rerun",
                    selection_mode="single-row",
                    key="flow_table"
                )
                
                if flow_event and flow_event.selection.rows:
                    f_idx = flow_event.selection.rows[0]
                    actual_payload = df_filtered_tl.iloc[f_idx]["Payload"]
                    risk_info = df_filtered_tl.iloc[f_idx]["Risk"]
                    
                    st.markdown(f"##### 🔍 Forensic Evidence | Risk: {risk_info}")
                    c_evidence, c_ai = st.columns([1, 1])
                    
                    with c_evidence:
                        st.text_area("Packet Payload", value=actual_payload if actual_payload else "No application layer data.", height=250)
                        if st.button("🚀 Explain with PacketCopilot", type="primary"):
                            st.session_state.explain_requested = True
                            st.session_state.selected_payload = actual_payload
                    
                    with c_ai:
                        if "messages" not in st.session_state:
                            st.session_state.messages = [{"role": "assistant", "content": "Evidence selected. Click 'Explain' to translate."}]
                        
                        for m in st.session_state.messages:
                            with st.chat_message(m["role"]): st.markdown(m["content"])

                        if st.session_state.get("explain_requested"):
                            # Check cache for this specific payload
                            cached_res = cache.get_explanation(st.session_state.selected_payload)
                            if cached_res:
                                st.session_state.messages.append({"role": "assistant", "content": f"**Analysis (Cached):** {cached_res}"})
                            else:
                                ai = AIEngine(api_key=google_key, model_name=selected_model)
                                with st.chat_message("assistant"):
                                    with st.spinner("Analyzing..."):
                                        # Pass the risk_info (signature match) to the AI
                                        res = ai.translate_payload(
                                            selected_indicator, 
                                            st.session_state.selected_payload,
                                            signature_match=risk_info
                                        )
                                    st.session_state.messages.append({"role": "assistant", "content": f"**Evidence Analysis:** {res}"})
                                    if "Error" not in res: cache.save_explanation(st.session_state.selected_payload, res)
                            del st.session_state.explain_requested
                            st.rerun()
            else:
                st.info("No timeline events matched your filters for this indicator.")
        else:
            st.info("👈 Select an indicator from the Triage Navigator to begin.")

else:
    st.info("Please upload a PCAP file to activate the SOC Mission Control desk.")

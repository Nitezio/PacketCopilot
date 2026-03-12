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
st.set_page_config(layout="wide", page_title="PacketCopilot")

# Initialize Cache
cache = LocalCache()

# --- UI Header ---
st.title("🛡️ PacketCopilot Dashboard")
st.subheader("AI-Augmented PCAP Triage & Analysis")

# --- Sidebar ---
with st.sidebar:
    st.header("File Upload")
    uploaded_file = st.file_uploader("Drag and drop a .pcap file", type=["pcap", "pcapng"])
    
    st.divider()
    st.header("Settings")
    vt_key = st.text_input(
        "VirusTotal API Key (Optional)", 
        value="", 
        type="password"
    )
    google_key = st.text_input(
        "Google Gemini API Key (Optional)", 
        value="", 
        type="password"
    )
    
    # Model Selection Dropdown
    model_options = [
        "gemini-2.0-flash", 
        "gemini-1.5-flash", 
        "gemini-1.5-pro", 
        "gemini-2.0-flash-lite-preview-02-05",
        "Custom"
    ]
    selected_option = st.selectbox("Select Gemini Model", options=model_options, index=0)
    if selected_option == "Custom":
        selected_model = st.text_input("Enter Custom Model Name", value="gemini-3-flash-preview")
    else:
        selected_model = selected_option

    st.divider()
    if st.button("🗑️ Clear Chat History"):
        st.session_state.messages = [
            {"role": "assistant", "content": "Chat history cleared. How can I help you analyze the traffic?"}
        ]
        st.rerun()
    
# --- Main Logic ---
if uploaded_file:
    # 1. Save file locally for processing
    # Use a more reliable absolute path
    temp_dir = os.path.abspath("temp_uploads")
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
        
    # Security: Use basename to prevent path traversal
    safe_filename = os.path.basename(uploaded_file.name)
    pcap_temp_path = os.path.join(temp_dir, safe_filename)
    with open(pcap_temp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    
    st.sidebar.success(f"File ready: {safe_filename}")

    # 2. Parse PCAP
    if "iocs" not in st.session_state or st.session_state.get("last_uploaded") != safe_filename:
        with st.status("Parsing Packet Capture...") as status:
            parser = PacketParser()
            st.session_state.iocs = parser.extract_iocs(pcap_temp_path)
            st.session_state.last_uploaded = safe_filename
            status.update(label="Parsing complete!", state="complete")

    iocs = st.session_state.iocs

    if iocs:
        # 3. Validate Threat Intel (Triage Matrix)
        st.header("📊 Top Pane: Triage Matrix")
        
        validator = IntelValidator(api_key=vt_key if vt_key else None)
        
        triage_data = []
        full_vt_reports = {} # Cache full reports for the AI

        for ip in iocs['unique_ips']:
            report = validator.get_ip_report(ip)
            triage_data.append({
                "Indicator": ip,
                "Type": "IP Address",
                "VT Score": f"{report['malicious_count']}/{report['total_engines']}",
                "Status": report['status']
            })
            full_vt_reports[ip] = report.get('full_report')
            
        for dns in iocs['dns_queries']:
            report = validator.get_domain_report(dns)
            triage_data.append({
                "Indicator": dns,
                "Type": "DNS Query",
                "VT Score": f"{report['malicious_count']}/{report['total_engines']}",
                "Status": report['status']
            })
            full_vt_reports[dns] = report.get('full_report')

        # Explicitly define columns to prevent KeyError if data is empty
        columns = ["Indicator", "Type", "VT Score", "Status"]
        df_triage = pd.DataFrame(triage_data, columns=columns)
        
        if not df_triage.empty:
            # --- Visualization Pane (Top Talkers) ---
            st.subheader("📊 Network Traffic Overview")
            ip_counts = iocs.get('ip_counts', {})
            if ip_counts:
                df_counts = pd.DataFrame(list(ip_counts.items()), columns=['IP', 'Packets'])
                df_counts = df_counts.sort_values('Packets', ascending=False).head(10)
                
                fig = px.bar(
                    df_counts, 
                    x='IP', 
                    y='Packets', 
                    title="Top 10 Talker IPs",
                    color='Packets',
                    color_continuous_scale='Reds'
                )
                st.plotly_chart(fig, use_container_width=True)

            # Use modern column_config for a professional look
            st.write("### Indicator Status")
            event = st.dataframe(
                df_triage,
                column_config={
                    "Status": st.column_config.TextColumn(
                        "Status",
                        help="Threat reputation from VirusTotal",
                    ),
                    "VT Score": st.column_config.TextColumn("Engines Flagged"),
                },
                use_container_width=True,
                hide_index=True,
                on_select="rerun",
                selection_mode="single-row"
            )

            # 4. Suspicious Streams (Middle Pane)
            st.divider()
            st.header("🔍 Middle Pane: Suspicious Streams")
            
            # Check if a row is selected
            if event and event.selection.rows:
                selected_index = event.selection.rows[0]
                selected_indicator = df_triage.iloc[selected_index]["Indicator"]
                st.subheader(f"Streams for: {selected_indicator}")
                
                # Show the raw payload slice in the middle pane
                payload_slice = iocs['payloads'].get(selected_indicator, "No application layer payload detected.")
                st.text_area("Packet Payload (1KB Slice)", value=payload_slice, height=150)
                
                # Button for the AI Copilot
                if st.button("Explain Selected Stream", type="primary"):
                    st.session_state.explain_requested = True
                    st.session_state.selected_indicator = selected_indicator
                    st.session_state.current_payload = payload_slice
                    st.session_state.current_vt_report = full_vt_reports.get(selected_indicator)
            else:
                st.info("Select a row from the Triage Matrix above to investigate its network streams.")
        else:
            st.warning("No IOCs (IPs or DNS queries) extracted from this PCAP.")

        # 5. AI Copilot (Side/Bottom Pane)
        st.divider()
        st.header("🤖 AI Copilot")
        
        # Initialize chat history
        if "messages" not in st.session_state:
            st.session_state.messages = [
                {"role": "assistant", "content": "I have finished the triage. Select a suspicious indicator above and click 'Explain' or ask me a question below."}
            ]

        # Display chat history
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])

        # Explain Stream Workflow
        if "explain_requested" in st.session_state and st.session_state.explain_requested:
            # 1. Check Cache First
            cached_explanation = cache.get_explanation(st.session_state.current_payload)
            
            if cached_explanation:
                st.session_state.messages.append({
                    "role": "assistant", 
                    "content": f"**Analysis for {st.session_state.selected_indicator} (Cached):** {cached_explanation}"
                })
            else:
                # 2. Call AI Engine
                ai_engine = AIEngine(api_key=google_key if google_key else None, model_name=selected_model)
                with st.chat_message("assistant"):
                    st.write(f"Analyzing the traffic for **{st.session_state.selected_indicator}**...")
                    with st.spinner("AI is thinking..."):
                        explanation = ai_engine.translate_payload(
                            st.session_state.selected_indicator, 
                            st.session_state.current_payload,
                            vt_report=st.session_state.get("current_vt_report")
                        )
                    st.session_state.messages.append({
                        "role": "assistant", 
                        "content": f"**Analysis for {st.session_state.selected_indicator}:** {explanation}"
                    })
                    # 3. Save to Cache
                    cache.save_explanation(st.session_state.current_payload, explanation)
            
            # Clear request to prevent re-triggering on rerun
            del st.session_state.explain_requested
            st.rerun()

        # Persistent Chat Input
        if prompt := st.chat_input("Ask a follow-up question (e.g., 'How do I block this?')"):
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)

            ai_engine = AIEngine(api_key=google_key if google_key else None, model_name=selected_model)
            with st.chat_message("assistant"):
                with st.spinner("Responding..."):
                    response = ai_engine.chat(
                        indicator=st.session_state.get("selected_indicator", "General"),
                        vt_report=st.session_state.get("current_vt_report"),
                        user_query=prompt
                    )
                st.markdown(response)
                st.session_state.messages.append({"role": "assistant", "content": response})

else:
    st.info("Please upload a PCAP file from the sidebar to begin analysis.")

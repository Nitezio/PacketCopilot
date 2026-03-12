# 🛡️ PacketCopilot

**PacketCopilot** is an advanced, AI-augmented network forensics dashboard designed to modernize and automate the triage of Packet Capture (PCAP) files. By integrating deterministic network parsing with Large Language Model (LLM) intelligence, PacketCopilot transforms raw, high-volume network traffic into actionable security narratives.

---

## 🎯 Purpose & Problem Statement

Modern Security Operations Centers (SOCs) face a critical challenge: **Alert Fatigue**. Manual PCAP analysis is a time-intensive process that requires deep protocol knowledge and the ability to distinguish malicious intent within thousands of technical frames. 

PacketCopilot is engineered to solve these challenges by:
*   **Accelerating Triage**: Automating the extraction and reputation-checking of Indicators of Compromise (IOCs).
*   **Bridging the Skills Gap**: Using AI to translate complex, low-level packet payloads (e.g., PowerShell scripts, SQL injections, or C2 handshakes) into clear, plain-English summaries.
*   **Optimizing Investigation Workflows**: Providing a high-performance, local web interface that keeps sensitive data within the organization's control while leveraging global threat intelligence.

---

## 🚀 Key Features

*   **Deterministic Triage Matrix**: Instant extraction of IP addresses, DNS queries, and application-layer metadata using a stabilized TShark backend.
*   **Threat Intelligence Fusion**: Real-time integration with the **VirusTotal API** for automated reputation scoring of all detected indicators.
*   **AI-Driven Contextual Analysis**: Leverages **Google Gemini** to interpret truncated packet payloads, cross-referencing them with threat reports to provide deep forensic insights.
*   **Visual Network Topography**: Interactive Plotly visualizations identifying "Top Talker" IPs and traffic volume trends.
*   **Token-Efficient "Data Funnel"**: Implements surgical 1KB payload truncation to ensure rapid AI responses and minimize API consumption.
*   **Local Session Caching**: Utilizes a persistent SQLite backend to cache previous analyses, enabling instant re-loading of PCAP reports with zero redundant API costs.

---

## 🛠️ System Architecture

1.  **The Data Funnel**: Employs a robust `tshark` subprocess engine to mathematically strip protocol noise and isolate high-entropy Layer 7 data.
2.  **Reputation Engine**: An asynchronous validator that queries global threat feeds for every extracted indicator.
3.  **AI Forensic Engine**: A LangChain-powered orchestration layer that grounds LLM responses in local packet data and real-time threat intelligence.

---

## 📦 Installation & Setup

### 1. Prerequisites
*   **Python 3.10+**
*   **Wireshark/TShark**: Ensure TShark is installed on your system.
    *   *Windows*: Usually located at `C:\Program Files\Wireshark\tshark.exe`.
    *   *Linux*: `sudo apt install tshark`

### 2. Set Up Environment
```bash
# Clone and enter directory
git clone https://github.com/Nitezio/PacketCopilot.git
cd PacketCopilot

# Create and activate virtual environment
python -m venv venv
# Windows: .\venv\Scripts\activate | Linux: source venv/bin/activate

# Install verified dependencies
pip install -r requirements.txt
```

---

## 🚦 Usage

1.  **Launch the Dashboard**:
    ```bash
    streamlit run src/app.py
    ```
2.  **Authentication**: Enter your **VirusTotal** and **Google Gemini** API keys in the sidebar settings.
3.  **Analyze Traffic**: 
    *   Upload a `.pcap` or `.pcapng` file.
    *   Select a suspicious indicator from the Triage Matrix.
    *   Review the payload in the Middle Pane and click **"Explain Selected Stream"** for an AI-generated forensic summary.

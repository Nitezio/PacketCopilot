# 🛡️ PacketCopilot

**PacketCopilot** is an advanced, AI-augmented network forensics dashboard designed to modernize and automate the triage of Packet Capture (PCAP) files. By integrating deterministic network parsing with Large Language Model (LLM) intelligence, PacketCopilot transforms raw, high-volume network traffic into actionable security narratives.

---

## 🎯 Purpose & Problem Statement

Modern Security Operations Centers (SOCs) face a critical challenge: **Alert Fatigue**. Manual PCAP analysis is a time-intensive process that requires deep protocol knowledge and the ability to distinguish malicious intent within thousands of technical frames. 

PacketCopilot is engineered to solve these challenges by:
*   **Accelerating Triage**: Automating the extraction and reputation-checking of Indicators of Compromise (IOCs).
*   **Heuristic Risk Detection**: Automatically flagging "Forensic Red Flags" (e.g., MZ headers, PowerShell drops, or suspicious encoded strings).
*   **Bridging the Skills Gap**: Using AI to translate complex, low-level packet payloads into clear, plain-English summaries.
*   **Optimizing Investigation Workflows**: Providing a "Single Pane of Glass" interface that keeps sensitive data within the organization's control.

---

## 🚀 Key Features

*   **Unified Mission Control**: A side-by-side investigation desk combining Triage, Timeline, and Evidence analysis.
*   **Forensic Heuristic Engine**: Real-time payload scanning that tags events with Risk Levels (CRITICAL, HIGH, MEDIUM, LOW).
*   **Threat Intelligence Fusion**: Integrated **VirusTotal API** scoring and **WHOIS/ASN** attribution for IPs and Domains.
*   **Chronological Attack Flow**: A detailed timeline showing real-world Date, Time, and Port mappings for every significant event.
*   **Self-Aware Rate Limiting**: Dynamically detects your VirusTotal API tier and adjusts request speeds to prevent throttling.
*   **Persistent AI Copilot**: A context-aware assistant that grounds responses in local packet data and real-time threat reports.
*   **Local Session Caching**: Persistent SQLite backend to cache previous analyses, enabling instant re-loading of PCAP reports.

---

## 🛠️ System Architecture

1.  **The Data Funnel**: Employs a robust `tshark` subprocess engine to mathematically strip protocol noise and isolate high-entropy Layer 7 data.
2.  **Reputation & WHOIS Engine**: An asynchronous validator that queries global threat feeds and ownership records for every extracted indicator.
3.  **AI Forensic Engine**: A LangChain-powered orchestration layer that grounds LLM responses in local packet data.

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
    *   Select a suspicious indicator from the Triage Navigator.
    *   Filter the **Attack Flow Timeline** by "Harmful Payloads" to isolate malicious events.
    *   Review the payload and click **"🚀 Explain with PacketCopilot"** for a deep forensic summary.

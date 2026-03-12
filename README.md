# 🛡️ PacketCopilot

**PacketCopilot** is a professional-grade, AI-augmented network forensics dashboard designed to automate the triage and analysis of Packet Capture (PCAP) files. By merging deterministic network parsing with Large Language Model (LLM) intelligence, PacketCopilot transforms complex network data into actionable security narratives.

---

## 🎯 Purpose & Problem Statement

Modern Security Operations Centers (SOCs) are often overwhelmed by **Alert Fatigue**. Manual PCAP analysis is time-consuming and requires specialized protocol knowledge. 

PacketCopilot solves these challenges by:
*   **Automated Evidence Orchestration**: Instant extraction and reputation-checking of Indicators of Compromise (IOCs).
*   **Forensic Narrative Generation**: Translating technical payloads (VBScripts, PowerShell, SQLi) into plain-English summaries using AI.
*   **Workflow Optimization**: Providing a "Single Pane of Glass" investigation desk that keeps sensitive forensic data local and secure.

---

## 🚀 Key Features

*   **Unified Mission Control**: A side-by-side investigation interface combining Triage, Chronological Flow, and Evidence Analysis.
*   **Forensic Heuristic Engine**: Real-time payload scanning that tags events with Risk Levels (CRITICAL, HIGH, MEDIUM, LOW) based on executable headers and script patterns.
*   **Threat Intelligence Fusion**: Integrated **VirusTotal API** scoring and **WHOIS/ASN** attribution for immediate provider identification.
*   **Chronological Attack Flow**: A detailed timeline featuring absolute **Date**, **Time**, and **Port** mappings for every significant network event.
*   **Self-Aware Rate Limiting**: Dynamically detects VirusTotal API tiers (Free/Premium) and adjusts request speeds to ensure continuous operation.
*   **Local Session Caching**: A persistent SQLite backend that uses **File Integrity Hashing (SHA-256)** to cache and instantly reload previous analyses with zero redundant API costs.
*   **Integrity Verification**: Generates and displays full copyable SHA-256 hashes for every analyzed PCAP to support forensic chain-of-custody.

---

## 🛠️ System Architecture

1.  **Extraction Layer**: Uses a stabilized `tshark` subprocess engine to mathematically isolate high-entropy Layer 7 data.
2.  **Intel Layer**: An asynchronous validator providing real-time reputation scoring and infrastructure ownership data.
3.  **AI Forensic Engine**: A LangChain-powered orchestration layer that grounds LLM responses in local packet data and threat intelligence.

---

## 📦 Installation & Setup

### 1. Prerequisites
*   **Python 3.10+**
*   **Wireshark/TShark**: Ensure TShark is installed on your system.
    *   *Windows*: Usually at `C:\Program Files\Wireshark\tshark.exe`.
    *   *Linux*: `sudo apt install tshark`

### 2. Set Up Environment
```bash
# Clone the repository
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
3.  **Investigate**: 
    *   Upload a `.pcap` or `.pcapng` file.
    *   Identify high-risk indicators in the **Triage Navigator**.
    *   Trace the attack flow in the **Timeline**, using the "Harmful" filter to isolate malicious payloads.
    *   Review specific evidence and click **"🚀 Explain with PacketCopilot"** for a deep forensic summary.

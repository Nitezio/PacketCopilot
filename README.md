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
*   **Forensic Heuristic Engine**: Real-time payload scanning that tags events with Risk Levels (CRITICAL, HIGH, MEDIUM, LOW).
*   **Threat Intelligence Fusion**: Integrated **VirusTotal API** scoring and **WHOIS/ASN** attribution.
*   **Chronological Attack Flow**: A detailed timeline featuring absolute Date, Time, and Port mappings.
*   **Local Session Caching**: A persistent SQLite backend that uses **File Integrity Hashing (SHA-256)** to reload previous analyses instantly.

---

## 🛡️ Detection Engine (Triple-Layer Risk Scoring)

PacketCopilot employs a multi-layered, deterministic risk engine to ensure professional-grade accuracy in threat identification:

*   **Layer 1: YARA Malware Engine**: Scans application-layer data against a pre-compiled master binary containing hundreds of community-verified YARA rules (e.g., AsyncRat, Cobalt Strike).
*   **Layer 2: ET Open Signature Engine**: Leverages over **5,000 optimized regex signatures** derived from the **Emerging Threats Open** ruleset to detect SQLi, Log4j, and C2 behaviors.
*   **Layer 3: Forensic Heuristics**: A protocol-aware fallback layer that identifies "Forensic Red Flags" such as unauthorized PowerShell drops and binary obfuscation.

---

## ⚙️ Engineering & Optimization Deep-Dive

To handle thousands of rules and massive PCAP files on local hardware without performance degradation, PacketCopilot utilizes several advanced engineering optimizations:

### 1. Binary Pre-Compilation (Loading Efficiency)
Instead of parsing thousands of lines of YARA text rules during runtime, the system utilizes a **Smart Compiler** (`src/compiler.py`). This module "bakes" the entire community ruleset into a single, master binary image (`.yarc`). 
*   **Impact**: Rule loading is reduced from seconds to **milliseconds**, and memory overhead is minimized by storing optimized bytecodes rather than raw strings.

### 2. Contextual Gating & Registry Dispatcher (CPU Efficiency)
PacketCopilot implements a **Protocol-Aware Registry**. Every packet is first identified by its protocol (e.g., DNS, HTTP, TLS) before the risk engine is engaged.
*   **Logic**: The engine only executes the **Global Rules** + **Protocol-Specific Rules** for each packet.
*   **Impact**: By "Gating" the signatures, the engine skips ~90% of irrelevant rules for every packet, ensuring the dashboard stays responsive even during high-volume traffic analysis.

### 3. The "Data Funnel" (Token Economy)
To optimize Large Language Model (LLM) performance and minimize API costs, PacketCopilot enforces a strict **Contextual Truncation** rule.
*   **Mechanism**: Every packet payload is surgically sliced to its first **1KB**, where high-entropy data (headers, commands, file magic) typically resides. 
*   **Impact**: This reduces the data sent to Gemini by 100x-1000x for large file transfers while preserving the critical forensic evidence needed for accurate AI translation.

### 4. Integrity-Based Session Caching (Zero-Redundancy)
The system calculates a unique **SHA-256 Hash** for every uploaded PCAP file. 
*   **Mechanism**: All triage results, top talker metrics, and attack timelines are stored in a local **SQLite database** indexed by this file hash. 
*   **Impact**: Re-investigating a previously analyzed file is instantaneous and costs **zero API tokens**, as the system retrieves the entire "Mission Control" state from the local cache.

---

## 🛠️ System Architecture

1.  **Extraction Layer**: Uses a stabilized `tshark` subprocess engine to mathematically isolate high-entropy Layer 7 data.
2.  **Intel Layer**: An asynchronous validator providing real-time reputation scoring and infrastructure ownership data.
3.  **AI Forensic Engine**: A LangChain-powered orchestration layer that grounds LLM responses in local packet data and signature matches.

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

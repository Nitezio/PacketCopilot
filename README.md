# 🛡️ PacketCopilot

**PacketCopilot** is an AI-augmented network forensics dashboard designed to automate the triage and analysis of Packet Capture (PCAP) files. It bridges the gap between technical network data and actionable security insights by combining deterministic parsing with Large Language Model (LLM) intelligence.

---

## 🚀 Key Features

*   **Deterministic Triage Matrix**: Automatically extracts Indicators of Compromise (IOCs) such as IP addresses and DNS queries.
*   **Threat Intel Integration**: Real-time reputation checks using the **VirusTotal API**.
*   **AI-Driven Translation**: Uses **Google Gemini** to translate technical packet payloads (HTTP, PowerShell, etc.) into plain-English summaries.
*   **Wireshark-Inspired UI**: A clean, 3-pane layout for seamless investigation (Triage -> Stream View -> AI Analysis).
*   **Token Economy**: Strictly enforces a 1KB payload truncation rule to optimize AI processing speed and costs.

---

## 🛠️ System Architecture

1.  **The Data Funnel**: Uses `tshark` to mathematically strip Layer 2-4 noise and extract high-value Layer 7 application data.
2.  **Reputation Engine**: Cross-references every extracted indicator against global threat feeds.
3.  **AI Copilot**: A context-aware chatbot grounded in local packet data and threat intelligence reports.

---

## 📦 Installation & Setup

### 1. Prerequisites
*   **Python 3.10+**
*   **Wireshark/TShark**: Ensure TShark is installed on your system.
    *   *Windows*: Usually located at `C:\Program Files\Wireshark\tshark.exe`.
    *   *Linux*: `sudo apt install tshark`

### 2. Clone the Repository
```bash
git clone https://github.com/Nitezio/PacketCopilot.git
cd PacketCopilot
```

### 3. Set Up Virtual Environment
```bash
python -m venv venv
# Windows
.\venv\Scripts\activate
# Linux/Mac
source venv/bin/activate
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🚦 Usage

1.  **Start the Application**:
    ```bash
    streamlit run src/app.py
    ```
2.  **Configure API Keys**: Open the dashboard in your browser (`http://localhost:8501`) and enter your **VirusTotal** and **Google Gemini** API keys in the sidebar.
3.  **Upload a PCAP**: Drag and drop any `.pcap` or `.pcapng` file.
4.  **Analyze**: Select a malicious indicator from the Triage Matrix, view its payload, and click **"Explain Selected Stream"** to receive an AI analysis.

---

## ⚖️ License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🎓 Author
Developed as part of a Final Year Project (FYP) for automated network forensics and threat translation.

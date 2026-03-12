import os
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

class AIEngine:
    def __init__(self, api_key=None, model_name="gemini-3-flash-preview"):
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        self.model = None
        if self.api_key:
            self.model = ChatGoogleGenerativeAI(
                model=model_name,
                google_api_key=self.api_key,
                temperature=0.2
            )

    def translate_payload(self, indicator, payload, vt_report=None):
        """
        Translates technical packet payload into plain English, 
        incorporating Threat Intel data if available.
        """
        if not self.model:
            # Mock AI translation for testing
            return f"Mock Analysis for {indicator}: This traffic appears to be a standard encrypted handshake. No malicious patterns detected in the first 1KB."

        system_prompt = """
        You are a Senior Network Forensic Analyst (PacketCopilot). 
        Your task is to analyze raw network packet data and explain it in plain English.
        
        Guidelines:
        - Be concise (max 3-4 sentences).
        - Identify the protocol if possible.
        - Cross-reference with VirusTotal data.
        - SPECIAL FOCUS: Look for script-based persistence (e.g., VBS, PowerShell). 
        - Identify any LOCAL FILE NAMES or PATHS being created or dropped by the script (e.g., filenames like 'Conted.vbs').
        - Decode malicious intent like C2 beaconing or credential theft.
        """
        
        human_template = """
        Analyze this indicator: {indicator}
        
        Packet Payload Segment:
        {payload}
        
        Threat Intelligence Context (VirusTotal):
        {vt_context}
        """
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("human", human_template)
        ])
        
        chain = prompt | self.model | StrOutputParser()
        
        vt_context = str(vt_report) if vt_report else "No threat intelligence available for this indicator."
        
        try:
            return chain.invoke({
                "indicator": indicator, 
                "payload": payload,
                "vt_context": vt_context
            })
        except Exception as e:
            err_msg = str(e)
            if "429" in err_msg or "RESOURCE_EXHAUSTED" in err_msg:
                return "⚠️ Quota Exceeded: Your Google Gemini API free tier limit has been reached. Please wait a few minutes or switch to a different model/API key."
            if "404" in err_msg or "NOT_FOUND" in err_msg:
                return f"❌ Model Not Found: The model name you entered is incorrect or not available for your API key. (Error: {err_msg})"
            return f"AI Error: {err_msg}"

    def chat(self, indicator, vt_report, user_query, chat_history=[]):
        """
        Handles persistent chat interaction grounded in the current context.
        """
        if not self.model:
            return f"Mock Response: To block {indicator}, you should apply a firewall rule on your perimeter gateway."

        system_prompt = """
        You are PacketCopilot, an expert AI Security Assistant.
        You are helping an analyst investigate a specific network indicator.
        
        Context:
        - Indicator: {indicator}
        - Threat Intel: {vt_context}
        
        Answer the user's question concisely and professionally. 
        If they ask for remediation, provide specific commands (e.g., iptables, netsh).
        """
        
        # Format history for the prompt if needed, but for now we'll use a simple template
        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("human", "{query}")
        ])
        
        chain = prompt | self.model | StrOutputParser()
        vt_context = str(vt_report) if vt_report else "None"
        
        try:
            return chain.invoke({
                "indicator": indicator,
                "vt_context": vt_context,
                "query": user_query
            })
        except Exception as e:
            return f"Chat Error: {str(e)}"

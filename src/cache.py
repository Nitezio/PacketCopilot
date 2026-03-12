import sqlite3
import hashlib
import os

class LocalCache:
    def __init__(self, db_path="data_cache.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initializes the SQLite database and cache tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # Individual payload translations
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ai_cache (
                payload_hash TEXT PRIMARY KEY,
                explanation TEXT
            )
        ''')
        # Full PCAP session details
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS session_cache (
                pcap_hash TEXT PRIMARY KEY,
                triage_data TEXT,
                ip_counts TEXT,
                streams TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def get_session(self, pcap_path):
        """Retrieves a full cached session based on PCAP file hash."""
        import json
        pcap_hash = self._generate_file_hash(pcap_path)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT triage_data, ip_counts, streams FROM session_cache WHERE pcap_hash = ?', (pcap_hash,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                "triage_data": json.loads(row[0]),
                "ip_counts": json.loads(row[1]),
                "streams": json.loads(row[2])
            }
        return None

    def save_session(self, pcap_path, triage_data, ip_counts, streams):
        """Saves a full analysis session to the cache."""
        import json
        pcap_hash = self._generate_file_hash(pcap_path)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO session_cache (pcap_hash, triage_data, ip_counts, streams) 
            VALUES (?, ?, ?, ?)
        ''', (pcap_hash, json.dumps(triage_data), json.dumps(ip_counts), json.dumps(streams)))
        conn.commit()
        conn.close()

    def _generate_file_hash(self, file_path):
        """Generates a SHA-256 hash for a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _generate_hash(self, text):
        """Generates a SHA-256 hash for a given text payload."""
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    def get_explanation(self, payload):
        """Retrieves a cached explanation if it exists."""
        if not payload:
            return None
            
        payload_hash = self._generate_hash(payload)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT explanation FROM ai_cache WHERE payload_hash = ?', (payload_hash,))
        row = cursor.fetchone()
        conn.close()
        
        return row[0] if row else None

    def save_explanation(self, payload, explanation):
        """Saves a new explanation to the cache."""
        if not payload or not explanation:
            return
            
        payload_hash = self._generate_hash(payload)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('INSERT OR REPLACE INTO ai_cache (payload_hash, explanation) VALUES (?, ?)', 
                       (payload_hash, explanation))
        conn.commit()
        conn.close()

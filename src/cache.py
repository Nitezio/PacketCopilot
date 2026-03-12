import sqlite3
import hashlib
import os
import json

class LocalCache:
    def __init__(self, db_path="data_cache.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initializes the SQLite database and cache tables with robust migration."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 1. Ensure ai_cache exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ai_cache (
                payload_hash TEXT PRIMARY KEY,
                explanation TEXT
            )
        ''')
        
        # 2. Schema Management for session_cache
        # We need 6 columns: pcap_hash, triage_data, ip_counts, streams, timeline, unique_ips
        cursor.execute("PRAGMA table_info(session_cache)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if not columns:
            # Table doesn't exist
            cursor.execute('''
                CREATE TABLE session_cache (
                    pcap_hash TEXT PRIMARY KEY,
                    triage_data TEXT,
                    ip_counts TEXT,
                    streams TEXT,
                    timeline TEXT,
                    unique_ips TEXT
                )
            ''')
        elif len(columns) < 6:
            # Outdated schema - rebuild it
            cursor.execute("DROP TABLE session_cache")
            cursor.execute('''
                CREATE TABLE session_cache (
                    pcap_hash TEXT PRIMARY KEY,
                    triage_data TEXT,
                    ip_counts TEXT,
                    streams TEXT,
                    timeline TEXT,
                    unique_ips TEXT
                )
            ''')
            
        conn.commit()
        conn.close()

    def get_session(self, pcap_path):
        """Retrieves a full cached session based on PCAP file hash."""
        pcap_hash = self._generate_file_hash(pcap_path)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            # Explicitly select all required columns
            cursor.execute('SELECT triage_data, ip_counts, streams, timeline, unique_ips FROM session_cache WHERE pcap_hash = ?', (pcap_hash,))
            row = cursor.fetchone()
            if row:
                return {
                    "triage_data": json.loads(row[0]),
                    "ip_counts": json.loads(row[1]),
                    "streams": json.loads(row[2]),
                    "timeline": json.loads(row[3]),
                    "unique_ips": json.loads(row[4])
                }
        except Exception:
            return None
        finally:
            conn.close()
        return None

    def save_session(self, pcap_path, triage_data, ip_counts, streams, timeline, unique_ips):
        """Saves a full analysis session to the cache."""
        pcap_hash = self._generate_file_hash(pcap_path)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO session_cache (pcap_hash, triage_data, ip_counts, streams, timeline, unique_ips) 
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (pcap_hash, json.dumps(triage_data), json.dumps(ip_counts), json.dumps(streams), json.dumps(timeline), json.dumps(unique_ips)))
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

import sqlite3
import hashlib
import os

class LocalCache:
    def __init__(self, db_path="data_cache.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initializes the SQLite database and cache table."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ai_cache (
                payload_hash TEXT PRIMARY KEY,
                explanation TEXT
            )
        ''')
        conn.commit()
        conn.close()

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

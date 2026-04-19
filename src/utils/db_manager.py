import sqlite3
import os
from datetime import datetime
import pandas as pd

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_DB_PATH = os.path.join(ROOT_DIR, 'audit_log.db')

class AuditDB:
    def __init__(self, db_path=DEFAULT_DB_PATH):
        self.db_path = db_path
        self.init_db()

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def init_db(self):
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    username TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reason TEXT,
                    description TEXT
                )
            ''')
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Error initializing database: {e}")

    def insert_log(self, username, action, status, reason, description):
        """Insert an audit log entry.
        
        Guards against blank/empty username or action to prevent empty rows.
        Returns (True, timestamp) on success, (False, None) on failure or invalid entry.
        """
        # --- Guard: skip blank records ---
        if not username or not str(username).strip():
            print(f"[AuditDB] Skipped insert: username is blank. action='{action}'")
            return False, None
        if not action or not str(action).strip():
            print(f"[AuditDB] Skipped insert: action is blank. username='{username}'")
            return False, None

        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO audit_logs (timestamp, username, action, status, reason, description)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                timestamp,
                str(username).strip(),
                str(action).strip(),
                str(status).strip() if status else "Unknown",
                str(reason).strip() if reason else "",
                str(description).strip() if description else "",
            ))
            conn.commit()
            conn.close()
            return True, timestamp
        except sqlite3.Error as e:
            print(f"Error inserting log: {e}")
            return False, None

    def get_logs(self, from_date=None, to_date=None, username_search="", action_filter="All", status_filter="All"):
        try:
            conn = self.get_connection()
            query = "SELECT timestamp, username, action, status, reason, description FROM audit_logs WHERE 1=1"
            params = []

            if from_date:
                query += " AND timestamp >= ?"
                params.append(f"{from_date} 00:00:00")
            
            if to_date:
                query += " AND timestamp <= ?"
                params.append(f"{to_date} 23:59:59")
                
            if username_search:
                query += " AND username LIKE ?"
                params.append(f"%{username_search}%")
                
            if action_filter and action_filter != "All":
                if action_filter == "Create User":
                    query += " AND action = 'Create User'"
                elif action_filter == "Remove User":
                    query += " AND action = 'Remove User'"
                elif action_filter == "Reset Password":
                    query += " AND action = 'Reset Password'"
                elif action_filter == "Add to Group":
                    query += " AND action = 'Add to Group'"
                else:
                    query += " AND action LIKE ?"
                    params.append(f"%{action_filter}%")
                    
            if status_filter and status_filter != "All":
                query += " AND status = ?"
                params.append(status_filter)
                
            query += " ORDER BY timestamp ASC"

            df = pd.read_sql_query(query, conn, params=params)
            conn.close()
            return df
        except sqlite3.Error as e:
            print(f"Error retrieving logs: {e}")
            return pd.DataFrame()

    def get_auth_events(self, limit=200):
        """Return recent authentication events from the audit log for the Auth Monitoring panel."""
        try:
            conn = self.get_connection()
            query = """
                SELECT timestamp, username, action, status, reason
                FROM audit_logs
                WHERE action IN ('Login', 'Failed Login', 'Logon', 'Failed Logon',
                                 'Create User', 'Remove User', 'Add to Group', 'Reset Password')
                ORDER BY timestamp DESC
                LIMIT ?
            """
            df = pd.read_sql_query(query, conn, params=[limit])
            conn.close()
            return df
        except sqlite3.Error as e:
            print(f"Error retrieving auth events: {e}")
            return pd.DataFrame()

    def get_summary_counts(self):
        """Return total, success, and failed counts for the counter cards."""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM audit_logs")
            total = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE status = 'Success'")
            success = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE status = 'Failed'")
            failed = cursor.fetchone()[0]
            conn.close()
            return total, success, failed
        except sqlite3.Error as e:
            print(f"Error retrieving summary counts: {e}")
            return 0, 0, 0

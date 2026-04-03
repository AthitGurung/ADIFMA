import sys
from datetime import datetime, timedelta
import pandas as pd

# Add src to path
import os
# Add src to path
# Use relative pathing to allow running from any drive/location
current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, 'src')
sys.path.append(src_path)

from ingestion.log_collector import LogCollector
from parsing.event_parser import EventParser
from analysis.anomaly_detector import AnomalyDetector

# Mock Classes for testing without valid Windows Logs
class MockTime:
    def __init__(self, dt):
        self.dt = dt
    def Format(self):
        return self.dt.strftime("%c")

class MockEvent:
    def __init__(self, event_id, time_offset_minutes=0, inserts=[]):
        self.EventID = event_id
        self.TimeGenerated = MockTime(datetime.now() - timedelta(minutes=time_offset_minutes))
        self.SourceName = "Security"
        self.EventType = 0
        self.EventCategory = 0
        self.StringInserts = inserts

def run_test():
    print("--- Starting Anomaly Detection Test ---")

    # 1. Mock Ingestion
    print("[1] Generating Mock Events...")
    events = []
    
    # Generate Brute Force Sequence (6 failures in 2 minutes)
    for i in range(6):
        # Event 4625: Logon Failure
        # Index 5 is usually TargetUserName
        inserts = ["Unknown", "Unknown", "Unknown", "Unknown", "Unknown", "hacker_user"] 
        events.append(MockEvent(4625, time_offset_minutes=0, inserts=inserts))

    # Generate Admin Group Add (Event 4728)
    # Index 0: User Added
    # Index 2: Group Name
    inserts_admin = ["new_admin", "stuff", "Domain Admins"]
    events.append(MockEvent(4728, time_offset_minutes=5, inserts=inserts_admin))

    print(f"    Generated {len(events)} mock events.")

    # 2. Parsing
    print("[2] Parsing Events...")
    parsed_data = []
    for evt in events:
        parsed_data.append(EventParser.parse_event(evt))
    
    df = EventParser.events_to_dataframe(parsed_data)
    print("    Parsed Data Sample:")
    print(df[['EventID', 'TimeGenerated']].head())

    # 3. Analysis
    print("[3] Running Analysis...")
    detector = AnomalyDetector(df)
    
    # Check Brute Force
    print("    Checking Brute Force...")
    bf_anomalies = detector.detect_brute_force(threshold=5, window='5min')
    if not bf_anomalies.empty:
        print("    [!] DETECTED BRUTE FORCE:")
        print(bf_anomalies)
    else:
        print("    [ ] No Brute Force Detected (Unexpected for this test)")

    # Check Admin Creation
    print("    Checking New Admin Creation...")
    admin_anomalies = detector.detect_new_admin_creation()
    if not admin_anomalies.empty:
        print("    [!] DETECTED PRIVILEGE ESCALATION:")
        print(admin_anomalies[['Type', 'MemberAdded', 'TargetGroup']])
    else:
        print("    [ ] No Privilege Escalation Detected (Unexpected for this test)")

    print("--- Test Completed ---")

if __name__ == "__main__":
    run_test()

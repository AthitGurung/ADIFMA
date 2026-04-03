import pandas as pd

class AnomalyDetector:
    """
    Analyzes parsed event logs to detect anomalies.
    """

    def __init__(self, data):
        """
        Args:
            data (pd.DataFrame): DataFrame containing parsed logs.
        """
        self.df = data.copy()
        # Convert TimeGenerated to datetime objects
        # Format usually matches standard locale or needs flexible parsing
        try:
             self.df['timestamp'] = pd.to_datetime(self.df['TimeGenerated'])
        except Exception:
             # Fallback if parsing fails, might be just row index if empty
             pass

    def detect_brute_force(self, threshold=5, window='1min', target_username_index=5):
        """
        Detects potential brute force attacks (multiple Event 4625).
        
        Args:
            threshold (int): Max failures allowed in the window.
            window (str): Time window to check (e.g., '1min').
            target_username_index (int): Index in EventData where username is stored. 
                                         4625 usually stores it at index 5.

        Returns:
            pd.DataFrame: Anomalous events or summary.
        """
        if self.df.empty:
            return pd.DataFrame()

        # Filter for Logon Failure
        failures = self.df[self.df['EventID'] == 4625].copy()
        
        if failures.empty:
            return pd.DataFrame()

        # Extract potential username (heuristic)
        # We assume EventData is available and has enough items
        def get_user(row):
            data = row.get('EventData', [])
            if data and len(data) > target_username_index:
                return data[target_username_index]
            return "Unknown"

        failures['TargetUser'] = failures.apply(get_user, axis=1)

        # Resample count by user
        # We need to set index to timestamp
        failures = failures.set_index('timestamp')
        
        # Group by user and resample
        anomalies = []
        for user, user_df in failures.groupby('TargetUser'):
            resampled = user_df.resample(window).size()
            spikes = resampled[resampled > threshold]
            if not spikes.empty:
                for time, count in spikes.items():
                    anomalies.append({
                        'Type': 'Brute Force',
                        'User': user,
                        'Time': time,
                        'Count': count
                    })
        
        return pd.DataFrame(anomalies)

    def detect_new_admin_creation(self):
        """
        Detects additions to privileged groups (Event 4728, 4732, 4756).
        """
        # IDs for member added to security-enabled groups
        admin_events = [4728, 4732, 4756] 
        
        if self.df.empty:
            return pd.DataFrame()

        # Filter
        additions = self.df[self.df['EventID'].isin(admin_events)].copy()
        
        if additions.empty:
            return pd.DataFrame()
            
        
        
        results = []
        for index, row in additions.iterrows():
            
            # This is specific to 4728 usually
            data = row.get('EventData', [])
            member = data[0] if len(data) > 0 else "Unknown"
            group = data[2] if len(data) > 2 else "Unknown Group" 
            
            results.append({
                'Type': 'Privilege Escalation',
                'EventID': row['EventID'],
                'Time': row.get('timestamp', 'Unknown'),
                'MemberAdded': member,
                'TargetGroup': group,
                'FullMessage': row.get('Message', '')[:100] + "..."
            })

        return pd.DataFrame(results)

    def detect_user_creation(self):
        """
        Detects new user creation (Event 4720).
        """
        if self.df.empty:
            return pd.DataFrame()

        # Event 4720: A user account was created
        creations = self.df[self.df['EventID'] == 4720].copy()

        if creations.empty:
            return pd.DataFrame()

        results = []
        for index, row in creations.iterrows():
            data = row.get('EventData', [])
            # In 4720:
            # TargetUserName is often at index 0
            
            
            created_user = data[0] if len(data) > 0 else "Unknown"
            creator = "Unknown" # Extracting creator is harder reliably without map, usually SubjectUserName
            
            results.append({
                'Type': 'User Creation',
                'EventID': 4720,
                'Time': row.get('timestamp', 'Unknown'),
                'CreatedUser': created_user,
                'FullMessage': row.get('Message', '')[:100] + "..."
            })
            
        return pd.DataFrame(results)

    def detect_password_changes(self):
        """
        Detects password changes (Event 4723, 4724).
        """
        # 4723: An attempt was made to change an account's password
        # 4724: An attempt was made to reset an account's password
        
        pw_events = [4723, 4724]
        
        if self.df.empty:
            return pd.DataFrame()

        changes = self.df[self.df['EventID'].isin(pw_events)].copy()

        if changes.empty:
            return pd.DataFrame()

        results = []
        for index, row in changes.iterrows():
            data = row.get('EventData', [])
            # Target User is usually index 0
            target_user = data[0] if len(data) > 0 else "Unknown"
            
            event_type = "Password Change" if row['EventID'] == 4723 else "Password Reset"
            
            results.append({
                'Type': event_type,
                'EventID': row['EventID'],
                'Time': row.get('timestamp', 'Unknown'),
                'TargetUser': target_user,
                'FullMessage': row.get('Message', '')[:100] + "..."
            })

        return pd.DataFrame(results)

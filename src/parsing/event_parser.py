import win32evtlogutil
import pandas as pd

class EventParser:
    """
    Parses raw Windows Event Log objects into structured dictionaries.
    """

    @staticmethod
    def parse_event(event, source_name='Security'):
        """
        Parses a single event object into a dictionary.
        
        Args:
            event: The raw event object from win32evtlog.
            source_name (str): Expected source channel (usually 'Security').

        Returns:
            dict: parsed event data.
        """
        
        data = {}
        data['EventID'] = event.EventID & 0xFFFF # EventID is sometimes just the lower 16 bits
        data['TimeGenerated'] = event.TimeGenerated.Format() # Returns string representation
        data['Source'] = event.SourceName
        data['Type'] = event.EventType
        data['Category'] = event.EventCategory
        
        # Extract data strings (variable content)
        if event.StringInserts:
            data['EventData'] = list(event.StringInserts)
        else:
            data['EventData'] = []

        # Attempt to resolve the full message
        try:
             data['Message'] = win32evtlogutil.SafeFormatMessage(event, source_name)
        except Exception:
             data['Message'] = ""

        return data

    @staticmethod
    def events_to_dataframe(events_list):
        """
        Converts a list of parsed event dictionaries to a Pandas DataFrame.
        """
        return pd.DataFrame(events_list)

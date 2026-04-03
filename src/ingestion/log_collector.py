import win32evtlog
import win32evtlogutil
import win32con

class LogCollector:
    """
    Collects Windows Event Logs from the specified channel or a backup .evtx file.
    """

    def __init__(self, server='localhost'):
        self.server = server

    def read_logs(self, channel='Security', backup_path=None, flags=None):
        """
        Reads event logs.
        
        Args:
            channel (str): The name of the channel to read from (e.g., 'Security').
            backup_path (str): Path to an .evtx file to read from. If provided, channel is ignored.
            flags (int): Custom flags for reading logs. Defaults to sequential, backwards read.

        Yields:
             The raw event object (or a handle to it, depending on the method).
        """
        
        if flags is None:
            # Read sequentially, backwards (newest first)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        if backup_path:
            # Open backup event log
            hand = win32evtlog.OpenBackupEventLog(self.server, backup_path)
        else:
            # Open live event log
            hand = win32evtlog.OpenEventLog(self.server, channel)

        try:
            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                for event in events:
                    yield event
        finally:
            win32evtlog.CloseEventLog(hand)

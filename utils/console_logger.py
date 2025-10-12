"""
Console Logger Utility - Saves all console output to ./logs/debug.log
Overwrites the log file on each run for easier debugging
"""
import sys
import os
from pathlib import Path
from datetime import datetime

class ConsoleLogger:
    """Dual output logger - writes to both console and debug log file"""
    
    def __init__(self, log_file_path="./logs/debug.log"):
        self.log_file_path = log_file_path
        self.terminal = sys.stdout
        self.log_file = None
        
        # Ensure logs directory exists
        log_dir = Path(log_file_path).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Open log file in write mode (overwrites previous run)
        try:
            self.log_file = open(log_file_path, 'w', buffering=1, encoding='utf-8')
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            header = f"=== Console Log Started: {timestamp} ===\n"
            self.log_file.write(header)
            self.log_file.flush()
        except Exception as e:
            print(f"Warning: Could not open debug log file: {e}")
    
    def write(self, message):
        """Write to both terminal and log file"""
        # Write to terminal
        self.terminal.write(message)
        
        # Write to log file
        if self.log_file and not self.log_file.closed:
            try:
                self.log_file.write(message)
                self.log_file.flush()  # Immediate flush for real-time logging
            except:
                pass  # Silently fail if file write fails
    
    def flush(self):
        """Flush both outputs"""
        self.terminal.flush()
        if self.log_file and not self.log_file.closed:
            try:
                self.log_file.flush()
            except:
                pass
    
    def fileno(self):
        """Return the file descriptor of the underlying terminal for subprocess compatibility"""
        return self.terminal.fileno()
    
    def close(self):
        """Close the log file"""
        if self.log_file and not self.log_file.closed:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            footer = f"\n=== Console Log Ended: {timestamp} ===\n"
            try:
                self.log_file.write(footer)
                self.log_file.close()
            except:
                pass

def setup_console_logging(log_file_path="./logs/debug.log"):
    """
    Setup dual console logging to file and terminal
    Call this once at app startup
    """
    logger = ConsoleLogger(log_file_path)
    sys.stdout = logger
    sys.stderr = logger  # Also capture stderr (errors)
    
    return logger

def restore_console_logging(logger):
    """Restore original console output (cleanup)"""
    if logger:
        sys.stdout = logger.terminal
        sys.stderr = logger.terminal
        logger.close()

import psutil
import time
import csv
import threading
import queue
import os
import json
from datetime import datetime
import signal
import sys
import subprocess
import select
import termios
import tty
from collections import defaultdict
import curses
import re

class SandcatLogger:
    def __init__(self):
        self.running = True
        self.log_queue = queue.Queue()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = os.path.join(os.getcwd(), f"sandcat_logs_{timestamp}")
        self.csv_file = os.path.join(self.output_dir, "sandcat_logs.csv")
        self.sandcat_pid = None
        self.server = "http://192.168.203.15:8888"
        self.stats = defaultdict(int)
        self.last_entries = []
        self.screen = None
        self.command_history = set()  # Use set to avoid duplicates
        
        # Create output directory
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def find_sandcat_process(self):
        """Find Sandcat process"""
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = proc.cmdline()
                if not cmdline:
                    continue
                
                if ('curl' in cmdline[0] and self.server in ' '.join(cmdline)) or \
                   ('splunkd' in cmdline[0] and '-server' in cmdline):
                    self.sandcat_pid = proc.pid
                    # Log only when we first find the process
                    cmd = ' '.join(cmdline)
                    if cmd not in self.command_history:
                        self.command_history.add(cmd)
                        self.log_event(
                            'process_start',
                            cmd,
                            'Sandcat process started'
                        )
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False

    def monitor_process_activities(self):
        """Monitor process activities"""
        while self.running:
            if not self.sandcat_pid:
                if not self.find_sandcat_process():
                    time.sleep(1)
                    continue

            try:
                process = psutil.Process(self.sandcat_pid)
                with process.oneshot():
                    # Check for new child processes
                    children = process.children(recursive=True)
                    for child in children:
                        try:
                            cmd = ' '.join(child.cmdline())
                            if cmd and cmd not in self.command_history:
                                self.command_history.add(cmd)
                                self.log_event(
                                    'command_execution',
                                    cmd,
                                    f'New command executed (PID: {child.pid})'
                                )
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue

                    # Monitor main process for changes
                    cmd = ' '.join(process.cmdline())
                    if cmd and cmd not in self.command_history:
                        self.command_history.add(cmd)
                        self.log_event(
                            'command_execution',
                            cmd,
                            'Main process command'
                        )

                    # Check network connections
                    connections = process.connections()
                    for conn in connections:
                        if conn.status == 'ESTABLISHED':
                            conn_str = f"{conn.laddr}:{conn.raddr}"
                            if conn_str not in self.command_history:
                                self.command_history.add(conn_str)
                                self.log_event(
                                    'network_connection',
                                    conn_str,
                                    f'New connection established'
                                )

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                self.sandcat_pid = None
            
            time.sleep(0.1)

    def log_event(self, event_type, command, details):
        """Log significant events"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = {
            'timestamp': timestamp,
            'event_type': event_type,
            'command': command,
            'details': details
        }
        self.log_queue.put(log_entry)
        self.stats[event_type] += 1
        
        # Update display entries
        self.last_entries = \
            ([f"[{timestamp}] {event_type}: {command[:100]}..."] + 
             self.last_entries)[:10]

    def log_writer(self):
        """Write logs to CSV"""
        with open(self.csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Event Type', 'Command', 'Details'])
            
            while self.running or not self.log_queue.empty():
                try:
                    log_entry = self.log_queue.get(timeout=1)
                    writer.writerow([
                        log_entry['timestamp'],
                        log_entry['event_type'],
                        log_entry['command'],
                        log_entry['details']
                    ])
                    f.flush()
                    self.stats['rows_written'] += 1
                except queue.Empty:
                    continue

    def update_display(self):
        """Update terminal display"""
        while self.running:
            try:
                self.screen.clear()
                height, width = self.screen.getmaxyx()
                
                # Display title and status
                self.screen.addstr(0, 0, "Sandcat Process Logger", curses.A_BOLD)
                self.screen.addstr(1, 0, "=" * (width - 1))
                
                status = "ACTIVE" if self.sandcat_pid else "SEARCHING"
                self.screen.addstr(2, 0, f"Status: {status}", 
                                 curses.A_BOLD | (curses.A_REVERSE if status == "ACTIVE" else 0))
                
                # Display statistics
                self.screen.addstr(4, 0, "Events Captured:", curses.A_BOLD)
                self.screen.addstr(5, 2, f"Process Starts: {self.stats['process_start']}")
                self.screen.addstr(6, 2, f"Commands Executed: {self.stats['command_execution']}")
                self.screen.addstr(7, 2, f"Network Connections: {self.stats['network_connection']}")
                
                # Display recent events
                self.screen.addstr(9, 0, "Recent Events:", curses.A_BOLD)
                for i, entry in enumerate(self.last_entries):
                    if 10 + i < height - 2:
                        self.screen.addstr(10 + i, 2, entry[:width-3])
                
                # Display footer
                self.screen.addstr(height-1, 0, "Press '`' to stop logging", curses.A_REVERSE)
                
                self.screen.refresh()
                time.sleep(0.1)
                
            except curses.error:
                continue

    def cleanup(self):
        """Cleanup resources"""
        if self.screen:
            curses.nocbreak()
            self.screen.keypad(False)
            curses.echo()
            curses.endwin()
        print(f"\nLogging completed. Results written to {self.csv_file}")

    def run(self):
        """Main execution method"""
        if os.geteuid() != 0:
            print("This script requires root privileges. Please run with sudo.")
            sys.exit(1)

        try:
            # Initialize curses
            self.screen = curses.initscr()
            curses.start_color()
            curses.noecho()
            curses.cbreak()
            self.screen.keypad(True)

            # Start monitoring threads
            threads = [
                threading.Thread(target=self.monitor_process_activities),
                threading.Thread(target=self.log_writer),
                threading.Thread(target=self.update_display)
            ]
            
            for thread in threads:
                thread.daemon = True
                thread.start()

            # Monitor for backtick
            while self.running:
                if self.screen.getch() == ord('`'):
                    self.running = False
                    break

            # Cleanup and wait for threads
            for thread in threads:
                thread.join(timeout=1.0)

        except Exception as e:
            self.cleanup()
            print(f"Error: {e}")
        finally:
            self.cleanup()

if __name__ == "__main__":
    logger = SandcatLogger()
    logger.run()

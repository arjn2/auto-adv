import psutil
import logging
import argparse
import json
from datetime import datetime, timedelta
from collections import defaultdict
import subprocess
import re

class EnhancedLogCorrelator:
    def __init__(self, target_pid, time_window=15):
        self.target_pid = target_pid
        self.time_window = time_window
        self.process_info = {}
        self.system_logs = defaultdict(list)
        self.correlated_events = []
        self.historical_data = {}

    def collect_process_info(self):
        try:
            if not psutil.pid_exists(self.target_pid):
                logging.info(f"PID {self.target_pid} no longer exists, collecting historical data")
                return self.collect_historical_info()

            process = psutil.Process(self.target_pid)
            self.process_info = {
                'pid': process.pid,
                'ppid': process.ppid(),
                'name': process.name(),
                'cmdline': ' '.join(process.cmdline()),
                'create_time': datetime.fromtimestamp(process.create_time()),
                'username': process.username(),
                'status': process.status(),
                'cwd': process.cwd(),
                'terminal': process.terminal()
            }

            try:
                children = process.children(recursive=True)
                self.process_info['children'] = [
                    {
                        'pid': child.pid,
                        'name': child.name(),
                        'cmdline': ' '.join(child.cmdline()),
                        'create_time': datetime.fromtimestamp(child.create_time())
                    } for child in children
                ]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                self.process_info['children'] = []

            return True

        except psutil.NoSuchProcess:
            return self.collect_historical_info()
        except Exception as e:
            logging.error(f"Error collecting process info: {e}")
            return False

    def collect_historical_info(self):
        """Collect historical information for completed processes"""
        cmd = [
            'journalctl',
            f'_PID={self.target_pid}',
            '--output=json',
            '-n', '1000'  # Limit to last 1000 entries
        ]
        
        try:
            output = subprocess.check_output(cmd, universal_newlines=True)
            entries = [json.loads(line) for line in output.splitlines() if line]
            
            if entries:
                latest_entry = entries[-1]
                self.historical_data = {
                    'pid': self.target_pid,
                    'status': 'terminated',
                    'last_seen': latest_entry.get('__REALTIME_TIMESTAMP', ''),
                    'command': latest_entry.get('_COMM', ''),
                    'unit': latest_entry.get('_SYSTEMD_UNIT', ''),
                    'logs': entries
                }
                self.process_info = self.historical_data
                return True
                
        except subprocess.CalledProcessError as e:
            logging.error(f"Error collecting historical data: {e}")
        return False

    def collect_system_logs(self):
        # Calculate time range
        if 'create_time' in self.process_info:
            start_time = self.process_info['create_time']
        else:
            start_time = datetime.now() - timedelta(minutes=self.time_window)
        
        end_time = start_time + timedelta(minutes=self.time_window)
        
        # Collect from multiple log sources
        self._collect_journal_logs(start_time, end_time)
        self._collect_auth_logs(start_time, end_time)
        self._collect_syslog(start_time, end_time)

    def _collect_journal_logs(self, start_time, end_time):
        cmd = [
            'journalctl',
            '--since', start_time.strftime('%Y-%m-%d %H:%M:%S'),
            '--until', end_time.strftime('%Y-%m-%d %H:%M:%S'),
            '--output=json'
        ]
        
        try:
            output = subprocess.check_output(cmd, universal_newlines=True)
            for line in output.splitlines():
                if line:
                    log_entry = json.loads(line)
                    if self._is_relevant_log(log_entry):
                        self.system_logs['journal'].append(log_entry)
        except subprocess.CalledProcessError as e:
            logging.error(f"Error collecting journal logs: {e}")

    def _collect_auth_logs(self, start_time, end_time):
        try:
            with open('/var/log/auth.log', 'r') as f:
                for line in f:
                    if self._is_within_timerange(line, start_time, end_time):
                        self.system_logs['auth'].append(line.strip())
        except Exception as e:
            logging.error(f"Error collecting auth logs: {e}")

    def _collect_syslog(self, start_time, end_time):
        try:
            with open('/var/log/syslog', 'r') as f:
                for line in f:
                    if self._is_within_timerange(line, start_time, end_time):
                        self.system_logs['syslog'].append(line.strip())
        except Exception as e:
            logging.error(f"Error collecting syslog: {e}")

    def _is_relevant_log(self, log_entry):
        relevant_pids = [str(self.target_pid)]
        if 'children' in self.process_info:
            relevant_pids.extend(str(child['pid']) for child in self.process_info['children'])

        pid_match = str(log_entry.get('_PID', '')) in relevant_pids
        message = log_entry.get('MESSAGE', '').lower()
        
        # Enhanced matching for Caldera commands
        cmd_match = any(
            str(pid) in message or
            (isinstance(self.process_info.get('cmdline'), str) and 
             self.process_info['cmdline'].lower() in message)
            for pid in relevant_pids
        )
        
        return pid_match or cmd_match

    def _is_within_timerange(self, log_line, start_time, end_time):
        try:
            log_time = datetime.strptime(log_line[:15], '%b %d %H:%M:%S')
            log_time = log_time.replace(year=datetime.now().year)
            return start_time <= log_time <= end_time
        except:
            return False

    def correlate_events(self):
        if not self.process_info:
            return

        base_event = {
            'timestamp': datetime.now().isoformat(),
            'process_info': self.process_info,
            'historical_data': self.historical_data if self.historical_data else None,
            'related_logs': dict(self.system_logs)
        }
        
        self.correlated_events.append(base_event)

def main():
    parser = argparse.ArgumentParser(description='Enhanced Log Correlation Tool')
    parser.add_argument('--pid', type=int, required=True, help='Target PID to analyze')
    parser.add_argument('--window', type=int, default=15, help='Time window in minutes')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    correlator = EnhancedLogCorrelator(args.pid, args.window)

    try:
        logging.info(f"Analyzing process {args.pid}")
        if correlator.collect_process_info():
            correlator.collect_system_logs()
            correlator.correlate_events()
            
            output_file = f"correlated_logs_pid_{args.pid}.json"
            with open(output_file, 'w') as f:
                json.dump(correlator.correlated_events, f, indent=2, default=str)
            
            logging.info(f"Results written to {output_file}")
        else:
            logging.error(f"Failed to collect information for PID {args.pid}")
    except Exception as e:
        logging.error(f"Error during correlation: {e}")
        raise

if __name__ == "__main__":
    main()

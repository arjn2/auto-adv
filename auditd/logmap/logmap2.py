import json
import argparse
import subprocess
import logging
from datetime import datetime, timedelta

class LogMapper:
    def __init__(self, json_file):
        self.json_file = json_file
        self.correlated_data = None
        self.security_logs = {
            'kernel_security': [],
            'auth': [],
            'pam': [],
            'audit_exec': []
        }

    def load_correlation_data(self):
        with open(self.json_file, 'r') as f:
            self.correlated_data = json.load(f)[0]
            
    def extract_correlation_info(self):
        if not self.correlated_data:
            return None
            
        process_info = self.correlated_data['process_info']
        journal_logs = self.correlated_data.get('related_logs', {}).get('journal', [])
        
        if not journal_logs:
            return None
            
        first_log = journal_logs[0]
        return {
            'boot_id': first_log.get('_BOOT_ID'),
            'audit_session': first_log.get('_AUDIT_SESSION'),
            'tty': first_log.get('_TTY'),
            'pid': process_info['pid'],
            'ppid': first_log.get('_PPID'),
            'timestamp': self.correlated_data['timestamp']
        }

    def collect_security_logs(self):
        info = self.extract_correlation_info()
        if not info:
            return

        timestamp = datetime.fromisoformat(info['timestamp'])
        start_time = timestamp - timedelta(minutes=5)
        end_time = timestamp + timedelta(minutes=5)

        # Kernel security logs (priority 0-6)
        cmd = [
            'journalctl',
            '-k',
            '-p', '0..6',
            f'--boot={info["boot_id"]}',
            f'--since={start_time.strftime("%Y-%m-%d %H:%M:%S")}',
            f'--until={end_time.strftime("%Y-%m-%d %H:%M:%S")}',
            '--output=json'
        ]
        self._execute_command(cmd, 'kernel_security')

        # Authentication logs
        cmd = [
            'journalctl',
            f'--boot={info["boot_id"]}',
            'SYSLOG_FACILITY=10',  # Auth facility
            f'--since={start_time.strftime("%Y-%m-%d %H:%M:%S")}',
            f'--until={end_time.strftime("%Y-%m-%d %H:%M:%S")}',
            '--output=json'
        ]
        self._execute_command(cmd, 'auth')

        # PAM events
        cmd = [
            'journalctl',
            f'_AUDIT_SESSION={info["audit_session"]}',
            'SYSLOG_IDENTIFIER=pam',
            f'--since={start_time.strftime("%Y-%m-%d %H:%M:%S")}',
            f'--until={end_time.strftime("%Y-%m-%d %H:%M:%S")}',
            '--output=json'
        ]
        self._execute_command(cmd, 'pam')

        # Audit execution logs
        cmd = [
            'ausearch',
            '-ts', start_time.strftime("%H:%M:%S"),
            '-te', end_time.strftime("%H:%M:%S"),
            '-m', 'EXECVE',
            '-i'
        ]
        self._execute_command(cmd, 'audit_exec', json_format=False)

    def _execute_command(self, cmd, log_type, json_format=True):
        try:
            output = subprocess.check_output(cmd, universal_newlines=True)
            if output:
                if json_format:
                    self.security_logs[log_type] = [
                        json.loads(line) for line in output.splitlines() if line
                    ]
                else:
                    self.security_logs[log_type] = output.splitlines()
        except subprocess.CalledProcessError as e:
            logging.error(f"Error collecting {log_type} logs: {e}")

    def save_mapped_logs(self):
        output_file = f"security_logs_{self.correlated_data['process_info']['pid']}.json"
        with open(output_file, 'w') as f:
            json.dump(self.security_logs, f, indent=2, default=str)
        logging.info(f"Security logs saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Security Log Mapper')
    parser.add_argument('--file', required=True, help='Correlated logs JSON file')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    mapper = LogMapper(args.file)
    mapper.load_correlation_data()
    mapper.collect_security_logs()
    mapper.save_mapped_logs()

if __name__ == "__main__":
    main()

import json
import argparse
import subprocess
import logging
from datetime import datetime, timedelta

class LogMapper:
    def __init__(self, json_file):
        self.json_file = json_file
        self.correlated_data = None
        self.system_logs = {}
        
    def load_correlation_data(self):
        with open(self.json_file, 'r') as f:
            self.correlated_data = json.load(f)[0]
            
    def extract_identifiers(self):
        process_info = self.correlated_data['process_info']
        journal_logs = self.correlated_data['related_logs']['journal']
        
        if not journal_logs:
            return None
            
        first_log = journal_logs[0]
        return {
            'boot_id': first_log.get('_BOOT_ID'),
            'session_id': first_log.get('_AUDIT_SESSION'),
            'tty': first_log.get('_TTY'),
            'pid': process_info['pid'],
            'timestamp': self.correlated_data['timestamp']
        }

    def collect_system_logs(self):
        identifiers = self.extract_identifiers()
        if not identifiers:
            return
            
        timestamp = datetime.fromisoformat(identifiers['timestamp'])
        start_time = timestamp - timedelta(minutes=5)
        end_time = timestamp + timedelta(minutes=5)

        # Collect journal logs
        cmd = [
            'journalctl',
            f'--boot={identifiers["boot_id"]}',
            f'--since={start_time.strftime("%Y-%m-%d %H:%M:%S")}',
            f'--until={end_time.strftime("%Y-%m-%d %H:%M:%S")}',
            '--output=json'
        ]
        
        try:
            output = subprocess.check_output(cmd, universal_newlines=True)
            self.system_logs['journal'] = [
                json.loads(line) for line in output.splitlines() if line
            ]
        except subprocess.CalledProcessError as e:
            logging.error(f"Error collecting journal logs: {e}")

        # Collect audit logs
        cmd = [
            'ausearch',
            '-ts', start_time.strftime("%H:%M:%S"),
            '-te', end_time.strftime("%H:%M:%S"),
            '-i'
        ]
        
        try:
            output = subprocess.check_output(cmd, universal_newlines=True)
            self.system_logs['audit'] = output.splitlines()
        except subprocess.CalledProcessError as e:
            logging.error(f"Error collecting audit logs: {e}")

    def save_mapped_logs(self):
        output_file = f"system_wide_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(self.system_logs, f, indent=2)
        logging.info(f"System-wide logs saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description='System-wide Log Mapper')
    parser.add_argument('--file', required=True, help='Correlated logs JSON file')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    
    mapper = LogMapper(args.file)
    mapper.load_correlation_data()
    mapper.collect_system_logs()
    mapper.save_mapped_logs()

if __name__ == "__main__":
    main()

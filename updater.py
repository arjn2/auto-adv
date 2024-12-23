#!/usr/bin/env python3

import os
import json
import yaml
import git
import logging
import hashlib
import datetime
from pathlib import Path

class SignatureUpdater:
    def __init__(self):
        self.repo_url = "https://github.com/mitre/stockpile.git"
        self.repo_path = "stockpile_temp"
        self.signature_file = "signatures.json"
        self.signature_backup = "signatures.json.backup"
        self.last_update_file = ".last_update"

    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('signature_updates.log'),
                logging.StreamHandler()
            ]
        )

    def backup_signatures(self):
        """Create backup of existing signatures file"""
        if os.path.exists(self.signature_file):
            try:
                with open(self.signature_file, 'r') as f:
                    current_signatures = json.load(f)
                with open(self.signature_backup, 'w') as f:
                    json.dump(current_signatures, f, indent=2)
                logging.info(f"Created backup at {self.signature_backup}")
            except Exception as e:
                logging.error(f"Failed to create backup: {str(e)}")
                return False
        return True

    def get_repo_hash(self):
        """Get current commit hash of stockpile repo"""
        try:
            repo = git.Repo(self.repo_path)
            return repo.head.object.hexsha
        except Exception as e:
            logging.error(f"Failed to get repo hash: {str(e)}")
            return None

    def needs_update(self):
        """Check if signatures need updating"""
        if not os.path.exists(self.last_update_file):
            return True

        try:
            with open(self.last_update_file, 'r') as f:
                last_hash = f.read().strip()

            current_hash = self.get_repo_hash()
            return last_hash != current_hash
        except Exception as e:
            logging.error(f"Error checking update status: {str(e)}")
            return True

    def clone_or_pull_repo(self):
        """Clone or update the stockpile repository"""
        try:
            if os.path.exists(self.repo_path):
                repo = git.Repo(self.repo_path)
                current_hash = repo.head.object.hexsha
                repo.remotes.origin.pull()
                new_hash = repo.head.object.hexsha
                if current_hash != new_hash:
                    logging.info("Repository updated successfully")
                else:
                    logging.info("Repository already up to date")
            else:
                git.Repo.clone_from(self.repo_url, self.repo_path)
                logging.info("Repository cloned successfully")
            return True
        except Exception as e:
            logging.error(f"Repository operation failed: {str(e)}")
            return False

    def parse_abilities(self):
        """Parse abilities from stockpile"""
        signatures = {
            "metadata": {
                "version": "2.0",
                "last_updated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source": "MITRE Caldera Stockpile",
                "description": "Automatically generated from Stockpile repository"
            },
            "techniques": {},
            "whitelisted_services": [
                "NetworkManager",
                "systemd-logind",
                "dbus",
                "cron",
                "CRON",
                "anacron",
                "systemd",
                "nm-dispatcher"
            ]
        }

        abilities_path = os.path.join(self.repo_path, "data", "abilities")
        for root, _, files in os.walk(abilities_path):
            for file in files:
                if file.endswith(('.yml', '.yaml')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            ability = yaml.safe_load(f)
                            self.process_ability(ability, signatures)
                    except Exception as e:
                        logging.error(f"Error parsing {file_path}: {str(e)}")

        return signatures

    def process_ability(self, ability, signatures):
        """Process individual ability and extract commands"""
        if isinstance(ability, list):
            for item in ability:
                self.process_ability(item, signatures)
            return

        if not isinstance(ability, dict):
            return

        for ability_id, details in ability.items():
            if not isinstance(details, dict):
                continue

            tactic = details.get('tactic', 'unknown')
            technique = details.get('technique', {})
            technique_id = technique.get('attack_id', 'T0000')
            technique_name = technique.get('name', 'Unknown Technique')

            if tactic not in signatures['techniques']:
                signatures['techniques'][tactic] = {}

            if technique_id not in signatures['techniques'][tactic]:
                signatures['techniques'][tactic][technique_id] = {
                    'name': technique_name,
                    'signatures': {}
                }

            # Process Linux commands
            executors = details.get('platforms', {}).get('linux', {}).get('sh', {})
            if isinstance(executors, dict):
                command = executors.get('command', '')
                if command:
                    signature = self.create_signature(command, details.get('name', ''))
                    if signature:
                        signatures['techniques'][tactic][technique_id]['signatures'].update(signature)

    def create_signature(self, command, ability_name):
        """Create signature patterns from command"""
        signatures = {}
        
        # Clean command of variables
        command = command.replace('#{', '').replace('}', '')
        
        # Split into individual commands
        commands = command.split('|')
        for cmd in commands:
            cmd = cmd.strip()
            if cmd:
                # Get base command
                base_cmd = cmd.split()[0]
                if len(base_cmd) > 2:  # Ignore very short commands
                    # Create signature pattern
                    signatures[base_cmd] = {
                        "description": f"{ability_name}: {base_cmd}",
                        "pattern": cmd.replace('"', '\\"'),
                        "severity": "high" if any(x in cmd.lower() for x in ['rm', 'kill', 'dd']) else "medium"
                    }

        return signatures

    def update_signatures(self):
        """Main update process"""
        self.setup_logging()
        logging.info("Starting signature update process")

        if not self.backup_signatures():
            return False

        if not self.clone_or_pull_repo():
            return False

        if not self.needs_update():
            logging.info("Signatures are already up to date")
            return True

        try:
            # Generate new signatures
            new_signatures = self.parse_abilities()

            # Save new signatures
            with open(self.signature_file, 'w') as f:
                json.dump(new_signatures, f, indent=2)

            # Save update hash
            with open(self.last_update_file, 'w') as f:
                f.write(self.get_repo_hash())

            logging.info("Successfully updated signatures")
            return True

        except Exception as e:
            logging.error(f"Update failed: {str(e)}")
            return False

        finally:
            # Cleanup
            if os.path.exists(self.repo_path):
                os.system(f"rm -rf {self.repo_path}")

def main():
    updater = SignatureUpdater()
    if updater.update_signatures():
        print("Signature update completed successfully")
    else:
        print("Signature update failed. Check logs for details")

if __name__ == "__main__":
    main()

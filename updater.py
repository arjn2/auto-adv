#!/usr/bin/env python3

import os
import json
import yaml
import git
import logging
import hashlib
import datetime
from pathlib import Path
from typing import Dict, Any, Optional

class SignatureUpdater:
    def __init__(self):
        self.repo_url = "https://github.com/mitre/stockpile.git"
        self.repo_path = Path("stockpile_temp")
        self.signature_file = Path("signatures.json")
        self.signature_backup = Path("signatures.json.backup")
        self.last_update_file = Path(".last_update")
        
        # Add mapping for MITRE ATT&CK tactics
        self.tactic_mapping = {
            'collection': 'Collection',
            'command-and-control': 'Command and Control',
            'credential-access': 'Credential Access',
            'defense-evasion': 'Defense Evasion',
            'discovery': 'Discovery',
            'execution': 'Execution',
            'exfiltration': 'Exfiltration',
            'impact': 'Impact',
            'lateral-movement': 'Lateral Movement',
            'persistence': 'Persistence',
            'privilege-escalation': 'Privilege Escalation'
        }

    def setup_logging(self) -> None:
        """Setup logging configuration with rotation"""
        log_file = Path('signature_updates.log')
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.RotatingFileHandler(
                    log_file,
                    maxBytes=1024*1024,  # 1MB
                    backupCount=3
                ),
                logging.StreamHandler()
            ]
        )

    def backup_signatures(self) -> bool:
        """Create backup of existing signatures file with error handling"""
        try:
            if self.signature_file.exists():
                with open(self.signature_file, 'r') as f:
                    current_signatures = json.load(f)
                with open(self.signature_backup, 'w') as f:
                    json.dump(current_signatures, f, indent=2)
                logging.info(f"Created backup at {self.signature_backup}")
            return True
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in signatures file: {str(e)}")
            return False
        except Exception as e:
            logging.error(f"Failed to create backup: {str(e)}")
            return False

    def get_repo_hash(self) -> Optional[str]:
        """Get current commit hash of stockpile repo"""
        try:
            repo = git.Repo(self.repo_path)
            return repo.head.object.hexsha
        except git.InvalidGitRepositoryError:
            logging.error(f"{self.repo_path} is not a valid git repository")
            return None
        except Exception as e:
            logging.error(f"Failed to get repo hash: {str(e)}")
            return None

    def needs_update(self) -> bool:
        """Check if signatures need updating with improved error handling"""
        if not self.last_update_file.exists():
            return True

        try:
            last_hash = self.last_update_file.read_text().strip()
            current_hash = self.get_repo_hash()
            
            if not current_hash:
                logging.error("Could not determine current repository hash")
                return True
                
            return last_hash != current_hash
        except Exception as e:
            logging.error(f"Error checking update status: {str(e)}")
            return True

    def clone_or_pull_repo(self) -> bool:
        """Clone or update the stockpile repository with improved error handling"""
        try:
            if self.repo_path.exists():
                repo = git.Repo(self.repo_path)
                current_hash = repo.head.object.hexsha
                origin = repo.remotes.origin
                origin.fetch()
                origin.pull()
                new_hash = repo.head.object.hexsha
                if current_hash != new_hash:
                    logging.info("Repository updated successfully")
                else:
                    logging.info("Repository already up to date")
            else:
                git.Repo.clone_from(self.repo_url, self.repo_path)
                logging.info("Repository cloned successfully")
            return True
        except git.GitCommandError as e:
            logging.error(f"Git command failed: {str(e)}")
            return False
        except Exception as e:
            logging.error(f"Repository operation failed: {str(e)}")
            return False

    def parse_abilities(self) -> Dict[str, Any]:
        """Parse abilities from stockpile with improved structure"""
        signatures = {
            "metadata": {
                "version": "2.1",
                "last_updated": datetime.datetime.now().isoformat(),
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

        abilities_path = self.repo_path / "data" / "abilities"
        if not abilities_path.exists():
            raise FileNotFoundError(f"Abilities directory not found: {abilities_path}")

        for tactic_dir in abilities_path.iterdir():
            if tactic_dir.is_dir():
                tactic_name = self.tactic_mapping.get(tactic_dir.name, tactic_dir.name)
                self.process_tactic_directory(tactic_dir, tactic_name, signatures)

        return signatures

    def process_tactic_directory(self, tactic_dir: Path, tactic_name: str, signatures: Dict[str, Any]) -> None:
        """Process all abilities within a tactic directory"""
        if tactic_name not in signatures['techniques']:
            signatures['techniques'][tactic_name] = {}

        for ability_file in tactic_dir.glob('**/*.y*ml'):
            try:
                with open(ability_file, 'r') as f:
                    ability_data = yaml.safe_load(f)
                    self.process_ability(ability_data, tactic_name, signatures)
            except yaml.YAMLError as e:
                logging.error(f"Error parsing YAML in {ability_file}: {str(e)}")
            except Exception as e:
                logging.error(f"Error processing {ability_file}: {str(e)}")

    def process_ability(self, ability: Any, tactic: str, signatures: Dict[str, Any]) -> None:
        """Process individual ability with improved type checking"""
        if not isinstance(ability, (dict, list)):
            return

        if isinstance(ability, list):
            for item in ability:
                self.process_ability(item, tactic, signatures)
            return

        for ability_id, details in ability.items():
            if not isinstance(details, dict):
                continue

            technique = details.get('technique', {})
            technique_id = technique.get('attack_id', 'T0000')
            technique_name = technique.get('name', 'Unknown Technique')

            if technique_id not in signatures['techniques'][tactic]:
                signatures['techniques'][tactic][technique_id] = {
                    'name': technique_name,
                    'signatures': {}
                }

            self.process_executors(details, tactic, technique_id, signatures)

    def process_executors(self, details: Dict[str, Any], tactic: str, technique_id: str, signatures: Dict[str, Any]) -> None:
        """Process executor commands with platform-specific handling and parser detection"""
        platforms = details.get('platforms', {})
        ability_name = details.get('name', '')
        ability_id = next(iter(details)) if isinstance(details, dict) else 'unknown'
        
        for platform in ['linux', 'darwin']:
            if platform in platforms:
                platform_data = platforms[platform]
                if isinstance(platform_data, dict) and 'sh' in platform_data:
                    executor = platform_data['sh']
                    if isinstance(executor, dict):
                        command = executor.get('command', '')
                        parsers = executor.get('parsers', {})
                        
                        if command:
                            signature = self.create_signature(
                                command=command,
                                ability_name=ability_name,
                                ability_id=ability_id,
                                platform=platform,
                                parsers=parsers
                            )
                            if signature:
                                signatures['techniques'][tactic][technique_id]['signatures'].update(signature)

    def create_signature(self, command: str, ability_name: str, ability_id: str, platform: str, parsers: Dict[str, Any]) -> Dict[str, Any]:
        """Create signature patterns with improved command parsing and metadata"""
        signatures = {}
        
        # Clean and normalize command
        command = command.replace('#{', '').replace('}', '')
        commands = [cmd.strip() for cmd in command.split('|') if cmd.strip()]
        
        for cmd in commands:
            try:
                parts = cmd.split()
                if not parts:
                    continue
                    
                base_cmd = parts[0]
                if len(base_cmd) <= 2:  # Skip very short commands
                    continue

                # Calculate risk severity
                high_risk_commands = {'rm', 'kill', 'dd', 'mkfs', 'fdisk'}
                medium_risk_commands = {'cp', 'mv', 'chmod', 'chown', 'mount'}
                severity = "high" if base_cmd in high_risk_commands else \
                          "medium" if base_cmd in medium_risk_commands else "low"

                signatures[f"{platform}_{base_cmd}_{ability_id}"] = {
                    "description": f"{ability_name}: {base_cmd}",
                    "pattern": cmd.replace('"', '\\"'),
                    "severity": severity,
                    "command_type": "destructive" if severity == "high" else "system",
                    "requires_privileges": any(x in cmd for x in ['sudo', 'su -']),
                    "platform": platform,
                    "ability_id": ability_id,
                    "parsers": list(parsers.keys()) if parsers else [],
                    "parser_sources": [
                        source for parser in parsers.values() 
                        if isinstance(parser, list)
                        for item in parser
                        if isinstance(item, dict)
                        for source in [item.get('source')]
                        if source
                    ] if parsers else []
                }
            except Exception as e:
                logging.warning(f"Error processing command '{cmd}': {str(e)}")
                continue

        return signatures

    def update_signatures(self) -> bool:
        """Main update process with improved error handling and cleanup"""
        self.setup_logging()
        logging.info("Starting signature update process")

        try:
            if not self.backup_signatures():
                return False

            if not self.clone_or_pull_repo():
                return False

            if not self.needs_update():
                logging.info("Signatures are already up to date")
                return True

            new_signatures = self.parse_abilities()
            
            # Validate new signatures before saving
            if not self.validate_signatures(new_signatures):
                return False

            # Save new signatures
            with open(self.signature_file, 'w') as f:
                json.dump(new_signatures, f, indent=2)

            # Update hash file
            current_hash = self.get_repo_hash()
            if current_hash:
                self.last_update_file.write_text(current_hash)

            logging.info("Successfully updated signatures")
            return True

        except Exception as e:
            logging.error(f"Update failed: {str(e)}")
            return False

        finally:
            self.cleanup()

    def validate_signatures(self, signatures: Dict[str, Any]) -> bool:
        """Validate signature structure and content"""
        try:
            required_keys = {'metadata', 'techniques', 'whitelisted_services'}
            if not all(key in signatures for key in required_keys):
                logging.error("Missing required keys in signatures")
                return False

            if not isinstance(signatures['techniques'], dict):
                logging.error("Invalid techniques structure")
                return False

            return True
        except Exception as e:
            logging.error(f"Signature validation failed: {str(e)}")
            return False

    def cleanup(self) -> None:
        """Clean up temporary files and directories"""
        try:
            if self.repo_path.exists():
                import shutil
                shutil.rmtree(self.repo_path)
                logging.info(f"Cleaned up {self.repo_path}")
        except Exception as e:
            logging.error(f"Cleanup failed: {str(e)}")

def main():
    updater = SignatureUpdater()
    success = updater.update_signatures()
    exit_code = 0 if success else 1
    exit(exit_code)

if __name__ == "__main__":
    main()

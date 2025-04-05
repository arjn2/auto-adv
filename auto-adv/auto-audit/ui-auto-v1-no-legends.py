#!/usr/bin/env python3
import os
import sys
import time
import json
import logging
import argparse
import threading
import queue
import subprocess
import requests
import signal
from datetime import datetime, timedelta
from collections import defaultdict
import psutil

# Import or install terminal menu for interactive UI
try:
    from simple_term_menu import TerminalMenu
except ImportError:
    print("Installing required package: simple_term_menu")
    subprocess.run([sys.executable, "-m", "pip", "install", "simple_term_menu"], check=True)
    from simple_term_menu import TerminalMenu

class CalderaClient:
    """Client for interacting with Caldera API"""
    def __init__(self, server_url="http://localhost:8888", api_key="ADMIN123"):
        self.server_url = server_url
        self.api_key = api_key
        self.headers = {"KEY": api_key}
        self.logger = logging.getLogger("CalderaClient")

    def test_connection(self):
        """Test connection to Caldera server"""
        try:
            response = requests.get(f"{self.server_url}/api/v2/health", 
                                   headers=self.headers, timeout=5)
            if response.status_code == 200:
                self.logger.info("Successfully connected to Caldera server")
                return True
            self.logger.error(f"Failed to connect to Caldera: {response.status_code}")
            return False
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
            return False

    def get_adversaries(self):
        """Get all available adversaries"""
        try:
            response = requests.get(f"{self.server_url}/api/v2/adversaries", 
                                   headers=self.headers, timeout=10)
            if response.status_code == 200:
                adversaries = response.json()
                self.logger.info(f"Retrieved {len(adversaries)} adversaries")
                return adversaries
            return []
        except Exception as e:
            self.logger.error(f"Error retrieving adversaries: {e}")
            return []

    def get_abilities(self):
        """Get all available abilities"""
        try:
            response = requests.get(f"{self.server_url}/api/v2/abilities", 
                                   headers=self.headers, timeout=10)
            if response.status_code == 200:
                abilities = response.json()
                self.logger.info(f"Retrieved {len(abilities)} abilities")
                return abilities
            return []
        except Exception as e:
            self.logger.error(f"Error retrieving abilities: {e}")
            return []

    def get_operations(self):
        """Get all operations"""
        try:
            response = requests.get(f"{self.server_url}/api/v2/operations", 
                                   headers=self.headers, timeout=10)
            if response.status_code == 200:
                operations = response.json()
                self.logger.info(f"Retrieved {len(operations)} operations")
                return operations
            return []
        except Exception as e:
            self.logger.error(f"Error retrieving operations: {e}")
            return []

    def get_techniques(self):
        """Extract unique MITRE ATT&CK techniques from abilities"""
        abilities = self.get_abilities()
        techniques = {}
        
        for ability in abilities:
            technique_id = ability.get('technique_id')
            if not technique_id:
                continue
                
            if technique_id not in techniques:
                techniques[technique_id] = {
                    'id': technique_id,
                    'name': ability.get('technique_name', 'Unknown'),
                    'tactic': ability.get('tactic', 'Unknown'),
                    'abilities': []
                }
            
            techniques[technique_id]['abilities'].append({
                'id': ability.get('ability_id'),
                'name': ability.get('name', 'Unknown'),
                'description': ability.get('description', '')
            })
        
        self.logger.info(f"Extracted {len(techniques)} unique techniques")
        return list(techniques.values())

    def start_operation(self, adversary_id):
        """Start a new operation with the specified adversary"""
        data = {
            "name": f"Auto_Op_{int(time.time())}",
            "adversary_id": adversary_id,
            "group": "red",
            "state": "running"
        }
        
        try:
            response = requests.post(
                f"{self.server_url}/api/v2/operations",
                headers=self.headers,
                json=data,
                timeout=10
            )
            
            if response.status_code == 200:
                operation_id = response.json().get('id')
                self.logger.info(f"Started operation {operation_id}")
                return operation_id
            
            self.logger.error(f"Failed to start operation: {response.status_code}")
            return None
        except Exception as e:
            self.logger.error(f"Error starting operation: {e}")
            return None

    def get_operation_abilities(self, operation_id):
        """Get abilities and their PIDs from an operation"""
        try:
            response = requests.get(
                f"{self.server_url}/api/v2/operations/{operation_id}",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code != 200:
                self.logger.error(f"Failed to get operation data: {response.status_code}")
                return []
                
            operation_data = response.json()
            abilities = []
            
            # Extract abilities with PIDs
            for agent in operation_data.get('host_group', {}).get('agents', {}).values():
                for link in agent.get('links', []):
                    if link.get('pid') and link.get('ability'):
                        abilities.append({
                            'pid': link['pid'],
                            'ability_id': link['ability']['ability_id'],
                            'ability_name': link['ability']['name'],
                            'tactic': link['ability']['tactic'],
                            'technique_id': link['ability'].get('technique_id', '')
                        })
            
            return abilities
        except Exception as e:
            self.logger.error(f"Error retrieving operation abilities: {e}")
            return []
            
class ProcessMonitor:
    """Monitor processes and collect logs"""
    # ... [keep existing ProcessMonitor class] ...

def select_caldera_server():
    """Prompt user for Caldera server details"""
    print("\n[*] Caldera Server Configuration")
    
    # Default values
    default_url = "http://10.0.2.15:8888"
    default_key = "ADMIN123"
    
    # Get server URL
    server_url = input(f"Enter Caldera server URL [{default_url}]: ").strip() or default_url
    
    # Get API key
    api_key = input(f"Enter Caldera API key [{default_key}]: ").strip() or default_key
    
    return server_url, api_key

def display_technique_menu(caldera_client):
    """Display menu of MITRE techniques grouped by tactic"""
    techniques = caldera_client.get_techniques()
    
    if not techniques:
        print("[-] No techniques found or unable to connect to Caldera server")
        return None
    
    # Group techniques by tactic
    tactics = defaultdict(list)
    for technique in techniques:
        tactic = technique.get('tactic', 'Unknown')
        tactics[tactic].append(technique)
    
    # Create menu for tactics
    tactic_menu_items = list(tactics.keys())
    tactic_menu_items.append("Back to Main Menu")
    
    tactic_menu = TerminalMenu(
        tactic_menu_items,
        title="Select a MITRE ATT&CK Tactic:",
        cycle_cursor=True
    )
    
    tactic_index = tactic_menu.show()
    if tactic_index is None or tactic_index == len(tactic_menu_items) - 1:
        return None
    
    selected_tactic = tactic_menu_items[tactic_index]
    tactic_techniques = tactics[selected_tactic]
    
    # Create menu for techniques in the selected tactic
    technique_menu_items = [
        f"{t['id']}: {t['name']} ({len(t['abilities'])} abilities)" 
        for t in tactic_techniques
    ]
    technique_menu_items.append("Back to Tactics")
    
    technique_menu = TerminalMenu(
        technique_menu_items,
        title=f"Select Techniques from {selected_tactic} (SPACE to toggle, ENTER to confirm):",
        multi_select=True,
        cycle_cursor=True
    )
    
    technique_indices = technique_menu.show()
    if technique_indices is None or len(technique_indices) == 0 or len(technique_menu_items) - 1 in technique_indices:
        return display_technique_menu(caldera_client)
    
    # Get selected techniques (excluding "Back" option)
    selected_techniques = [tactic_techniques[i] for i in technique_indices 
                           if i < len(tactic_techniques)]
    
    return {
        "tactic": selected_tactic,
        "techniques": selected_techniques
    }

def display_adversary_menu(caldera_client):
    """Display menu of available adversaries"""
    adversaries = caldera_client.get_adversaries()
    
    if not adversaries:
        print("[-] No adversaries found or unable to connect to Caldera server")
        return None
    
    # Create menu items
    menu_items = [
        f"{adv.get('name', 'Unknown')} ({adv.get('description', 'No description')[:50]}...)" 
        for adv in adversaries
    ]
    menu_items.append("Back to Main Menu")
    
    menu = TerminalMenu(
        menu_items,
        title="Select Adversaries to Run (SPACE to toggle, ENTER to confirm):",
        multi_select=True,
        cycle_cursor=True
    )
    
    indices = menu.show()
    if indices is None or len(indices) == 0 or len(menu_items) - 1 in indices:
        return None
    
    # Get selected adversaries (excluding "Back" option)
    selected_adversaries = [adversaries[i] for i in indices if i < len(adversaries)]
    
    return selected_adversaries

def display_abilities_menu(caldera_client):
    """Display menu of available abilities"""
    abilities = caldera_client.get_abilities()
    
    if not abilities:
        print("[-] No abilities found or unable to connect to Caldera server")
        return None
    
    # Group abilities by tactic
    tactics = defaultdict(list)
    for ability in abilities:
        tactic = ability.get('tactic', 'Unknown')
        tactics[tactic].append(ability)
    
    # Create menu for tactics
    tactic_menu_items = list(tactics.keys())
    tactic_menu_items.append("Back to Main Menu")
    
    tactic_menu = TerminalMenu(
        tactic_menu_items,
        title="Select a Tactic to view Abilities:",
        cycle_cursor=True
    )
    
    tactic_index = tactic_menu.show()
    if tactic_index is None or tactic_index == len(tactic_menu_items) - 1:
        return None
    
    selected_tactic = tactic_menu_items[tactic_index]
    tactic_abilities = tactics[selected_tactic]
    
    # Create menu for abilities in the selected tactic
    ability_menu_items = [
        f"{a.get('name', 'Unknown')} - {a.get('description', 'No description')[:50]}..." 
        for a in tactic_abilities
    ]
    ability_menu_items.append("Back to Tactics")
    
    ability_menu = TerminalMenu(
        ability_menu_items,
        title=f"Select Abilities from {selected_tactic} (SPACE to toggle, ENTER to confirm):",
        multi_select=True,
        cycle_cursor=True
    )
    
    ability_indices = ability_menu.show()
    if ability_indices is None or len(ability_indices) == 0 or len(ability_menu_items) - 1 in ability_indices:
        return display_abilities_menu(caldera_client)
    
    # Get selected abilities (excluding "Back" option)
    selected_abilities = [tactic_abilities[i] for i in ability_indices 
                         if i < len(tactic_abilities)]
    
    return {
        "tactic": selected_tactic,
        "abilities": selected_abilities
    }

def display_caldera_main_menu(caldera_client):
    """Display main Caldera options menu"""
    if not caldera_client.test_connection():
        print("[-] Cannot connect to Caldera server")
        # Prompt to reconfigure
        if input("Would you like to reconfigure Caldera connection? (y/n): ").lower() == 'y':
            server_url, api_key = select_caldera_server()
            caldera_client = CalderaClient(server_url, api_key)
            if not caldera_client.test_connection():
                print("[-] Still unable to connect to Caldera server")
                return None
        else:
            return None
    
    menu_items = [
        "Run by MITRE Technique",
        "Run Specific Adversaries",
        "Run Individual Abilities",
        "Run All Adversaries",
        "Back to Main Menu"
    ]
    
    menu = TerminalMenu(
        menu_items,
        title="Select Caldera Operation Type:",
        cycle_cursor=True
    )
    
    index = menu.show()
    if index is None or index == 4:  # Back option
        return None
    
    if index == 0:  # Techniques
        return {
            "type": "techniques",
            "selection": display_technique_menu(caldera_client)
        }
    elif index == 1:  # Adversaries
        return {
            "type": "adversaries",
            "selection": display_adversary_menu(caldera_client)
        }
    elif index == 2:  # Abilities
        return {
            "type": "abilities",
            "selection": display_abilities_menu(caldera_client)
        }
    elif index == 3:  # All Adversaries
        return {
            "type": "all_adversaries",
            "selection": None
        }

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Process Monitor and Caldera Integration')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode')
    parser.add_argument('--caldera-url', help='Caldera server URL')
    parser.add_argument('--caldera-key', help='Caldera API key')
    # Add your other arguments
    args = parser.parse_args()
    
    print("""
╔══════════════════════════════════════════════════════╗
║  MITRE ATT&CK Process Monitor and Caldera Controller ║
║  Real-time Attack Pattern Analysis Tool              ║
╚══════════════════════════════════════════════════════╝
    """)
    
    # Get Caldera server details
    server_url = args.caldera_url
    api_key = args.caldera_key
    
    if not server_url or not api_key:
        server_url, api_key = select_caldera_server()
    
    # Create Caldera client
    caldera_client = CalderaClient(server_url, api_key)
    
    # Display Caldera menu
    caldera_selection = display_caldera_main_menu(caldera_client)
    
    if caldera_selection:
        print("\n[+] Selected Caldera Operations:")
        
        if caldera_selection["type"] == "techniques":
            techniques = caldera_selection["selection"]
            if techniques:
                print(f"  Tactic: {techniques['tactic']}")
                for technique in techniques["techniques"]:
                    print(f"  - {technique['id']}: {technique['name']} ({len(technique['abilities'])} abilities)")
        
        elif caldera_selection["type"] == "adversaries":
            adversaries = caldera_selection["selection"]
            if adversaries:
                for adv in adversaries:
                    print(f"  - {adv.get('name')}")
        
        elif caldera_selection["type"] == "abilities":
            abilities = caldera_selection["selection"]
            if abilities:
                print(f"  Tactic: {abilities['tactic']}")
                for ability in abilities["abilities"]:
                    print(f"  - {ability.get('name')}")
        
        elif caldera_selection["type"] == "all_adversaries":
            print("  - Running all available adversaries")
    
    # Continue with process monitoring logic
    print("\n[*] Press Ctrl+C to exit")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Exiting...")

if __name__ == "__main__":
    main()

import os
import json
import time
import base64
import requests
from datetime import datetime
from cryptography.hazmat.primitives import serialization

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class TokenClient:
    def __init__(self, server_url="http://localhost:1220"):
        self.server_url = server_url
        self.public_key = None
        self._fetch_public_key()

    def _fetch_public_key(self):
        try:
            response = requests.get(f"{self.server_url}/public-key")
            if response.status_code == 200:
                pem_data = response.json()['public_key'].encode()
                self.public_key = serialization.load_pem_public_key(pem_data)
            else:
                raise ConnectionError(f"Server error: {response.json().get('error')}")
        except requests.RequestException as e:
            raise ConnectionError(f"Connection error: {str(e)}")

    def register(self, username, password):
        try:
            response = requests.post(
                f"{self.server_url}/register",
                json={'username': username, 'password': password}
            )
            
            if response.status_code == 200:
                return {'status': 'success', 'message': "Registration successful!"}
            else:
                raise ValueError(response.json().get('error', 'Registration failed'))
        except requests.RequestException as e:
            raise ConnectionError(f"Connection error: {str(e)}")

    def login(self, username, password):
        try:
            response = requests.post(
                f"{self.server_url}/login",
                json={'username': username, 'password': password}
            )
            
            if response.status_code == 200:
                token = response.json()['token']
                return {'status': 'success', 'token': token}
            else:
                raise ValueError(response.json().get('error', 'Login failed'))
        except requests.RequestException as e:
            raise ConnectionError(f"Connection error: {str(e)}")

def decode_jwt(token):
    parts = token.split('.')
    if len(parts) != 3:
        return "Invalid token format"
    
    try:
        header = base64.urlsafe_b64decode(parts[0] + '=' * (4 - len(parts[0]) % 4))
        payload = base64.urlsafe_b64decode(parts[1] + '=' * (4 - len(parts[1]) % 4))
        
        header_data = json.loads(header)
        payload_data = json.loads(payload)
            
        return {
            'header': header_data,
            'payload': payload_data,
            'signature': parts[2],
            'full_token': token
        }
    except Exception as e:
        return f"Error decoding token: {str(e)}"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    banner = f"""
{Colors.BLUE}╔══════════════════════════════════════╗
║          TOKEN CLIENT v1.0           ║
╚══════════════════════════════════════╝{Colors.ENDC}
"""
    print(banner)

def print_menu():
    menu = f"""
{Colors.BOLD}Available Options:{Colors.ENDC}
{Colors.GREEN}1.{Colors.ENDC} Register New User
{Colors.GREEN}2.{Colors.ENDC} Login
{Colors.GREEN}3.{Colors.ENDC} View Current Token
{Colors.GREEN}4.{Colors.ENDC} Exit
"""
    print(menu)

def print_token_info(token_data):
    print(f"\n{Colors.BLUE}=== Token Information ==={Colors.ENDC}")
    
    print(f"\n{Colors.BOLD}Full JWT Token:{Colors.ENDC}")
    print(f"{Colors.GREEN}{token_data['full_token']}{Colors.ENDC}")
    
    print(f"\n{Colors.BOLD}Header:{Colors.ENDC}")
    print(json.dumps(token_data['header'], indent=2))
    
    print(f"\n{Colors.BOLD}Payload:{Colors.ENDC}")
    payload = token_data['payload']
    
    if 'exp' in payload:
        exp_time = datetime.fromtimestamp(payload['exp'])
        payload['exp'] = exp_time.strftime('%Y-%m-%d %H:%M:%S')
    
    print(json.dumps(payload, indent=2))
    
    print(f"\n{Colors.BOLD}Signature:{Colors.ENDC}")
    print(token_data['signature'])

def loading_animation(duration=1):
    chars = "|/-\\"
    for _ in range(int(duration * 10)):
        for char in chars:
            print(f"\r{Colors.BLUE}Processing {char}{Colors.ENDC}", end='')
            time.sleep(0.1)
    print("\r" + " " * 20 + "\r", end='')

def interactive_client():
    client = None
    token = None
    
    try:
        client = TokenClient()
    except ConnectionError as e:
        print(f"\n{Colors.FAIL}✗ Failed to initialize client: {str(e)}{Colors.ENDC}")
        return
    except Exception as e:
        print(f"\n{Colors.FAIL}✗ Unexpected error during initialization: {str(e)}{Colors.ENDC}")
        return
    
    while True:
        try:
            clear_screen()
            print_banner()
            print_menu()
            
            choice = input(f"\n{Colors.BOLD}Enter your choice (1-4):{Colors.ENDC} ")
            
            if choice == "1":
                print(f"\n{Colors.BLUE}=== User Registration ==={Colors.ENDC}")
                username = input(f"{Colors.BOLD}Username:{Colors.ENDC} ")
                password = input(f"{Colors.BOLD}Password:{Colors.ENDC} ")
                
                if not username or not password:
                    raise ValueError("Username and password cannot be empty")
                
                loading_animation()
                result = client.register(username, password)
                print(f"\n{Colors.GREEN}✓ {result['message']}{Colors.ENDC}")
                
            elif choice == "2":
                print(f"\n{Colors.BLUE}=== User Login ==={Colors.ENDC}")
                username = input(f"{Colors.BOLD}Username:{Colors.ENDC} ")
                password = input(f"{Colors.BOLD}Password:{Colors.ENDC} ")
                
                if not username or not password:
                    raise ValueError("Username and password cannot be empty")
                
                loading_animation()
                result = client.login(username, password)
                if result['status'] == 'success':
                    token = result['token']
                    print(f"\n{Colors.GREEN}✓ Login successful!{Colors.ENDC}")
                    
            elif choice == "3":
                if token:
                    try:
                        decoded = decode_jwt(token)
                        if isinstance(decoded, str) and "Error" in decoded:
                            raise ValueError(decoded)
                        print_token_info(decoded)
                    except ValueError as e:
                        print(f"\n{Colors.FAIL}✗ Token error: {str(e)}{Colors.ENDC}")
                    except Exception as e:
                        print(f"\n{Colors.FAIL}✗ Unexpected error while decoding token: {str(e)}{Colors.ENDC}")
                else:
                    print(f"\n{Colors.WARNING}⚠ No active token. Please login first.{Colors.ENDC}")
                    
            elif choice == "4":
                print(f"\n{Colors.GREEN}Thank you for using Token Client!{Colors.ENDC}")
                break
                
            else:
                print(f"\n{Colors.WARNING}⚠ Invalid choice. Please select 1-4.{Colors.ENDC}")
                
        except ValueError as e:
            print(f"\n{Colors.FAIL}✗ Validation error: {str(e)}{Colors.ENDC}")
        except ConnectionError as e:
            print(f"\n{Colors.FAIL}✗ Connection error: {str(e)}{Colors.ENDC}")
        except KeyboardInterrupt:
            print(f"\n\n{Colors.WARNING}⚠ Operation cancelled by user{Colors.ENDC}")
            break
        except Exception as e:
            print(f"\n{Colors.FAIL}✗ Unexpected error: {str(e)}{Colors.ENDC}")
        
        try:
            input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
        except KeyboardInterrupt:
            print(f"\n\n{Colors.WARNING}⚠ Program terminated by user{Colors.ENDC}")
            break

interactive_client()
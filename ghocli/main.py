import typer
from rich import print
from ghocli.modules import password
import json
import os
from pathlib import Path
import pyperclip

app = typer.Typer(
    help="GHOpass: Your own password manager provided by GHO",
    rich_markup_mode="rich"
)

DB_DIR = Path.home() / ".ghopass"
DB_PATH = DB_DIR / "vault.json"

#-------------------------------------------------------------------

def check_access() -> bytes:
    if not (DB_DIR / "master.hash").exists():
        print("[bold red]App not initialized. Run 'ghopass init' first.[/bold red]")
        raise typer.Exit()    
    attempt = typer.prompt("Enter Master Password", hide_input=True)
    if not password.verify_master_password(attempt, DB_DIR):
        print("[bold red]Access Denied: Invalid Master Password![/bold red]")
        raise typer.Exit()
    salt = load_salt(DB_DIR)
    key = password.get_encryption_key(attempt, salt)
    return key

def load_salt(path: Path) -> bytes:
    with open(path / "master.hash", "r") as f:
        data = f.read()
    salt_hex, _ = data.split(":")
    return bytes.fromhex(salt_hex)

#-------------------------------------------------------------------

@app.command(help="Generates new entry to your database, generates, assigns and encrypts a strong password to it. Use ghopass gen 'new_service_name'")
def gen(service: str, length: int = 16):
    key = check_access()
    if not DB_PATH.exists():
        print("[bold red]Database does not exist.[/bold red] Use [bold cyan]'ghopass init'[/bold cyan] to create it.")
        return
    new_password = password.generate_password(length)
    encrypted = password.encrypt_password(new_password, key)
    
    #------------------------------------------------------
    
    entry = {"service": service, "password": encrypted}
    with open(DB_PATH, "r") as f:
        data = json.load(f)
    data.append(entry)
    with open(DB_PATH, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[bold green]Generated & Saved for:[/bold green] [bold white]{service}[/bold white]")

#-Rozdzial funkcji get na kopiowanie i samo pokazywanie i jeszcze poprawka bo dodam tu listowanie wszystkich hasełek

#*zrobione juz jak co*Tutaj dorobic zapytanie czy na pewno chcesz pokazać hsalo i ze je mozesz skopiowac sobie lol
@app.command(help="Decrypts and prints password assigned to selected service. Use ghopass show 'service_name'")
def show(service: str):
    key = check_access()
    if not DB_PATH.exists():
        print("[bold red]Database does not exist.[/bold red]")
        return
    confirm = typer.confirm(f"Are you sure to print your password for service: '{service}' ?")
    if not confirm:
        print(f"[bold green]Operation 'ghopass show {service}' aborted.[/bold green]")
        raise typer.Abort()
    with open(DB_PATH, "r") as f:
        data = json.load(f)
    for entry in data:
        if entry["service"] == service:
            decrypted = password.decrypt_password(entry["password"], key)
            print(f"[bold cyan]{service}:[/bold cyan] [bold white]{decrypted}[/bold white]")
            return
    
    print(f"[bold red]Service '{service}' not found.[/bold red]")

@app.command(help="Copies to clipboard password assigned to selected service. Use ghopass get 'service_name'")
def get(service: str):
    key = check_access()
    if not DB_PATH.exists():
        print("[bold red]Database does not exist.[/bold red]")
        return
    with open(DB_PATH, "r") as f:
        data = json.load(f)
    for entry in data:
        if entry["service"] == service:
            decrypted = password.decrypt_password(entry["password"], key)
            pyperclip.copy(decrypted)
            print(f"[bold yellow]Copied password assigned to {service}[/bold yellow]")
            return
    
    print(f"[bold red]Service '{service}' not found.[/bold red]")

@app.command(help="Prints all services you added to the database. Use ghopass shlist")
def shlist():
    key = check_access()
    if not DB_PATH.exists():
        print("[bold red]Database does not exist.[/bold red]")
        return
    with open(DB_PATH, "r") as f:
        data = json.load(f)
    for entry in data:
        print(f"[bold red]-[/bold red] [bold blue]      {entry["service"]}[/bold blue]")

#-------------------------------------------------------

@app.command(help="Lets you delete an entry from your password database. Use: ghopass delete 'service_name'")
def delete(service: str):
    check_access()
    if not DB_PATH.exists():
        print("[bold red]Database does not exist.[/bold red] Use 'ghopass init' to create it.")
        return
    with open(DB_PATH, "r") as f:
        data = json.load(f)
    new_data = [entry for entry in data if entry["service"] != service]
    if len(new_data) == len(data):
        print(f"[bold red]Service '{service}' not found.[/bold red]")
        return
    with open(DB_PATH, "w") as f:
        json.dump(new_data, f, indent=4)
    print(f"[bold red]Deleted service:[/bold red] [bold white]{service}[/bold white]")

@app.command(help="Generates a new password database, key for it and a master password you have to confirm. Use ghopass init. WARNING! DO NOT FORGET YOUR MASTER PASSWORD")
def init():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    if not (DB_DIR / "master.hash").exists():
        password_1 = typer.prompt("Create Master Password", hide_input=True)
        password_2 = typer.prompt("Confirm Master Password", hide_input=True)
        if password_1 != password_2:
            print("[bold red]Passwords do not match![/bold red]")
            return
        password.save_master_password(password_1, DB_DIR)
        print("[bold green]Master Password set successfully![/bold green]")    
    if not DB_PATH.exists():
        with open(DB_PATH, "w") as f:
            json.dump([], f)
        print(f"[bold green]Created database:[/bold green] {DB_PATH}")
    else:
        print("[bold yellow]Database already exists.[/bold yellow]")

@app.command(help="Deletes your password database")
def reset():
    hash_file = DB_DIR / "master.hash"
    print("[bold red]WARNING: This will permanently delete your database and Master Password![/bold red]")
    confirm = typer.confirm("Are you sure you want to proceed?")
    if not confirm:
        print("[bold blue]Operation cancelled.[/bold blue]")
        raise typer.Abort()
    removed = False
    if DB_PATH.exists():
        os.remove(DB_PATH)
        print(f"[bold yellow]Deleted database:[/bold yellow] {DB_PATH}")
        removed = True
    if hash_file.exists():
        os.remove(hash_file)
        print(f"[bold yellow]Deleted Master Password hash and salt:[/bold yellow] {hash_file}")
        removed = True
    if removed:
        print("\n[bold green]System reset successful. You can now run 'ghopass init' to set up a new vault.[/bold green]")
    else:
        print("[bold white]No files found to delete.[/bold white]")

if __name__ == "__main__":
    app()
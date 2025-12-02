"""
Port Killer - Kill Unnecessary Open Ports
This script scans for open network ports and allows you to close them
to prevent potential malware connections.

Usage: Simply run this script manually when needed.
It will NOT auto-start with Windows.
"""

import psutil
import socket
from datetime import datetime

# Common suspicious/unnecessary ports that might be used by malware
SUSPICIOUS_PORTS = {
    # Common malware ports
    1080: "SOCKS Proxy (often used by malware)",
    3389: "Remote Desktop (if not needed)",
    4444: "Metasploit default",
    5555: "Android Debug Bridge / Malware",
    5900: "VNC Server",
    6666: "IRC/Trojan",
    6667: "IRC",
    6668: "IRC",
    6669: "IRC",
    7777: "Commonly used by trojans",
    8080: "HTTP Proxy",
    8888: "HTTP Proxy",
    9999: "Commonly used by backdoors",
    12345: "NetBus trojan",
    27374: "Sub7 trojan",
    31337: "Back Orifice trojan",
}

def print_banner():
    """Print script banner"""
    print("=" * 60)
    print("           PORT KILLER - Security Tool")
    print("=" * 60)
    print(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print()

def get_open_ports():
    """Scan for all open network connections"""
    print("[*] Scanning for open ports and connections...")
    connections = psutil.net_connections(kind='inet')
    
    open_ports = {}
    for conn in connections:
        if conn.status == 'LISTEN' and conn.laddr:
            port = conn.laddr.port
            if port not in open_ports:
                try:
                    process = psutil.Process(conn.pid) if conn.pid else None
                    open_ports[port] = {
                        'pid': conn.pid,
                        'process_name': process.name() if process else 'Unknown',
                        'address': conn.laddr.ip,
                        'suspicious': port in SUSPICIOUS_PORTS
                    }
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    open_ports[port] = {
                        'pid': conn.pid,
                        'process_name': 'Access Denied',
                        'address': conn.laddr.ip,
                        'suspicious': port in SUSPICIOUS_PORTS
                    }
    
    return open_ports

def display_ports(open_ports):
    """Display all open ports in a formatted table"""
    if not open_ports:
        print("\n[+] No listening ports found.")
        return
    
    print(f"\n[+] Found {len(open_ports)} open ports:\n")
    print(f"{'Port':<8} {'Address':<16} {'PID':<8} {'Process Name':<25} {'Status'}")
    print("-" * 80)
    
    suspicious_count = 0
    for port in sorted(open_ports.keys()):
        info = open_ports[port]
        status = ""
        
        if info['suspicious']:
            status = f"⚠️  SUSPICIOUS - {SUSPICIOUS_PORTS[port]}"
            suspicious_count += 1
        
        pid_str = str(info['pid']) if info['pid'] else 'N/A'
        
        print(f"{port:<8} {info['address']:<16} {pid_str:<8} {info['process_name']:<25} {status}")
    
    print("-" * 80)
    print(f"\n[!] Found {suspicious_count} potentially suspicious ports.")

def kill_port(port, open_ports):
    """Kill the process using the specified port"""
    if port not in open_ports:
        print(f"[!] Port {port} is not open.")
        return False
    
    info = open_ports[port]
    pid = info['pid']
    
    if not pid:
        print(f"[!] Cannot kill port {port} - no process ID found.")
        return False
    
    try:
        process = psutil.Process(pid)
        process_name = process.name()
        
        # Confirm before killing
        print(f"\n[!] About to kill process: {process_name} (PID: {pid}) on port {port}")
        confirm = input("    Are you sure? (yes/no): ").strip().lower()
        
        if confirm in ['yes', 'y']:
            process.terminate()
            try:
                process.wait(timeout=3)
            except psutil.TimeoutExpired:
                process.kill()
            
            print(f"[+] Successfully killed process on port {port}")
            return True
        else:
            print("[*] Operation cancelled.")
            return False
            
    except psutil.NoSuchProcess:
        print(f"[!] Process no longer exists.")
        return False
    except psutil.AccessDenied:
        print(f"[!] Access denied. Try running this script as Administrator.")
        return False
    except Exception as e:
        print(f"[!] Error: {e}")
        return False

def kill_all_suspicious(open_ports):
    """Kill all processes on suspicious ports"""
    suspicious_ports = [p for p in open_ports.keys() if open_ports[p]['suspicious']]
    
    if not suspicious_ports:
        print("\n[*] No suspicious ports found.")
        return
    
    print(f"\n[!] Found {len(suspicious_ports)} suspicious ports.")
    print("    This will attempt to close all suspicious ports.")
    confirm = input("    Continue? (yes/no): ").strip().lower()
    
    if confirm not in ['yes', 'y']:
        print("[*] Operation cancelled.")
        return
    
    killed = 0
    for port in suspicious_ports:
        info = open_ports[port]
        if info['pid']:
            try:
                process = psutil.Process(info['pid'])
                process.terminate()
                try:
                    process.wait(timeout=2)
                except psutil.TimeoutExpired:
                    process.kill()
                print(f"[+] Killed process on port {port}")
                killed += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                print(f"[!] Failed to kill port {port}: {e}")
    
    print(f"\n[+] Successfully closed {killed} suspicious ports.")

def main():
    """Main function"""
    print_banner()
    
    try:
        # Get open ports
        open_ports = get_open_ports()
        display_ports(open_ports)
        
        if not open_ports:
            input("\nPress Enter to exit...")
            return
        
        # Interactive menu
        while True:
            print("\n" + "=" * 60)
            print("Options:")
            print("  1. Refresh port scan")
            print("  2. Kill specific port")
            print("  3. Kill ALL suspicious ports")
            print("  4. Exit")
            print("=" * 60)
            
            choice = input("\nEnter your choice (1-4): ").strip()
            
            if choice == '1':
                open_ports = get_open_ports()
                display_ports(open_ports)
                
            elif choice == '2':
                try:
                    port = int(input("Enter port number to kill: ").strip())
                    kill_port(port, open_ports)
                    # Refresh after killing
                    open_ports = get_open_ports()
                except ValueError:
                    print("[!] Invalid port number.")
                    
            elif choice == '3':
                kill_all_suspicious(open_ports)
                # Refresh after killing
                open_ports = get_open_ports()
                display_ports(open_ports)
                
            elif choice == '4':
                print("\n[*] Exiting Port Killer. Stay safe!")
                break
                
            else:
                print("[!] Invalid choice. Please select 1-4.")
                
    except KeyboardInterrupt:
        print("\n\n[*] Script interrupted by user. Exiting...")
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        import traceback
        traceback.print_exc()
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()

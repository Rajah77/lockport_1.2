import os
import psutil
import subprocess
import re
import time
import datetime
import json
import sys
import ctypes
import socket
import platform

RISKY_PORTS = [
    135, 139, 445, 593,
    
    22,     
    23,     
    3389,   
    5900,   
    5800,   
    5985,   
    5986,   
    
    1433,   
    1434,  
    3306,   
    5432,   
    1521,   
    
    161,    
    162,    
    389,    
    636,    
    25,     
    21,     
    
    7680,   
    50537, 50538, 54288,  
    
    137, 138
]

GAMING_PORTS = [
    3074,     
    27015,   
    27016,    
    3478,     
    3479,    
    3480,     
    88,       
    500,    
    3544,     
    11235,    
    
    27000, 27001, 27002, 27003, 27004, 27005, 27006, 27007, 27008, 27009,
    27010, 27011, 27012, 27013, 27014, 27015, 27016, 27017, 27018, 27019,
    27020, 27021, 27022, 27023, 27024, 27025, 27026, 27027, 27028, 27029,
    27030, 27031, 27032, 27033, 27034, 27035, 27036, 27037, 27038, 27039,
    
    50000, 50001, 50002, 50003, 50004, 50005,
    
    5222, 5795, 5222
]

CRITICAL_SERVICES = [
    "RpcEptMapper",  
    "DcomLaunch",   
    "wuauserv",      
    "BITS",          
    "cryptsvc",      
    "TrustedInstaller", 
    "WpnService",    
    "EventLog",      
    "MpsSvc",       
    "Schedule",     
    "PlugPlay",      
    "Power",        
    "WinDefend",     
    "XblAuthManager", 
    "XboxNetApiSvc",  
    "Dnscache",      
    "nsi",           
    "iphlpsvc",      
    "LanmanWorkstation" 
]

SYSTEM_CRITICAL_PROCESSES = [
    "svchost.exe", 
    "lsass.exe", 
    "services.exe", 
    "wininit.exe",
    "winlogon.exe",
    "csrss.exe",
    "smss.exe",
    "spoolsv.exe",
    "explorer.exe",
    "taskmgr.exe",
    "MsMpEng.exe",    
    "steam.exe",      
    "EpicGamesLauncher.exe", 
    "Battle.net.exe", 
    "Discord.exe",    
    "agent.exe",      
    "System"          
]

WHITELIST_IPS = [
    "127.0.0.1",      
    "224.0.0.0/4",    
    "239.255.255.250", 
    "255.255.255.255"  
]

ESSENTIAL_PORTS = [
    80,    
    443,   
    8530,  
    8531,  
    123,   
    53     
]

WINDOWS_SECURITY_PORTS = [135, 137, 138, 139, 445]

def log_message(message, level="INFO"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

def backup_current_firewall_settings():
    log_message("Creating backup of current firewall settings...", "BACKUP")
    backup_dir = os.path.join(os.environ['TEMP'], "portlock_backup")
    os.makedirs(backup_dir, exist_ok=True)
    
    backup_file = os.path.join(backup_dir, f"firewall_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.wfw")
    subprocess.run(
        f'netsh advfirewall export "{backup_file}"',
        shell=True, capture_output=True
    )
    
    services_data = {}
    for service in CRITICAL_SERVICES:
        result = subprocess.run(
            f'sc qc {service}', shell=True, capture_output=True, text=True
        )
        start_type = re.search(r'START_TYPE\s+:\s+(\d)', result.stdout)
        if start_type:
            services_data[service] = start_type.group(1)
    
    with open(os.path.join(backup_dir, "services_backup.json"), 'w') as f:
        json.dump(services_data, f)
    
    log_message(f"Backup created at {backup_file}", "BACKUP")
    return backup_file

def restore_firewall_settings(backup_file):
    if os.path.exists(backup_file):
        log_message(f"Restoring firewall settings from {backup_file}...", "RESTORE")
        subprocess.run(
            f'netsh advfirewall import "{backup_file}"',
            shell=True, capture_output=True
        )
        log_message("Firewall settings restored", "RESTORE")
        return True
    else:
        log_message(f"Backup file {backup_file} not found!", "ERROR")
        return False

def service_exists(service_name):
    result = subprocess.run(
        f'sc query {service_name}', 
        shell=True, capture_output=True, text=True
    )
    return "FAILED 1060" not in result.stderr and "The specified service does not exist" not in result.stdout

def find_processes_using_ports(ports):
    log_message("Checking for active processes using monitored ports...", "CHECK")
    port_pids = {}

    netstat_output = subprocess.run(
        ["netstat", "-ano"], capture_output=True, text=True
    ).stdout

    for port in ports:
        if port in GAMING_PORTS:
            continue
            
        pattern = rf':{port}\s+.*LISTENING\s+(\d+)'
        matches = re.findall(pattern, netstat_output)
        if matches:
            pids = list(set(matches))
            port_pids[port] = pids
            
            process_names = []
            for pid in pids:
                try:
                    proc = psutil.Process(int(pid))
                    process_names.append(f"{proc.name()} (PID: {pid})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_names.append(f"Unknown (PID: {pid})")
                    
            log_message(f"Port {port} is open and used by: {', '.join(process_names)}", "ALERT")

    return port_pids

def modify_service_startup(service_name, start_type):
    if not service_exists(service_name):
        log_message(f"Service {service_name} does not exist, skipping", "SERVICE")
        return False
        
    log_message(f"Setting service {service_name} startup type to {start_type}...", "SERVICE")
    result = subprocess.run(
        f'sc config {service_name} start= {start_type}',
        shell=True, capture_output=True, text=True
    )
    if "SUCCESS" in result.stdout or "[SC] ChangeServiceConfig SUCCESS" in result.stdout:
        log_message(f"Successfully configured {service_name}", "SERVICE")
        return True
    else:
        log_message(f"Failed to configure {service_name}: {result.stderr}", "ERROR")
        return False

def safely_manage_services():
    log_message("Configuring service startup types...", "SERVICE")
    
    services_to_modify = {
        "lanmanserver": "demand",      
        "lanmanworkstation": "auto",   
        "netbt": "demand",             
        "Browser": "disabled",         
        "RemoteRegistry": "disabled",  
        "TermService": "disabled",     
        "SessionEnv": "disabled",      
        "UmRdpService": "disabled",    
        "TlntSvr": "disabled",         
        "SshBroker": "disabled",       
        "ftpsvc": "disabled",          
        "SNMPTRAP": "disabled",        
        "MSSQLSERVER": "disabled"     
    }
    
    gaming_services = [
        "XblAuthManager",
        "XboxNetApiSvc",
        "XblGameSave",
        "BcastDVRUserService",
        "SteamClient",
        "EpicOnlineServices"
    ]
    
    for service, start_type in services_to_modify.items():
        if service not in CRITICAL_SERVICES and service not in gaming_services:
            modify_service_startup(service, start_type)
        else:
            log_message(f"Skipping critical/gaming service: {service}", "SERVICE")

def is_critical_process(pid):
    try:
        proc = psutil.Process(int(pid))
        process_name = proc.name().lower()
        
        for critical in SYSTEM_CRITICAL_PROCESSES:
            if critical.lower() in process_name:
                return True
            
        if int(pid) == 4:
            return True
            
        if any(game_keyword in process_name for game_keyword in ["game", "play", "steam", "epic", "battle", "riot", "minecraft", "launcher"]):
            log_message(f"Identified possible game process: {process_name}", "GAME")
            return True
            
        return False
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return True  # If we can't check, assume it's critical for safety

def safely_manage_processes(port_pids):
    log_message("Managing processes using risky ports...", "PROCESS")
    
    for port, pids in port_pids.items():
        if port in ESSENTIAL_PORTS or port in GAMING_PORTS:
            log_message(f"Skipping essential/gaming port {port}", "PROCESS")
            continue
            
        if port in WINDOWS_SECURITY_PORTS:
            log_message(f"Skipping Windows security port {port} - will secure via firewall", "PROCESS")
            continue
            
        for pid in pids:
            if is_critical_process(pid):
                try:
                    proc = psutil.Process(int(pid))
                    log_message(f"Skipping critical process {proc.name()} (PID: {pid}) on port {port}", "PROCESS")
                except:
                    log_message(f"Skipping unknown critical process with PID {pid}", "PROCESS")
                continue

            try:
                proc = psutil.Process(int(pid))
                proc_name = proc.name()
                log_message(f"Terminating process {proc_name} (PID: {pid}) using port {port}...", "PROCESS")
                proc.terminate()
                gone, alive = psutil.wait_procs([proc], timeout=3)
                if proc in alive:
                    log_message(f"Process {proc_name} did not terminate gracefully, forcing...", "WARNING")
                    proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                log_message(f"Could not terminate process {pid} - Access denied or process not found", "ERROR")

def secure_firewall():
    log_message("Configuring Windows Firewall for enhanced security...", "FIREWALL")
    
    subprocess.run(
        'netsh advfirewall set allprofiles state on',
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    
    subprocess.run(
        'netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound',
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    
    for port in RISKY_PORTS:
        subprocess.run(
            f'netsh advfirewall firewall delete rule name="PortLock Block TCP {port}"',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            f'netsh advfirewall firewall delete rule name="PortLock Block UDP {port}"',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    
    for port in RISKY_PORTS:
        if port not in ESSENTIAL_PORTS and port not in GAMING_PORTS:
            if port in WINDOWS_SECURITY_PORTS:
                secure_windows_port(port)
            else:
                log_message(f"Blocking port {port} TCP and UDP...", "FIREWALL")
                subprocess.run(
                    f'netsh advfirewall firewall add rule name="PortLock Block TCP {port}" '
                    f'dir=in action=block protocol=TCP localport={port}',
                    shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                subprocess.run(
                    f'netsh advfirewall firewall add rule name="PortLock Block UDP {port}" '
                    f'dir=in action=block protocol=UDP localport={port}',
                    shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
        else:
            log_message(f"Skipping essential/gaming port {port}", "FIREWALL")
    
    log_message("Creating rules for Windows Update and essential services...", "FIREWALL")
    for port in ESSENTIAL_PORTS:
        subprocess.run(
            f'netsh advfirewall firewall add rule name="PortLock Allow Essential TCP {port}" '
            f'dir=in action=allow protocol=TCP localport={port}',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            f'netsh advfirewall firewall add rule name="PortLock Allow Essential UDP {port}" '
            f'dir=in action=allow protocol=UDP localport={port}',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    
    log_message("Creating rules for online gaming...", "FIREWALL")
    for port in GAMING_PORTS:
        subprocess.run(
            f'netsh advfirewall firewall add rule name="PortLock Allow Gaming TCP {port}" '
            f'dir=in action=allow protocol=TCP localport={port}',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            f'netsh advfirewall firewall add rule name="PortLock Allow Gaming UDP {port}" '
            f'dir=in action=allow protocol=UDP localport={port}',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    
    for ip in WHITELIST_IPS:
        log_message(f"Whitelisting IP: {ip}", "FIREWALL")
        subprocess.run(
            f'netsh advfirewall firewall add rule name="PortLock Allow {ip}" '
            f'dir=in action=allow remoteip={ip}',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    
    log_message("Creating rules for game executables...", "FIREWALL")
    
    game_paths = [
        "%ProgramFiles(x86)%\\Steam",
        "%ProgramFiles(x86)%\\Epic Games",
        "%ProgramFiles(x86)%\\Battle.net",
        "%ProgramFiles(x86)%\\Riot Games",
        "%ProgramFiles(x86)%\\Origin",
        "%ProgramFiles(x86)%\\Ubisoft",
        "%ProgramFiles(x86)%\\Steam\\steamapps\\common",
        "%ProgramFiles%\\Epic Games"
    ]
    
    user_dirs = ["Documents", "Downloads", "Desktop", "Games"]
    for user_dir in user_dirs:
        user_path = os.path.join(os.environ['USERPROFILE'], user_dir)
        if os.path.exists(user_path):
            game_paths.append(user_path)
    
    game_executables = []
    for path in game_paths:
        game_executables.append(f"{path}\\*.exe")
    
    for i, exe_path in enumerate(game_executables):
        subprocess.run(
            f'netsh advfirewall firewall add rule name="PortLock Allow Game Exe {i}" '
            f'dir=in action=allow program="{exe_path}" enable=yes profile=any',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            f'netsh advfirewall firewall add rule name="PortLock Allow Game Exe Out {i}" '
            f'dir=out action=allow program="{exe_path}" enable=yes profile=any',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

def secure_windows_port(port):
    log_message(f"Securing Windows security port {port} with restrictions...", "SECURITY")
    
    hostname = socket.gethostname()
    local_ips = []
    
    try:
        local_ips.append(socket.gethostbyname(hostname))
    except:
        pass
        
    try:
        for ip in socket.gethostbyname_ex(hostname)[2]:
            local_ips.append(ip)
    except:
        pass
    
    if "127.0.0.1" not in local_ips:
        local_ips.append("127.0.0.1")
    
    subnet = "LocalSubnet"
    
    subprocess.run(
        f'netsh advfirewall firewall delete rule name="PortLock Security {port}"',
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    
    local_ips_str = ",".join(local_ips)
    
    if port == 135:
        subprocess.run(
            f'netsh advfirewall firewall add rule name="PortLock Security {port}" '
            f'dir=in action=allow protocol=TCP localport={port} remoteip={local_ips_str},{subnet}',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            f'netsh advfirewall firewall add rule name="PortLock Block External {port}" '
            f'dir=in action=block protocol=TCP localport={port} remoteip=any',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    
    elif port in [137, 138, 139, 445]:
        subprocess.run(
            f'netsh advfirewall firewall add rule name="PortLock Security {port}" '
            f'dir=in action=allow protocol=TCP localport={port} remoteip={local_ips_str},{subnet}',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            f'netsh advfirewall firewall add rule name="PortLock Security UDP {port}" '
            f'dir=in action=allow protocol=UDP localport={port} remoteip={local_ips_str},{subnet}',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            f'netsh advfirewall firewall add rule name="PortLock Block External {port}" '
            f'dir=in action=block protocol=TCP localport={port} remoteip=any',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            f'netsh advfirewall firewall add rule name="PortLock Block External UDP {port}" '
            f'dir=in action=block protocol=UDP localport={port} remoteip=any',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

def verify_ports_status():
    log_message("Verifying port status after changes...", "VERIFY")
    time.sleep(3) 
    
    netstat_output = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
    
    for port in RISKY_PORTS:
        if f":{port}" in netstat_output:
            if port in ESSENTIAL_PORTS:
                log_message(f"Port {port} is open (essential service port)", "VERIFY")
            elif port in GAMING_PORTS:
                log_message(f"Port {port} is open (gaming port)", "VERIFY")
            elif port in WINDOWS_SECURITY_PORTS:
                log_message(f"Port {port} is open but restricted to local access (Windows security port)", "VERIFY")
            else:
                log_message(f"Port {port} is still open! Further investigation needed", "WARNING")
        else:
            log_message(f"Port {port} is successfully closed", "VERIFY")

def create_restore_script(backup_file):
    restore_script = os.path.join(os.environ['USERPROFILE'], "Desktop", "PortLock_Restore.bat")
    
    with open(restore_script, 'w') as f:
        f.write("@echo off\n")
        f.write("echo PortLock Windows Security - Restore Utility\n")
        f.write("echo --------------------------------------\n")
        f.write("echo This will restore your system to its previous state.\n")
        f.write("echo.\n")
        f.write("echo Restoring Firewall Settings...\n")
        f.write(f'netsh advfirewall import "{backup_file}"\n')
        f.write("echo.\n")
        f.write("echo Re-enabling services...\n")
        
        for service in CRITICAL_SERVICES:
            f.write(f'sc config {service} start= auto\n')
            f.write(f'sc start {service}\n')
        
        f.write("echo.\n")
        f.write("echo System restored to previous state.\n")
        f.write("echo If you continue to experience issues, you may need to restart your computer.\n")
        f.write("pause\n")
    
    log_message(f"Restore script created at {restore_script}", "RESTORE")
    log_message("If your system experiences issues, run this script to restore settings", "RESTORE")
    
    os.chmod(restore_script, 0o755)

def add_advanced_protections():
    log_message("Adding advanced security protections...", "ADVANCED")
    
    log_message("Disabling vulnerable SMBv1 protocol...", "ADVANCED")
    try:
        subprocess.run(
            'sc config lanmanworkstation depend= bowser/mrxsmb20/nsi',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            'sc config mrxsmb10 start= disabled',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except:
        log_message("Could not disable SMBv1 - may already be disabled", "WARNING")
    
    log_message("Disabling LLMNR to prevent poisoning attacks...", "ADVANCED")
    try:
        subprocess.run(
            'reg add "HKLM\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient" /v "EnableMulticast" /t REG_DWORD /d "0" /f',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except:
        log_message("Could not disable LLMNR via registry", "WARNING")
    
    log_message("Disabling NetBIOS over TCP/IP on network adapters...", "ADVANCED")
    try:
        network_interfaces = subprocess.run(
            'wmic nicconfig get index', 
            shell=True, capture_output=True, text=True
        ).stdout
        
        indexes = re.findall(r'\d+', network_interfaces)
        
        for index in indexes:
            if index.strip():
                subprocess.run(
                    f'wmic nicconfig where index={index} call SetTcpipNetbios 2',
                    shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
    except:
        try:
            subprocess.run(
                'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters" /v "NetbiosOptions" /t REG_DWORD /d "2" /f',
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except:
            log_message("Could not disable NetBIOS over TCP/IP", "WARNING")
    
    log_message("Setting NTLMv2 security policy...", "ADVANCED")
    try:
        subprocess.run(
            'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v "LmCompatibilityLevel" /t REG_DWORD /d "5" /f',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except:
        log_message("Could not set NTLM security policy", "WARNING")
    
    log_message("Blocking suspicious outbound connections...", "ADVANCED")
    suspicious_ips = [
        "185.125.190.0/24",
        "192.168.33.0/24",   
        "45.32.0.0/16"       
    ]
    
    for ip in suspicious_ips:
        subprocess.run(
            f'netsh advfirewall firewall add rule name="PortLock Block Suspicious {ip}" '
            f'dir=out action=block remoteip={ip}',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    
    log_message("Blocking cryptomining ports...", "ADVANCED")
    mining_ports = [3333, 3334, 3335, 3336, 4444, 5555, 6666, 7777, 8888, 9999, 14444, 14433]
    
    for port in mining_ports:
        subprocess.run(
            f'netsh advfirewall firewall add rule name="PortLock Block Mining TCP {port}" '
            f'dir=out action=block protocol=TCP localport={port}',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            f'netsh advfirewall firewall add rule name="PortLock Block Mining UDP {port}" '
            f'dir=out action=block protocol=UDP localport={port}',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    
    log_message("Ensuring UAC is enabled...", "ADVANCED")
    try:
        subprocess.run(
            'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v "EnableLUA" /t REG_DWORD /d "1" /f',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except:
        log_message("Could not enable UAC", "WARNING")
    
    log_message("Advanced protections applied", "ADVANCED")

def create_security_report():
    log_message("Generating security report...", "REPORT")
    
    report_file = os.path.join(os.environ['USERPROFILE'], "Desktop", "PortLock_Security_Report.txt")
    
    with open(report_file, 'w') as f:
        f.write("PortLock Windows Security Report\n")
        f.write("==============================\n\n")
        f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Computer Name: {platform.node()}\n")
        f.write(f"Windows Version: {platform.platform()}\n\n")
        
        f.write("Security Measures Applied:\n")
        f.write("------------------------\n")
        f.write("1. Windows Firewall enabled and configured\n")
        f.write("2. Restricted high-risk ports\n")
        f.write("3. Disabled vulnerable protocols (SMBv1, LLMNR, NetBIOS over TCP/IP)\n")
        f.write("4. Secured Windows networking ports (135, 139, 445, etc.)\n")
        f.write("5. Blocked suspicious outbound connections\n")
        f.write("6. Set NTLMv2 security policy\n")
        f.write("7. Disabled unnecessary services\n\n")
        
        f.write("Gaming Compatibility:\n")
        f.write("--------------------\n")
        f.write("* All gaming ports allowed (Steam, Epic Games, Xbox, etc.)\n")
        f.write("* Game executables whitelisted in firewall\n")
        f.write("* Gaming services preserved\n\n")
        
        f.write("Windows Update Compatibility:\n")
        f.write("--------------------------\n")
        f.write("* All Windows Update services preserved\n")
        f.write("* Update ports (80, 443, 8530, 8531) allowed\n\n")
        
        f.write("Known Issues:\n")
        f.write("------------\n")
        f.write("* Some Windows security ports (135, 139, 445) remain open but are restricted to local network\n")
        f.write("* Remote desktop connections are blocked\n")
        f.write("* File sharing with external networks may be limited\n\n")
        
        f.write("Recovery:\n")
        f.write("--------\n")
        f.write("If you experience any issues, run the PortLock_Restore.bat file on your desktop\n")
    
    log_message(f"Security report created at {report_file}", "REPORT")

def main():
    log_message("=== PortLock Windows Security Tool - Ultimate Edition ===", "START")
    log_message("This tool will secure your Windows system while preserving gaming functionality", "INFO")
    
    backup_file = backup_current_firewall_settings()
    
    try:
        port_pids = find_processes_using_ports(RISKY_PORTS)
        
        safely_manage_services()
        
        if port_pids:
            safely_manage_processes(port_pids)
        else:
            log_message("No suspicious processes found using monitored ports", "CHECK")
        
        secure_firewall()
        
        add_advanced_protections()
        
        verify_ports_status()
        
        create_restore_script(backup_file)
        
        create_security_report()
        
        log_message("Security hardening completed successfully!", "COMPLETE")
        log_message("Your system is now protected while maintaining gaming functionality", "COMPLETE")
        log_message("Windows updates will continue to work normally", "COMPLETE")
        
    except Exception as e:
        log_message(f"An error occurred: {str(e)}", "ERROR")
        log_message("Attempting to restore previous settings...", "RECOVERY")
        restore_firewall_settings(backup_file)
        log_message("Please check system functionality", "RECOVERY")

if __name__ == "__main__":
    try:
        if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
            log_message("This script requires administrator privileges", "ERROR")
            log_message("Please run as administrator", "ERROR")
            sys.exit(1)
    except:
        pass
        
    main()
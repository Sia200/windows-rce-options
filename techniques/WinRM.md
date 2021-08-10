Table of Contents
=================

* [WinRM (Technique)](#winrm-technique)
   * [Summary](#summary)
   * [How it works (deeply)](#how-it-works-deeply)
   * [Requirements](#requirements)
   * [Logs](#logs)
      * [Security Logs](#security-logs)
      * [Sysmon Logs](#sysmon-logs)
      * [PowerShell Logs](#powershell-logs)
      * [Windows Remote Management Logs](#windows-remote-management-logs)
   * [Remarks](#remarks)
   * [Implementations](#implementations)
   * [References](#references)


WinRM (Technique)
============

## Summary

WinRM allows administrators to perform management tasks on systems
remotely. Communication is performed via HTTP (5985) or HTTPS SOAP
(5986) and support Kerberos and NTLM authentication by default and
Basic authentication.

## How it works (deeply)

...

## Requirements

1. WinRM service has to be enabled
```bash
Test-WSMan
Get-Service WinRM

# Check remotely
Test-WSMan -ComputerName <TARGET_IP>
```

2. WinRM port has to be accessible (through firewall)
```bash
nmap -Pn -n -p 5985,5986 <TARGET_IP>
```
3. Administrator permissions on the target machine

4. Remote UAC (UAC Over network) disabled if the user chosen to
authenticate with is a **local user** and not a domain user
```bash
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1
# Restart the 'Server' service might be required (I have tested twice on a Windows 10 and it **was not** required)
```

## Logs

#### Security Logs

- 4624, Logon event - Network Logon, Type 3
- 4672, Special Logon (If the user is Administrator)

#### Sysmon Logs

- 3, Network connection detected - from the "attacker" source IP
- 1, Process create - `wsmprovhost.exe` is created by `svchost.exe -k DcomLaunch -p`
- 11, File created - `wsmprovhost.exe` creates a `.ps1` and a `.psm1`
files at `C:\Users\%USERNAME%\AppData\Local\Temp`
- 17, Pipe Created - `wsmprovhost.exe` creates a pipe
- 10, Process accessed - Mcafee accesses the `wsmprovhost.exe`
process and creates a remote thread in it (event id 8)

#### PowerShell Logs

- 53504, PowerShell Named Pipe IPC
- 4102, Executing Pipeline

#### Windows Remote Management Logs

- 91, Request handling

## Remarks

* NTLM-based authentication is disabled by default, but may be
permitted by either configuring SSL on the target server, or by
configuring the WinRM TrustedHosts setting on the client.
* When connecting over HTTPS, the TLS protocol is used to negotiate
the encryption used to transport data. When connecting over HTTP,
message-level encryption is determined by initial authentication
protocol used.
* When using `Invoke-Command` with an IP Address instead of computer
name, the transport has to be HTTPS, or the remote IP has to be in
TrustedHosts list.
* When using `Invoke-Command` the executed powershell commands are
logged in the history of the 'attacker' machine and not in the target
machine.
* It's easy to modify the WinRM configuration with `Set-Item` or the
`winrm.vbs` helper file. For example, modify the listening port the
WinRM server listens on:
```bash
winrm set winrm/config/Listener?Address=*+Transport=HTTP '@{Port="8080"}'
# OR
Set-Item WSMan:\localhost\Listener\*\Port 8080 -Force
```

## Implementations

- [Invoke-Command](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command?view=powershell-7.1) (Powershell Cmdlet)
```bash
Invoke-Command -ComputerName <TARGET_COMPUTERNAME> -ScriptBlock { Get-NetAdapter }

# OR

Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force
Invoke-Command -ComputerName <TARGET_IP> -Credential "DOMAIN\USER" -ScriptBlock { Get-NetAdapter }
```
- [pywinrm](https://github.com/diyan/pywinrm)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm)
```bash
./evil-winrm.rb -i <TARGET_IP> -u DOMAIN\\USER
```
- [winrm](https://github.com/masterzen/winrm) (GO library and cli)

## References

- https://stackoverflow.com/questions/21548566/how-to-add-more-than-one-machine-to-the-trusted-hosts-list-using-winrm/31378248
- https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_troubleshooting?view=powershell-7.1#how-to-add-a-computer-to-the-trusted-hosts-list
- https://docs.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management
- https://www.fireeye.com/content/dam/fireeye-www/global/en/solutions/pdfs/wp-lazanciyan-investigating-powershell-attacks.pdf

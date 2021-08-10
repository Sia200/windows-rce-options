Table of Contents
=================

* [WmiExec (Technique)](#wmiexec-technique)
   * [Summary](#summary)
   * [How it works (deeply)](#how-it-works-deeply)
   * [Requirements](#requirements)
   * [Logs](#logs)
      * [Security Logs](#security-logs)
      * [Sysmon Logs](#sysmon-logs)
      * [Wmi-Activity Logs](#wmi-activity-logs)
   * [Remarks](#remarks)
   * [Implementations](#implementations)
   * [References](#references)


WmiExec (Technique)
============

## Summary

Executing code through WMI classes, for instance Win32_Process
'Create' method (RPC). Code  runs under the user account and not 
SYSTEM.

## How it works (deeply)

...

## Requirements

1. RPC is running
	```bash
	Get-Service RpcSs,RpcEptMapper,DcomLaunch
	```

2. RPC and high ports are accessible (through firewall)

3. Administrator (by default has all permissions) **or**, a user in
the 'Distributed COM Users' and the 'Remote Enable' permission under
the `root\cimv2` namespace for 'Win32_Process'

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

- 1, Process Create, `WmiPrvSE.exe` is the parent image, full 
commandline is visible
- 10, Process Access, from McAfee

#### Wmi-Activity Logs

> Note that Wmi-Activity logs are **not** traced by default

- 11, WbemServices::Connect, authenticated username and copmuter name
are logged
- 11, WbemService::ExecMethod, class name and method name are logged
- 22, Method execution log
- 13, Method execution log, arguments are logged (full commandline
for Win32_Process)

## Remarks

* `Invoke-WmiMethod` fails with `Access is denied (HRESULT:
0x80070005)` if the authenticated user is not in the 'Distributed COM
Users' group.
* `Invoke-WmiMethod` failes with `Access denied
(ManagementException)` if the authenticated user does not have the
`Remote Enable` permission on the namespace.
* While it's most common to acheive remote code execution via the
Win32_Process class, it's also possible to acheive it with the
following classes:
	- Win32_Service, Win32_BaseService, Win32_TerminalService, Win32_SystemDriver
	- Win32_ScheduledJob, PS_ScheduledTask
	- Win32_Product

## Implementations

* [Invoke-WmiMethod](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/invoke-wmimethod?view=powershell-5.1) (Powershell Cmdlet)
	```bash
	Invoke-WmiMethod -ComputerName <TARGET_IP> -Class Win32_Process -Name Create -ArgumentList "powershell.exe -NoLogo -NonInteractive -WindowStyle Hidden echo hello > C:\hello.txt"
	```
* [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py) (Impacket)
* [WmiExec](https://github.com/OneScripter) (Powershell)
* [Invoke-WmiExec.ps1](https://github.com/Kevin-Robertson/Invoke-TheHash) (Powershell)

## References

* https://docs.microsoft.com/en-us/windows/win32/wmisdk/connecting-to-wmi-remotely-starting-with-vista
* https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-process
* https://docs.microsoft.com/en-us/windows/win32/wmisdk/setting-namespace-security-with-the-wmi-control
* https://www.cybereason.com/blog/wmi-lateral-movement-win32
* https://docs.microsoft.com/en-us/windows/win32/wmisdk/tracing-wmi-activity
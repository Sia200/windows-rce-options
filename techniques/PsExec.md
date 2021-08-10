Table of Contents
=================

* [PsExec (Technique)](#psexec-technique)
   * [Summary](#summary)
   * [How it works (deeply)](#how-it-works-deeply)
   * [Requirements](#requirements)
   * [Logs](#logs)
      * [Security Logs](#security-logs)
      * [System Logs](#system-logs)
      * [Sysmon Logs](#sysmon-logs)
   * [Remarks](#remarks)
   * [Implementations](#implementations)
   * [Links](#links)

PsExec (Technique)
============

## Summary

Copies a binary to a writable target machine's share (ADMIN$) and
creates a service remotely to run that binary. Then, just start it
remotely. Redirection of the input/output of the process goes back
and forth between the endpoints via named pipes.

## How it works (deeply)

1. SMB authentication (NTLM / Kerberos) and setup
2. Open SMB tree connection (connection to a share)
3. File request with write access
4. Write the remote PsExec executable
5. *something with RPC...*
6. Close request file
7. Close tree connection
8. Disconnect from SMB session
9. SMB authentication (NTLM / Kerberos) and setup
10. Request file to svcctl


...


## Requirements

1. SMB server is running on the target machine

Detect SMB1 & SMB2:
```bash
Get-SmbServerConfiguration | Select EnableSMB*
```

Detect SMB1 (requires elevation):
```bash
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```

The Windows features window can also be used to check if the feature
is enabled or not.

2. SMB is accessible

```bash
nmap -Pn -n -p 445 <TARGET>

# Version scan
nmap -p 445 --script smb-protocols <TARGET>
```

3. Permissions to a writable share

4. Permissions to access SCM remotely (by default only for
Administrators)

A check for permissions could be `sc.exe \\DESKTOP-TARGET query`

5. Remote UAC (UAC Over network) disabled if the user chosen to
authenticate with is a **local user** and not a domain user
```bash
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1
# Restart the 'Server' service might be required (I have tested twice on a Windows 10 and it **was not** required)
```

## Logs

#### Security Logs

- 4624, Logon event - Network Logon, Type 3
- 4672, Special Logon (If the user is Administrator)

#### System Logs

- 7045, SCM - A service was installed in the system

#### Sysmon Logs

- 1, Process create - The Psexec.exe executable and the executable
chosen to run
- 3, Network connection detected - from the "attacker" source IP
- 11, File created - The PsExec.exe / PAExec.exe
- 13, Registry value set - from the creation of the service
- 17-18, Pipe created & Pipe connected - redirection of stdout, stdin
and stderr via named pipes

## Remarks

* Permissions for the remote SCM are by default only to memebers of
the local Administrators group. It is [possible](http://woshub.com/granting-remote-access-on-scmanager-to-non-admin-users/)
to edit the members who have this permissions.
* For some reason, `PsExec.exe` tries to communicate with the remote
machine using RPC (port 135) right before starting the service.
It tries to do it firstly using RPC (port 135 and  high
ports). Weather it failes or not, progress is continued with SMB.
* `PsExec.exe` communicates with SMB2 unencrypted channel.
* `psexec.py` (impacket) does everything with SMB (port 445) and uses
SMB3 encrypted channel.
* `Paexec.exe` (PA) does everything with SMB (port 445) and uses
SMB2 unencrypted channel.
* If PsExec (Sysinternals) is provided with wrong credentials, the
process will try to authenticate with the user owning the process
context.
* Usage of the technique from a mimikatz `sekurlsa::pth` shell is
recommended in order to prevent possible errors and unwanted ntlmssp
packets from the attacker machine.

## Implementations

- [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) (Sysinternals)
- [PAExec](https://github.com/poweradminllc/PAExec) (Open Source C++)
- [CSExec](https://github.com/malcomvetter/CSExec) (Open Source C#)
- [psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) (Impacket)
- [Invoke-Psexec](https://gist.github.com/HarmJ0y/c84065c0c487d4c74cc1) (Powershell)

## References

- https://www.contextis.com/en/blog/lateral-movement-a-deep-look-into-psexec
- https://github.com/SecureAuthCorp/impacket
- https://help.pdq.com/hc/en-us/articles/220533007-Can-t-access-ADMIN-share-using-a-local-user-or-LAPS-account
- https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw
- http://woshub.com/granting-remote-access-on-scmanager-to-non-admin-users/

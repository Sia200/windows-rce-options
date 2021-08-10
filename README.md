# Windows RCE Techniques

Windows comes with builtin services and features which allows to 
execute code from remote machines.
This repo lists every option and documents the following topics:

- Summary
- How the technique works
- Requirements
- Logs left behind
- Implementations
- References

Logs will be searched in:

- Windows event logs 'Security' and 'System'
- Sysmon event logs
- Wmi-Activity event logs
- TaskSchedular event logs
- Powershell logs
- Windows Remote Management logs
- Mcafee ENS "Event Log" tab

> JPCERTCC [documented](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
event logs that are created from tools using techniques documented in
this repoistory.

> sbousseaden [documented](https://github.com/sbousseaden) .evtx
files and .pcap files that are created from using the techniques
documented in this repository.

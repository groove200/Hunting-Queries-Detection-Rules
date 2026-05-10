# Outbound MSHTA Connection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1218.005 | System Binary Proxy Execution: Mshta | https://attack.mitre.org/techniques/T1218/005/ |

#### Description
Detects outbound network connections initiated by `mshta.exe`. `mshta.exe` is a legitimate Windows binary, but it is frequently abused by adversaries to execute malicious script content from local or remote HTA resources.

This query helps identify suspicious executions.

It is recommended to investigate if you can block mshta in your organization, if not possible use auto isolation rules for suspicious outbound mshta connections.

#### Risk
Adversaries often abuse the lolbin mshta as malware droppers.

#### References
- https://redcanary.com/threat-detection-report/techniques/mshta/

## Defender XDR
```KQL
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "mshta.exe"
| where RemoteIPType == "Public" or not(ipv4_is_private(RemoteIP))
| project-reorder Timestamp, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, DeviceName, InitiatingProcessAccountUpn
```

## Sentinel
```KQL
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "mshta.exe"
| where RemoteIPType == "Public" or not(ipv4_is_private(RemoteIP))
| project-reorder TimeGenerated, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, DeviceName, InitiatingProcessAccountUpn
```

## Objective
Identify Device which received huge volume of ACK or SYN Flood. Then Filter out the CIDR associated with the unsuccessful connection attempts to our endpoint device.

## Detection Rule
<pre>
let CIDRASN =
    externaldata (CIDR:string, CIDRASN:int, CIDRASNName:string)
    ['https://firewalliplists.gypthecat.com/lists/kusto/kusto-cidr-asn.csv.zip']
    with (ignoreFirstRecord=true);
let TargetDevice =
DeviceNetworkEvents
| where tostring(todynamic(AdditionalFields).direction) has "In"
| extend TCPFlags = toint(todynamic(AdditionalFields)["Tcp Flags"])
| extend
    FIN = iif(TCPFlags % 2 >= 1, 1, 0),
    SYN = iif(TCPFlags % 4 >= 2, 1, 0),
    RST = iif(TCPFlags % 8 >= 4, 1, 0),
    PSH = iif(TCPFlags % 16 >= 8, 1, 0),
    ACK = iif(TCPFlags % 32 >= 16, 1, 0),
    URG = iif(TCPFlags % 64 >= 32, 1, 0)
| summarize
    FIN = sum(FIN),
    SYN = sum(SYN),
    RST = sum(RST),
    PSH = sum(PSH),
    ACK = sum(ACK),
    URG = sum(URG)
    by DeviceId
| where (FIN > 0 or RST > 0 or PSH > 0 or URG > 0 or SYN > 100 or ACK > 100)
    and (todouble(ACK) / SYN < 0.2 or todouble(SYN) / ACK < 0.2);
DeviceNetworkEvents
| lookup TargetDevice on DeviceId
| where isnotempty(FIN)
| evaluate ipv4_lookup(CIDRASN, RemoteIP, CIDR, return_unmatched=true)
| summarize
    Timestamp=max(TimeGenerated),
    ReportId=any(ReportId),
    Success_Connections = countif(ActionType == "ConnectionSuccess"),
    Attempts_Connections = countif(ActionType in ("ConnectionAttempt", "ConnectionFailed")),
    Totalconnection = count(),
    IpCount=count_distinct(RemoteIP),
    RemoteIPs = make_set(RemoteIP)
    by DeviceId, CIDR
| where todouble(Success_Connections) / Totalconnection < 0.05
    and Attempts_Connections >= 100
</pre>

## Playbook

### Overview

Large volume of unsuccessful attempted connection to the Device.

### Issue to be solved

Threat actors usually send large volume of network traffic to block the server or device from responding to normal user requests. Also, they might want to know if any vulnerable services are running in the system by conducting port scanning on the devices. 

### Resolve Process

- Check for the CIDR and IPs associated with the attempted connection.
    - Go on with tracing IP related info if these is few IPs with high connection attempts.
    - If these is large no. of IPs associated with the incident, go with CIDR for tracing.
- Using third-party tools like AbuseipDb, URLhaus, Virustotal to check if they are associated with any malicious activities. We can also look into Source Mac ID to see if it is a virtual machine.
- In the advance hunting, check the Network events of those IPs or CIDR.
    - Check if they are targeting particular ports.
    - Check if there is no successful connection to the device.

### Conclusion

Activity is malicious?

- Given there is large volume of  unsuccessful connection from that ip or CIDR to any of our devices, we could just add that ip or domain to Endpoints IOC blocklist to relieve some network congestion stress to our devices.
Path: **System → Settings → Endpoints → Indicators**

_**Reference:**_
- https://detect.fyi/identifying-potential-ddos-cases-based-on-asn-with-kql-queries-f3878ab5178f
- https://detect.fyi/threat-hunting-via-autonomous-system-numbers-asn-99e038df235a

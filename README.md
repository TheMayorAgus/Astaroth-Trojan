# Astaroth-Trojan
Malware Analysis 

Title: Malware Analysis Report: Suspicious Trojan Embedded in .HTA File
Investigator: TheMayorAgusS
Date: March 12


---

1. Executive Summary

On March 12, a phishing email was received, prompting the download of a .zip file. After extraction, the archive contained a suspicious .hta (HTML Application) file, which was identified as a potential Trojan. Initial analysis indicated that the file was attempting to communicate with external servers, likely for malicious purposes such as remote code execution, data exfiltration, or payload delivery.


---

2. Identification

2.1 Filename, File Size, File Type

Filename: 𝔸𝔻𝕁𝕌ℕ𝕋𝕆𝕊𝟙𝟛𝟘𝟛𝟚𝟘𝟚𝟝_⑥⑨④⑥①③④.zip 

File Size: 355 KiB

Filename: 𝔸𝔻𝕁𝕌ℕ𝕋𝕆𝕊𝟙𝟛𝟘𝟛𝟚𝟘𝟚𝟝_②⑥⑦⑤④④②.hta

File Size: 15 KiB

File Type: .HTA (HTML Application)


2.2 MAC Timestamps

Created: [Timestamp]

Modified: [Timestamp]

Accessed: [Timestamp]


2.3 Hashes (md5, sha1, sha256, fuzzy)

MD5: a75de3037e093237720d26686ab34a6c

SHA1: f32dc39e38a00b53858ca6684a6e9aca0666cde5

SHA256: 26fd30238def54fafb44a094b17abaf1cfa24f5b85f78abe59b2638e4dcd3931

2.4 Signing Information (Certificates)

No digital signature detected.


2.5 TrID - Packer Info

The file was identified as an HTA file and contains obfuscated JavaScript code.


2.6 Aliases

No aliases found.



---

3. Capabilities

Remote code execution: The .hta file contains embedded JavaScript that may attempt to execute malicious code on the infected system.

Data exfiltration: The embedded JavaScript is capable of browser exploitation and possibly stealing sensitive information.

Command and Control (C2): The file attempts to establish a connection to a remote server, which could indicate potential C2 communication.



---

4. Dependencies

Browser exploitation: The payload seems dependent on a browser's vulnerability to execute JavaScript for exploitation.



---

5. Static Analysis

5.1 Top-level Components

The .hta file embeds JavaScript code that is executed upon opening the file.

The code attempts to make outbound connections to external URLs.


5.2 Execution Points of Entry

Upon opening the .hta file, the embedded JavaScript code executes, potentially triggering the exploit.


5.3 Embedded Strings

The file contains URLs that link to external servers hosting JavaScript files.


5.4 Code-Related Observations (Reflection, Obfuscation, Encryption, Native Code, etc.)

Obfuscation: The JavaScript code is obfuscated, making it difficult to read or understand without deobfuscating.

Remote code execution: The JavaScript aims to load a script from an external server to further the attack.


5.5 File Contents

5.5.1 Package Contents

The .zip archive contains the .hta file and possibly other benign-looking documents to lure the victim.


5.5.2 Files Created/Deployed on the System

No files were explicitly created or deployed during this analysis.



---

6. Dynamic Analysis

6.1 Network Traffic Analysis

6.1.1 DNS Queries

No DNS queries were observed during the analysis.


6.1.2 HTTP Conversations

Suspicious URLs:

1. https://club-ui-static-files.cb.hotmart.com/meteor/604ed2842c197920578701b6fa2f55458cd23ec1c55b4.js: Returns "NoSuchKey" error.


2. https://168.40.167.72.host.secureserver.net/cgi/nq8FAvNkE/LAisCpJezqO.js: Contains obfuscated JavaScript.




6.1.3 TCP/UDP Communication

Outbound connection detected to IP 168.40.167.72 over port 443, likely indicating an attempt to contact a remote server for further malicious activity.


6.2 File Operations (Files Read and Written)

No new files were written to the system during dynamic analysis.


6.3 Services/Processes Started

No new services or processes were detected.


6.4 Data Leaked

Based on the analysis, there are indications that the file could be attempting to exfiltrate data, though no explicit leakage was observed during this analysis.



---

7. Supporting Data

7.1 Log Files

Logs captured from the tcpdump packet capture are available for further analysis.


7.2 Network Traces

Packet capture data (pcap file) shows outbound connection attempts to the suspicious IP address.


7.3 Screenshots




7.4 Other Data (Database Dumps, Config Files, etc.)




---

8. Conclusion

The .HTA file functions as a potential Trojan loader, using obfuscated JavaScript to facilitate remote code execution and establish a potential C2 connection. The analysis has confirmed that the file attempts to communicate with an external server, likely to download additional payloads or exfiltrate sensitive information. This incident highlights the importance of phishing detection, network monitoring, and the need for further inspection of suspicious files.


---

#!/usr/bin/env python3
"""Write batch 034-040 extractions to extractions.jsonl"""
import json

extractions = [
    {"article_id": 3245, "source": "cisco_talos", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3246, "source": "cisco_talos", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3264, "source": "cisco_talos", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3271, "source": "cisco_talos", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3290, "source": "cisco_talos", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3295, "source": "cisco_talos", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3302, "source": "cisco_talos", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1219", "tactic_id": "TA0011", "evidence_quote": "Syncro was among many other remote access and management tools, including AnyDesk and SplashTop, that adversaries leveraged to establish and maintain remote access to compromised hosts", "confidence": 1.00},
        {"technique_id": "T1003", "tactic_id": "TA0006", "evidence_quote": "the affiliate(s) using red team frameworks such as Cobalt Strike and Mimikatz", "confidence": 1.00},
        {"technique_id": "T1486", "tactic_id": "TA0040", "evidence_quote": "In one Royal ransomware incident, Talos IR identified the affiliate(s) using red team frameworks such as Cobalt Strike and Mimikatz, and by performing mass uninstallation of security software across the environment", "confidence": 0.75}
    ], "valid_ttp_count": 3},
    {"article_id": 3321, "source": "cisco_talos", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3331, "source": "cisco_talos", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1566.001", "tactic_id": "TA0001", "evidence_quote": "This campaign consists of the use of malicious PDFs and Microsoft Office documents (maldocs) to serve as the initial infection vector", "confidence": 1.00},
        {"technique_id": "T1059.001", "tactic_id": "TA0002", "evidence_quote": "Malicious PowerShell-based downloaders acting as initial footholds into the target's enterprise", "confidence": 1.00},
        {"technique_id": "T1547.001", "tactic_id": "TA0003", "evidence_quote": "HKCU\\Software\\Microsoft\\windows\\CurrentVersion\\Run", "confidence": 1.00},
        {"technique_id": "T1218", "tactic_id": "TA0005", "evidence_quote": "the attackers make use of a LoLBin DLL called pcwutl.dll, which is part of the operating system, to execute the VBScript on reboot or re-login", "confidence": 1.00}
    ], "valid_ttp_count": 4},
    {"article_id": 3335, "source": "cisco_talos", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1219", "tactic_id": "TA0011", "evidence_quote": "they like to use the AnyDesk remote management software to control victim machines", "confidence": 1.00},
        {"technique_id": "T1562.001", "tactic_id": "TA0005", "evidence_quote": "It also disables Windows Defender. The base64-obfuscated string 'VwBpAG4ARABlAGYAZQBuAGQA' decodes to 'WinDefend', which is the Windows Defender service", "confidence": 1.00},
        {"technique_id": "T1486", "tactic_id": "TA0040", "evidence_quote": "approximately 17 hours after the ransomware infection process started, the machine reboots and the ransomware note \"BlackByteRestore.txt\" is shown to the user via Notepad", "confidence": 1.00}
    ], "valid_ttp_count": 3},
    {"article_id": 3340, "source": "cisco_talos", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3383, "source": "cisco_talos", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1566.001", "tactic_id": "TA0001", "evidence_quote": "the target was initially infected via a phish containing a commodity trojan. In this case, the phish contained a malicious Microsoft Excel attachment that executed the commodity trojan Zloader when if the user enabled macros", "confidence": 1.00},
        {"technique_id": "T1486", "tactic_id": "TA0040", "evidence_quote": "the adversary pivoted in the environment, leveraging the Group Policy replication mechanism in Windows Active Directory to distribute Ryuk and using PsExec to move laterally and execute remote commands", "confidence": 1.00},
        {"technique_id": "T1003", "tactic_id": "TA0006", "evidence_quote": "The adversaries obtained domain administrator (DA) credentials and, besides encrypting systems on the network, also wiped backup indexes", "confidence": 0.75}
    ], "valid_ttp_count": 3},
    {"article_id": 3392, "source": "cisco_talos", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1195.002", "tactic_id": "TA0001", "evidence_quote": "Attackers first infected victims via a malicious automatic update to the software, eventually delivering the REvil/Sodinokibi ransomware", "confidence": 1.00},
        {"technique_id": "T1486", "tactic_id": "TA0040", "evidence_quote": "the ransomware encrypts the contents of systems on the network, causing widespread operational disruptions to a variety of organizations that use this software", "confidence": 1.00},
        {"technique_id": "T1490", "tactic_id": "TA0040", "evidence_quote": "deletion of shadow copies on infected systems", "confidence": 1.00}
    ], "valid_ttp_count": 3},
    {"article_id": 3394, "source": "cisco_talos", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3404, "source": "trendmicro_research", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1059.001", "tactic_id": "TA0002", "evidence_quote": "we found a PowerShell script (start.ps1) that functions as a loader for the BERT ransomware payload (payload.exe). The script escalates privileges, disables Windows Defender, the firewall, and user account control (UAC), then downloads and executes the ransomware from the remote IP address 185[.]100[.]157[.]74", "confidence": 1.00},
        {"technique_id": "T1562.001", "tactic_id": "TA0005", "evidence_quote": "disables Windows Defender, the firewall, and user account control (UAC)", "confidence": 1.00},
        {"technique_id": "T1486", "tactic_id": "TA0040", "evidence_quote": "utilizes 50 threads to maximize encryption speed, enabling it to quickly encrypt files across the system", "confidence": 1.00},
        {"technique_id": "T1529", "tactic_id": "TA0040", "evidence_quote": "it will proceed to shutdown virtual machines using the command", "confidence": 1.00}
    ], "valid_ttp_count": 4},
    {"article_id": 3409, "source": "trendmicro_research", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3410, "source": "trendmicro_research", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1190", "tactic_id": "TA0001", "evidence_quote": "By exploiting SharePoint's authentication and deserialization flaws, attackers were able to rapidly gain code execution capabilities", "confidence": 1.00},
        {"technique_id": "T1486", "tactic_id": "TA0040", "evidence_quote": "deliver disruptive ransomware at scale", "confidence": 0.75}
    ], "valid_ttp_count": 2},
    {"article_id": 3414, "source": "trendmicro_research", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3418, "source": "trendmicro_research", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3425, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1190", "tactic_id": "TA0001", "evidence_quote": "attackers had been attempting exploits targeting older vulnerabilities such as CVE-2019-11580 against a victim's internet-facing applications since early April 2025", "confidence": 1.00},
        {"technique_id": "T1219", "tactic_id": "TA0011", "evidence_quote": "they successfully deployed a Linux version of Sliver, a publicly available cross-platform adversary emulation framework written in Go", "confidence": 1.00},
        {"technique_id": "T1486", "tactic_id": "TA0040", "evidence_quote": "attackers deployed multiple 01flip ransomware instances onto many devices within the network, including both Windows and Linux machines", "confidence": 1.00},
        {"technique_id": "T1070.004", "tactic_id": "TA0005", "evidence_quote": "the 01flip ransomware attempts to remove any trace of itself, to prevent it from being recovered from an infected host", "confidence": 1.00}
    ], "valid_ttp_count": 4},
    {"article_id": 3429, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3430, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3447, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3452, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1566.001", "tactic_id": "TA0001", "evidence_quote": "Clop has been commonly observed being delivered as the final-stage payload of a malicious spam campaign carried out by the financially motivated actor TA505", "confidence": 1.00},
        {"technique_id": "T1486", "tactic_id": "TA0040", "evidence_quote": "After the ransomware is executed, Clop appends the .clop extension to the victim's files", "confidence": 1.00}
    ], "valid_ttp_count": 2},
    {"article_id": 3457, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1190", "tactic_id": "TA0001", "evidence_quote": "Pro-Ocean targeting Apache ActiveMQ (CVE-2016-3088), Oracle WebLogic (CVE-2017-10271) and Redis (unsecure instances)", "confidence": 1.00},
        {"technique_id": "T1014", "tactic_id": "TA0005", "evidence_quote": "LD_PRELOAD forces binaries to load specific libraries before others, allowing the preloaded libraries to override any function from any library", "confidence": 1.00}
    ], "valid_ttp_count": 2},
    {"article_id": 3459, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3464, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3465, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3473, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3474, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3484, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3526, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1566.001", "tactic_id": "TA0001", "evidence_quote": "our case example begins with the first contact a potential victim receives from this threat actor", "confidence": 0.75},
        {"technique_id": "T1105", "tactic_id": "TA0011", "evidence_quote": "Bumblebee malware replaced BazarLoader sometime in February 2022. Since then, campaigns that formerly distributed BazarLoader are now distributing Bumblebee instead", "confidence": 0.75}
    ], "valid_ttp_count": 2},
    {"article_id": 3541, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1566.001", "tactic_id": "TA0001", "evidence_quote": "delivering the LokiBot information stealer via business email compromise (BEC) phishing emails", "confidence": 1.00}
    ], "valid_ttp_count": 1},
    {"article_id": 3546, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3556, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3570, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3579, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3609, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3612, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1574.006", "tactic_id": "TA0003", "evidence_quote": "LD_PRELOAD forces binaries to load specific libraries before others, allowing the preloaded libraries to override any function from any library", "confidence": 1.00},
        {"technique_id": "T1071.001", "tactic_id": "TA0011", "evidence_quote": "Hiding remote command and control (C2) connections using an advanced technique similar to the one used by the Symbiote malware family", "confidence": 0.75}
    ], "valid_ttp_count": 2},
    {"article_id": 3615, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3616, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3620, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1566.004", "tactic_id": "TA0001", "evidence_quote": "Shift to voice-based phishing (aka vishing) as a primary social engineering technique to manipulate IT help desk personnel into resetting credentials and MFA", "confidence": 1.00},
        {"technique_id": "T1003.003", "tactic_id": "TA0006", "evidence_quote": "Dumping credentials from password vaults including NTDS.dit to achieve full enterprise password stores and Active Directory compromise", "confidence": 1.00},
        {"technique_id": "T1567.002", "tactic_id": "TA0010", "evidence_quote": "Transferring stolen data to cloud storage services, including in some cases being sent directly from victims' environments", "confidence": 1.00}
    ], "valid_ttp_count": 3},
    {"article_id": 3628, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3637, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3638, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1566.004", "tactic_id": "TA0001", "evidence_quote": "The Ignoble Scorpius attack began with a voice phishing (vishing) call. The attacker impersonated the company's IT help desk and tricked an employee into entering their legitimate VPN credentials on a phishing site", "confidence": 1.00},
        {"technique_id": "T1003.003", "tactic_id": "TA0006", "evidence_quote": "They executed a DCSync attack on a domain controller to steal highly privileged credentials", "confidence": 1.00},
        {"technique_id": "T1219", "tactic_id": "TA0011", "evidence_quote": "The attackers established persistence by deploying AnyDesk and a custom RAT on a domain controller, configured as a scheduled task to survive reboots", "confidence": 1.00},
        {"technique_id": "T1567.002", "tactic_id": "TA0010", "evidence_quote": "exfiltrated over 400 GB of data using a renamed rclone utility", "confidence": 1.00},
        {"technique_id": "T1486", "tactic_id": "TA0040", "evidence_quote": "BlackSuit ransomware, orchestrated through Ansible, simultaneously encrypted hundreds of virtual machines across approximately 60 VMware ESXi hosts", "confidence": 1.00}
    ], "valid_ttp_count": 5},
    {"article_id": 3645, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1195.002", "tactic_id": "TA0001", "evidence_quote": "The malicious package versions contain a worm that executes a post-installation script", "confidence": 1.00},
        {"technique_id": "T1552.001", "tactic_id": "TA0006", "evidence_quote": "This malware scans the compromised environment for sensitive credentials, including: .npmrc files (for npm tokens)", "confidence": 1.00}
    ], "valid_ttp_count": 2},
    {"article_id": 3659, "source": "unit42", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1578.002", "tactic_id": "TA0005", "evidence_quote": "we observed the attackers accessing the target's vSphere portal and creating a new VM named \"New Virtual Machine\"", "confidence": 1.00},
        {"technique_id": "T1572", "tactic_id": "TA0011", "evidence_quote": "attackers established additional persistence in the target's environment using an SSH tunnel through the Chisel tool", "confidence": 1.00},
        {"technique_id": "T1003.003", "tactic_id": "TA0006", "evidence_quote": "copy the NTDS.dit and SYSTEM registry hive files from these two DCs and place them on the desktop of the Administrator account", "confidence": 1.00},
        {"technique_id": "T1087.002", "tactic_id": "TA0007", "evidence_quote": "the attackers began executing the Active Directory enumeration tool ADRecon", "confidence": 1.00},
        {"technique_id": "T1567.002", "tactic_id": "TA0010", "evidence_quote": "attackers began interacting with significant data from the target's Snowflake database, which they also downloaded to their VM", "confidence": 1.00}
    ], "valid_ttp_count": 5},
    {"article_id": 3663, "source": "welivesecurity", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3669, "source": "welivesecurity", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3676, "source": "welivesecurity", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3690, "source": "welivesecurity", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3716, "source": "cisa", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3767, "source": "cisa", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1566.001", "tactic_id": "TA0001", "evidence_quote": "Spearphishing campaigns using tailored emails that contain malicious attachments", "confidence": 1.00},
        {"technique_id": "T1059.001", "tactic_id": "TA0002", "evidence_quote": "Windows Management Instrumentation Command-Line (WMIC) to run PowerShell commands on additional systems on the victim network", "confidence": 1.00},
        {"technique_id": "T1486", "tactic_id": "TA0040", "evidence_quote": "Conti ransomware attacks, malicious cyber actors steal files, encrypt servers and workstations, and demand a ransom payment", "confidence": 1.00},
        {"technique_id": "T1003", "tactic_id": "TA0006", "evidence_quote": "add additional tools, such as Windows Sysinternals and Mimikatz\u2014to obtain users' hashes and clear-text credentials", "confidence": 1.00}
    ], "valid_ttp_count": 4},
    {"article_id": 3780, "source": "cisa", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3787, "source": "cisa", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3792, "source": "cisa", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1486", "tactic_id": "TA0040", "evidence_quote": "Maui uses a combination of Advanced Encryption Standard (AES), RSA, and XOR encryption to encrypt target files", "confidence": 1.00},
        {"technique_id": "T1059.008", "tactic_id": "TA0002", "evidence_quote": "The remote actor uses command-line interface to interact with the malware and to identify files to encrypt", "confidence": 1.00}
    ], "valid_ttp_count": 2},
    {"article_id": 3794, "source": "cisa", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1190", "tactic_id": "TA0001", "evidence_quote": "Vice Society actors likely obtain initial network access through compromised credentials by exploiting internet-facing applications", "confidence": 0.75},
        {"technique_id": "T1068", "tactic_id": "TA0004", "evidence_quote": "Vice Society actors have been observed exploiting the PrintNightmare vulnerability (CVE-2021-1675 and CVE-2021-34527) to escalate privileges", "confidence": 1.00},
        {"technique_id": "T1047", "tactic_id": "TA0002", "evidence_quote": "targeting the legitimate Windows Management Instrumentation (WMI) service", "confidence": 1.00}
    ], "valid_ttp_count": 3},
    {"article_id": 3799, "source": "cisa", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1190", "tactic_id": "TA0001", "evidence_quote": "Initial access was obtained via exploitation of an Internet-facing Microsoft SharePoint, exploiting CVE-2019-0604", "confidence": 1.00},
        {"technique_id": "T1505.003", "tactic_id": "TA0003", "evidence_quote": "the actors used several .aspx webshells, pickers.aspx, error4.aspx, and ClientBin.aspx, to maintain persistence", "confidence": 1.00},
        {"technique_id": "T1003", "tactic_id": "TA0006", "evidence_quote": "The FBI also found evidence of Mimikatz usage and LSASS dumping", "confidence": 1.00},
        {"technique_id": "T1486", "tactic_id": "TA0040", "evidence_quote": "the actor logged in to a victim organization print server via RDP and kicked off a process (Mellona.exe) which would propagate the GoXml.exe encryptor to a list of internal machines", "confidence": 1.00}
    ], "valid_ttp_count": 4},
    {"article_id": 3802, "source": "cisa", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1078", "tactic_id": "TA0001", "evidence_quote": "the actors used previously compromised credentials to access a legacy VPN server that did not have multifactor authentication (MFA) enabled", "confidence": 1.00},
        {"technique_id": "T1486", "tactic_id": "TA0040", "evidence_quote": "the Daixin Team's ransomware is based on leaked Babuk Locker source code. This third-party reporting as well as FBI analysis show that the ransomware targets ESXi servers and encrypts files located in /vmfs/volumes/", "confidence": 1.00},
        {"technique_id": "T1003", "tactic_id": "TA0006", "evidence_quote": "Daixin actors have sought to gain privileged account access through credential dumping", "confidence": 1.00}
    ], "valid_ttp_count": 3},
    {"article_id": 3812, "source": "cisa", "model": "claude-opus-4-6", "error": None, "ttps": [], "valid_ttp_count": 0},
    {"article_id": 3829, "source": "cisa", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1190", "tactic_id": "TA0001", "evidence_quote": "APT actors exploited CVE-2022-47966 to gain unauthorized access to a public-facing application (Zoho ManageEngine ServiceDesk Plus)", "confidence": 1.00},
        {"technique_id": "T1136.001", "tactic_id": "TA0003", "evidence_quote": "APT actors achieved root level access on the web server and created a local user account named Azure with administrative privileges", "confidence": 1.00},
        {"technique_id": "T1003.001", "tactic_id": "TA0006", "evidence_quote": "The Azure user successfully accessed and dumped credentials stored in the process memory of LSASS for the Active Directory (AD) domain", "confidence": 1.00},
        {"technique_id": "T1588.002", "tactic_id": "TA0042", "evidence_quote": "the legitimate ConnectWise ScreenConnect client was utilized to connect to the ServiceDesk system, download mimikatz.exe, and execute malicious payloads to steal credentials", "confidence": 1.00},
        {"technique_id": "T1505.003", "tactic_id": "TA0003", "evidence_quote": "APT actors further leveraged legitimate credentials to move from the firewall to a web server, where multiple web shells were loaded", "confidence": 1.00}
    ], "valid_ttp_count": 5},
    {"article_id": 3860, "source": "cisa", "model": "claude-opus-4-6", "error": None, "ttps": [
        {"technique_id": "T1190", "tactic_id": "TA0001", "evidence_quote": "leveraging vulnerabilities in Fortinet FortiOS appliances (CVE-2018-13379), servers running Adobe ColdFusion (CVE-2010-2861 and CVE-2009-3960), Microsoft SharePoint (CVE-2019-0604), and Microsoft Exchange (CVE-2021-34473, CVE-2021-34523, and CVE-2021-31207", "confidence": 1.00},
        {"technique_id": "T1059.001", "tactic_id": "TA0002", "evidence_quote": "leveraging Windows Command Prompt and/or PowerShell to download and execute Cobalt Strike Beacon malware", "confidence": 1.00},
        {"technique_id": "T1486", "tactic_id": "TA0040", "evidence_quote": "Ghost variants can be used to encrypt specific directories or the entire system's storage", "confidence": 1.00},
        {"technique_id": "T1562.001", "tactic_id": "TA0005", "evidence_quote": "Ghost frequently runs a command to disable Windows Defender on network connected devices. Options used in this command are: Set-MpPreference -DisableRealtimeMonitoring 1", "confidence": 1.00},
        {"technique_id": "T1490", "tactic_id": "TA0040", "evidence_quote": "ransomware payloads clear Windows Event Logs, disable the Volume Shadow Copy Service, and delete shadow copies to inhibit system recovery attempts", "confidence": 1.00}
    ], "valid_ttp_count": 5},
]

outpath = "benchmark_v2_results/claude_opus/extractions.jsonl"  # relativo a la raíz del repo
with open(outpath, "a") as f:
    for ext in extractions:
        f.write(json.dumps(ext) + "\n")

with_ttps = sum(1 for e in extractions if e["valid_ttp_count"] > 0)
total_ttps = sum(e["valid_ttp_count"] for e in extractions)
print(f"Wrote {len(extractions)} extractions")
print(f"Articles with TTPs: {with_ttps}/{len(extractions)} ({with_ttps/len(extractions)*100:.1f}%)")
print(f"Total TTPs extracted: {total_ttps}")

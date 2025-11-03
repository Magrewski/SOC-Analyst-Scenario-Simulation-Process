# SOC-Analyst-Phishing Scenario-Simulation-Process
In this scenario you will see how I effectively handle a high process alert using different tools and resources. 

# Splunk DNS Tunneling/Process Phishing Triage (TryHackMe SOC Simulation)

**Author:** Blake Anderson  
**Platform:** TryHackMe.com  
**Tools Used:** Splunk, CyberChef, VirusTotal, Dmarcian.com  

---

## Scenario Overview
This simulation, based on a TryHackMe SOC training exercise, replicates a real-world phishing investigation using Splunk as the SIEM platform.  
A **high-priority alert** was triggered in the alert queue for suspicious process behavior on a Windows host.

Initial analysis revealed:
- `nslookup.exe` was executed within `powershell.exe`  
- The command queried a suspicious domain: `haz4rdw4re.io`  
- The process originated from a user's **Downloads** directory (`C:\Users\michael.ascott\Downloads`), a common malware drop location.
- The behavior was flagged under `rule: ProcessCreate`, consistent with *living off the land* (LOLBAS) activity. 

---

## Investigation Steps

1. **Log Querying (Splunk)**  
   - Queried Splunk for events related to `nslookup.exe`, `powershell.exe`, and the suspicious domain.  
   - Found **10 unique events** with different Base64-encoded strings appended to the same domain (`haz4rdw4re.io`).

2. **Domain Verification**  
   - Checked the domain on **VirusTotal** — no significant intelligence or previous detections.  
   - Queried **dmarcian.com** for DNS records and confirmed missing **DMARC, SPF, and DKIM** entries.  
   - Determined the domain was newly registered and lacked basic security controls.

3. **Data Analysis (CyberChef)**  
   - Extracted the appended strings from the Splunk logs.  
   - Used CyberChef to decode the Base64 data — initial output was obfuscated.  
   - Further decoding revealed layered encoding; eventually uncovered a readable payload and the challenge flag (`THM...`).

---

## Findings

- **Indicator of Compromise (IOC):** `haz4rdw4re.io`  
- **TTPs:**  
  - DNS tunneling for command-and-control (C2)  
  - LOLBAS (Living Off the Land Binaries and Scripts) via `nslookup.exe` and `powershell.exe`  
- **Classification:** Confirmed *Phishing / DNS Tunneling Attempt*  

---

## Actions Taken

- Documented all observations, timestamps, and actions in the SOC ticketing system.  
- Contained the threat by submitting the IOC (`haz4rdw4re.io`) to the DNS/firewall blocklist.  
- Notified and escalated the case to the **Tier 2 Incident Response** team per internal procedures.  
- Recommended enhanced user training on safe downloading practices.  

---

## Outcome

This simulation demonstrates the end-to-end triage process of identifying, investigating, and escalating a potential phishing incident using Splunk, open-source analysis tools, and structured SOC methodology.

---

## Screenshots

<img width="643" height="217" alt="image" src="https://github.com/user-attachments/assets/aa59ea38-8b98-4465-86f8-c530fa9742ae" />
<img width="645" height="240" alt="image" src="https://github.com/user-attachments/assets/41392b9a-7a4c-4ec1-8213-013beb0fe0f3" />
<img width="625" height="519" alt="image" src="https://github.com/user-attachments/assets/4d434bf8-6e22-4c7b-a55c-280ed0b09f96" />
<img width="563" height="624" alt="image" src="https://github.com/user-attachments/assets/ba298cf6-baff-4c8a-82b4-6d822f9ba47e" />
<img width="634" height="334" alt="image" src="https://github.com/user-attachments/assets/1b235e8d-2f29-4dc9-9bc5-ad266fbdb17f" />

---

## Skills Demonstrated

- SIEM log analysis (Splunk)  
- Incident triage and escalation  
- DNS tunneling detection  
- Threat intelligence gathering (VirusTotal, dmarcian)  
- Data decoding and IOC analysis (CyberChef)  
- Documentation and communication of findings  

---

## Reference

> **TryHackMe:** [https://tryhackme.com](https://tryhackme.com)  
> **Scenario:** Phishing Investigation (SOC Analyst Simulation)

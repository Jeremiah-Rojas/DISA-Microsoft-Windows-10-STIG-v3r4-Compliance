# DISA-Microsoft-Windows-10-STIG-v3r4-Compliance

## STIG Compliance Lab
In this lab I will attempt to make my VM DISA Microsoft Windows 10 STIG v3r4 compliant.

I scanned my machine for STIG Compliance and found the following results:
![image](https://github.com/user-attachments/assets/3b2590e3-f976-4f29-813d-97f50c6d8c9a)


Rather than attempting to remediate all of them manually as I did to some([see here](https://github.com/Jeremiah-Rojas/Jeremiah-Rojas/tree/main/STIGs)), I decided to write scripts that would make this system compliant.

Script #1: [script#1.ps1](https://github.com/Jeremiah-Rojas/DISA-Microsoft-Windows-10-STIG-v3r4-Compliance/blob/main/script%231.ps1)
</br>Script #2: [script#2.ps1](https://github.com/Jeremiah-Rojas/DISA-Microsoft-Windows-10-STIG-v3r4-Compliance/blob/main/script%232.ps1)
</br>Script #3: [script#3.ps1](https://github.com/Jeremiah-Rojas/DISA-Microsoft-Windows-10-STIG-v3r4-Compliance/blob/main/script%233.ps1)

I decided to break these scripts up into three pieces just to prevent any error of overwhelming the system with too many configuration changes in such a short period of time; although the machine can probably handle it.
As I was working on this lab, I ran into a problem where I could no longer connect to my VM via Remote Desktop most likely due to a STIG configuration change so I created a new VM and decided to temporarily leave out some STIGs to prevent further interruption. Some STIGs just don't apply since I am applying them to a VM, some cannot be automated with a script, and others were creating problems concerning the scans and accessibility. I also created a restore point before running the STIGs so that if any similar error came up again, I would be able to simply restore the VM to a clean state instead of having to recreate the VM.

## Conclusion
After days of trying to figure out the issue, I have come to the conclusion that these scripts are functioning correctly but due to the complicated nature of the scan, Cloud Tenable scan on VM in Microsoft Azure via RDP, it is very difficult to rescan the machine after applying the scripts and still get a good result; or a result that will show the remaining STIGs. 

Some of the STIGs cannot be applied via powershell script, but I have done my best to collect the STIG fixes that can be automated.

![image](https://github.com/user-attachments/assets/f03c4105-c630-45cf-9cf8-40e96e59bede)

I hope anyone who sees this finds these scripts useful for lab purposes.


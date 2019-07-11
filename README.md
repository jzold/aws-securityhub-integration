# aws-securityhub-integration
Powershell script to integrate Windows Defender Antivirus scan alerts into AWS Security Hub. This script currently fetches the latest Windows Defender Antivirus event ID 1116 only and submits various details from the log it to AWS Security Hub using the AWS custom finding format.

#Requirements
1. Latest AWS PowerShell Tools installed.
2. Powershell v5.1 (not tested on PowerShell Core V6 yet)

function Import-SecurityFinding {
    <#
    .SYNOPSIS
        Submits Windows Defender Antivirus scan logs from Windows Event Logs to AWS Security Hub.
    .DESCRIPTION
        The Import-SecurityFinding cmdlet submits the latest Windows Defender Antivirus scan alert 
        from the Windows Event log from (event ID: 1116) and submits it to AWS Security Hub.
    #>
    [CmdletBinding()]
    param(
    [Parameter(Mandatory = $true)]
    [string]$AwsRegion
    )
    begin {
    $virusalertevent = Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Windows Defender/Operational';ID=1116} -MaxEvents 1 
    $finding = [Amazon.SecurityHub.Model.AwsSecurityFinding] @{
      AwsAccountId = (Get-STSCallerIdentity).Account;
      CreatedAt = [Xml.XmlConvert]::ToString((get-date),[Xml.XmlDateTimeSerializationMode]::Utc);     #use the AWS custom finding date format
      Criticality = 100;
      Description = 'Windows Defender Antivirus malware alert!';
      GeneratorId = 'WindowsDefender';
      Id = $AwsRegion + '/' + $(Get-STSCallerIdentity).Account + '/' + [guid]::newguid().ToString("N");                      #generate a new ID for each new finding
      ProductArn = 'arn:aws:securityhub:' + $AwsRegion + ':' + $(Get-STSCallerIdentity).Account + ':product/' + $(Get-STSCallerIdentity).Account + '/default'
      Resources = [Amazon.SecurityHub.Model.Resource[]]@(
        @{
          Type = 'Other';
          Id = (Get-WmiObject win32_computersystem).DNSHostName + "." + (Get-WmiObject win32_computersystem).Domain     #log the FQDN of the server/workstation 
          });
      SchemaVersion = '2018-10-08';
      Severity = @{
          Product = 2.5;
          Normalized = 100
        };
       Title = 'Windows Defender Antivirus malware alert!';
       UpdatedAt = [Xml.XmlConvert]::ToString((Get-Date),[Xml.XmlDateTimeSerializationMode]::Utc);
       Types = @('Unusual Behaviors/Process')
       
    }
    Import-SHUBFindingsBatch -Finding $finding
    }
}

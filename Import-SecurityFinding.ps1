function Import-SecurityFinding {
    <#
    .SYNOPSIS
        Submits Windows Defender Antivirus scan logs from Windows Event Logs to AWS Security Hub.
    .DESCRIPTION
        The Import-SecurityFinding cmdlet submits the latest Windows Defender Antivirus scan alert 
        from the Windows Event log from (event ID: 1116) and submits it to AWS Security Hub.
    .EXAMPLE
        Import-SecurityFinding -AwsRegion 'eu-west-2'
        Imports the Windows Defender log into AWS Security Hub eu-west-2 (London) region 
    #>
    [CmdletBinding()]
    param(
    [Parameter(Mandatory = $true)]
    [string]$AwsRegion
    )
    begin {
    $ProductFields = New-Object 'System.Collections.Generic.Dictionary[String,String]'  
    $virusalertevent = Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Windows Defender/Operational';ID=1116} -MaxEvents 1 
    $ProductFields.Add('Defender Version',$virusalertevent.properties[1].value)
    $ProductFields.Add('Defender Signature Version',$virusalertevent.properties[40].value)
    $ProductFields.Add('Defender Engine Version',$virusalertevent.properties[41].value)
    $ProductFields.Add('Defender Account',$virusalertevent.properties[19].value)
    $ProductFields.Add('Defender Action Result',$virusalertevent.properties[33].value)
    $ProductFields.Add('Defender User Result',$virusalertevent.properties[37].value)
    $finding = [Amazon.SecurityHub.Model.AwsSecurityFinding] @{
      AwsAccountId = (Get-STSCallerIdentity).Account;
      Compliance = @{
        Status = 'FAILED' };
      CreatedAt = [Xml.XmlConvert]::ToString((get-date),[Xml.XmlDateTimeSerializationMode]::Utc);     #use the AWS custom finding date format
      Criticality = 100;
      Description = 'Windows Defender Antivirus malware alert!';
      GeneratorId = 'WindowsDefender';
      Id = $AwsRegion + '/' + $(Get-STSCallerIdentity).Account + '/' + [guid]::newguid().ToString("N");                      #generate a new ID for each new finding
      Malware = [Amazon.SecurityHub.Model.Malware[]]@(
        @{
         Name = $virusalertevent.properties[7].value;
     Path = $virusalertevent.properties[21].value;
     State = "OBSERVED";  #this has to be aligned with properties[37] of the event log! 
     Type = $virusalertevent.properties[11].value
        });
      ProductArn = 'arn:aws:securityhub:' + $AwsRegion + ':' + $(Get-STSCallerIdentity).Account + ':product/' + $(Get-STSCallerIdentity).Account + '/default'
      ProductFields = $ProductFields
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

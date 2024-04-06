<# : bat kodu
@echo off
powershell -nop "if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) { Start-Process -Verb RunAs 'cmd.exe' -ArgumentList '/c %~dpnx0 %*' } else { Invoke-Expression ([System.IO.File]::ReadAllText('%~f0')) }"
goto :eof
#>

$ScriptBlock = {
    $MAPS_Status = (Get-MpPreference).MAPSReporting
    Set-MpPreference -DisableRealtimeMonitoring 1
    Set-MpPreference -MAPSReporting Disabled

    Get-ChildItem -File 'C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service' -Recurse | Remove-Item -Force

    Set-MpPreference -DisableRealtimeMonitoring 0
    Set-MpPreference -MAPSReporting $MAPS_Status
}

$Gorev_Adi = 'Selamlar Polis Abi'
$Gorev_Yolu = '\Microsoft\Windows\PowerShell\ScheduledJobs'
Unregister-ScheduledJob $Gorev_Adi -Confirm:$false 2>&1 | Out-Null
Register-ScheduledJob -Name $Gorev_Adi -ScriptBlock $ScriptBlock | Out-Null

$Admin_Hesabi = Get-LocalUser | Where-Object {$_.SID -like "*-500"} | Select-Object -ExpandProperty Name
$Gorev_Baslatma = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\$Admin_Hesabi"
Set-ScheduledTask -TaskPath $Gorev_Yolu -TaskName $Gorev_Adi -Principal $Gorev_Baslatma | Out-Null

$Servis = New-Object -ComObject 'Schedule.Service'
$Servis.Connect()

$Kullanici = 'NT SERVICE\TrustedInstaller'
$Klasor = $Servis.GetFolder($Gorev_Yolu)
$Gorev = $Klasor.GetTask($Gorev_Adi)

$Gorev.RunEx($null, 0, 0, $Kullanici) | Out-Null

# Wait for task completion, or timed out

$Zaman = 60
$Zamanlayici =  [Diagnostics.Stopwatch]::StartNew()

while (((Get-ScheduledTask -TaskName $Gorev_Adi).State -ne 'Ready') -and ($Zamanlayici.Elapsed.TotalSeconds -lt $Zaman)) {
    Start-Sleep -Seconds 1
}

$Zamanlayici.Stop()

# Remove scheduled task
Unregister-ScheduledJob $Gorev_Adi -Confirm:$false | Out-Null

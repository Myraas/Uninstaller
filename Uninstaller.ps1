Clear-Host

#Check if C:\temp Exists and Create DIR
if (!(Test-Path -Path C:\temp)){mkdir C:\temp}

Start-Transcript -Path "C:\temp\Uninstaller-Transcript.txt"
[System.DateTime]::Now

# List Apps to uninstall here.

$apps = @(
    "*Adobe*"
)

# List Apps to whitelist here.

$whitelist = @(
    "*PhotoShop*"
    "*Illustrator*"
    "*Creative*"
    "*Lightroom*"
    "*Premiere*"
    "*Effects*"
    "*Substance*"
    "*Stock*"
    "*Express*"
    "*Dreamweaver*"
    "*Stager*"
    "*Sampler*"
    "*Painter*"
    "*Designer*"
    "*InCopy*"
    "*Rush*"
    "*Aero*"
    "*Express*"
    "*PhotoShop*"
    "*Audition*"
)

# --------------------------------------------------------------------------------------

# Log actions in the %temp% directory
$Timestamp = Get-Date -Format "yyyy-MM-dd_THHmmss"
$LogFile = "C:\temp\Uninstaller-MsiexecLog_$Timestamp.log"

function Get-InstalledApps{
    if ([IntPtr]::Size -eq 4) {
        $regpath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    }
    else {
        $regpath = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
            'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
    }
    Get-ItemProperty $regpath | .{process{if($_.DisplayName -and $_.UninstallString) { $_ } }}
}

$MSIUninstallArguments = @(
    "/X"
    "$($result.PSChildName)"
    "REBOOT=ReallySuppress"
    "/qn"
    "/Q"
    "/L*V"
    "$LogFile"
)

Get-Process * | Where-Object {$_.CompanyName -like $app -or $_.Path -like $app} | Stop-Process

foreach ($app in $apps){
    $results = ( Get-InstalledApps | Where { $_.DisplayName -like $app } ) | Sort-Object


    # Filter whitelisted apps out
    
#    $results = $results | Where-Object { $_ -notin $whitelist }
#    $results = ($results | Where-Object {$_ -notin $whitelist}) | Sort-Object
#    $results = $results | where-object -property "$whitelist" -notin $_.DisplayName


    foreach($result in $results){
        Write-Host $result `
        
#        Start-Process "C:\Windows\System32\Msiexec.exe" -ArgumentList $MSIUninstallArguments -Wait -NoNewWindow
#        Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like $app } | foreach-object -process {$_.Uninstall()}
    }
}

#Check if Previous Adobe Installers Exist in C:\temp and Delete
if ((Test-Path -Path C:\temp\Adobe.zip)){Remove-Item C:\temp\Adobe.zip}
if ((Test-Path -Path C:\temp\AdobeAcrobatReader.exe)){Remove-Item C:\temp\AdobeAcrobatReader.exe}

# Download Adobe Acrobat to C:\temp
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
$sourceURL = "https://urlofinstallerhere"
Invoke-WebRequest -Uri $sourceURL -OutFile "C:\temp\Adobe.zip"

if ((Get-Item -Path C:\temp\Adobe.zip).length/1KB -le 114){Write-Host "Error Downloading File." -ForegroundColor Red}

# Expand Archive
Expand-Archive "C:\temp\Adobe.zip" -DestinationPath "C:\temp"

# Silent Install Adobe Acrobat EXE
C:\temp\AdobeAcrobatReader.exe /sAll /rs /msi EULA_ACCEPT=YES

Write-Host ""

Stop-Transcript

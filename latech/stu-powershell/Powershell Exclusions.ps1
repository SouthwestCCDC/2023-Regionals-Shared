$Download = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
$Desktop = (New-Object -ComObject Shell.Application).NameSpace('shell:Desktop').Self.Path
$status = Get-MpComputerStatus | Select-Object AntivirusEnabled
if($status -eq $false)
{
       Set-MpPreference -DisableRealtimeMonitoring $false
}
Set-MpPreference -DisableRemovableDriveScanning $false
Set-MpPreference -DisableArchiveScanning $false

$exEx = Get-MpPreference  | Select-Object -ExpandProperty ExclusionExtension
$exPa = Get-MpPreference  | Select-Object -ExpandProperty ExclusionPath
$extensionPathDict = [ordered]@{0 = "All"}
echo "`nExcluded File Paths`n"
$count = 1
ForEach($x in $exPa)
{
    echo "    $x`n"
    $extensionPathDict.Add($count, $x)
    $count++
}
echo "`nExcluded Extensions"

ForEach($x in $exEx)
{
    echo "    $x`n"
}

echo $extensionPathDict

$extensionPathDict.add(99, "back")
$ans = Read-Host "Would you like to remove one of these exclusions?"

if($ans -ne 0 -and $ans -ne 99)
{
    echo "Removing: "$extensionPathDict[$ans]
    Remove-MpPreference -ExclusionPath $extensionPathDict[$ans]
}
if($ans -eq 0)
{
    ForEach($val in $extensionPathDict.Values)
    {
     echo "Removing: $val"
     Remove-MpPreference -ExclusionPath $val  
    }
}

$scan = [ordered]@{0 = "Fullscan"
          1 = "Quickscan"
          2 = "Custom"
          3 = "None"}
echo $scan
$ans = Read-Host "Would you like to scan?"
if($ans -eq 0)
{
    Start-MpScan -ScanType Fullscan
}
if($ans -eq 1)
{
    Start-MpScan -ScanType Quickscan
}
if($ans -eq 2)
{
    echo "
          [0] Downloads
          [1] Desktop
          [2] Custom"
    $dir = Read-Host "Which file would you like to scan?"
    if($dir -eq 0)
        {
            $dir = $Download
        }
    if($dir -eq 1)
        {
            $dir = $Desktop
        }
    if($dir -eq 2)
        {
            $dir = Read-Host "Please enter the file path of the folder: "      
        }
    Start-MpScan -ScanType Customscan -ScanPath $dir
}


#Remove Active Threats
#Remove-MpThreat

#Remove Exclusions
#Remove-MpPreference -ExclusionPath

#Defender Scan
#Start-MpScan -ScanType Fullscan
##Start-MpScan -ScanType Quickscan
#Start-MpScan -ScanType Customscan -ScanPath
 #Files to scan: 
    #Downloads
    #Desktop
    #Custom


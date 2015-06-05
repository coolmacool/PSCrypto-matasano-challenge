if(!$PSScriptRoot){ $PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent }
Import-Module $PSScriptRoot\..\..\PSCrypto -Force

foreach($Hex in (Get-Content $PSScriptRoot\4.txt)) 
{ 
    $Result = Get-BruteXOR ($Hex | Convert-HexToBytes) (32..126) | ? { $_.Score -gt 20 } | Select @{Name="Hex";Expression={$Hex}}, Key, KeyValue, Decrypted, Score
    if ($Result) { break }
}
$Result

# Output
#
# Hex       : 7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f
# Key       : 5
# KeyValue  : 53
# Decrypted : Now that the party is jumping
#            
# Score     : 22
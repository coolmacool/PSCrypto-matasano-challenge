if(!$PSScriptRoot){ $PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent }
Import-Module $PSScriptRoot\..\..\PSCrypto -Force

$Encrypted = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736' | Convert-HexToBytes
Get-BruteXOR $Encrypted -Keys (0..255) | ? { $_.Score -ge 22 } | fl

# Winner
#
# Key       : X
# KeyValue  : 88
# Decrypted : Cooking MC's like a pound of bacon
# Score     : 23
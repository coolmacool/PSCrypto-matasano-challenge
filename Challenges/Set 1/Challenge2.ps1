if(!$PSScriptRoot){ $PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent }
Import-Module $PSScriptRoot\..\..\PSCrypto -Force

$XOR1   = '1c0111001f010100061a024b53535009181c' | Convert-HexToBytes
$XOR2   = '686974207468652062756c6c277320657965' | Convert-HexToBytes
$Result = foreach($i in 0..($XOR1.Length-1)) { $XOR1[$i] -bxor $XOR2[$i] }
([Bitconverter]::ToString($Result)).ToLower() -replace '-'

# Output
#
# 746865206b696420646f6e277420706c6179
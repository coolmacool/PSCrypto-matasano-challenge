if(!$PSScriptRoot){ $PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent }
Import-Module $PSScriptRoot\..\..\PSCrypto -Force

$Plain =  "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"

Invoke-RepeatingXOR -Plaintext $Plain -KeyPhrase 'ICE'

# Output
#
# 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f


# Decryption Output
#
# Invoke-RepeatingXOR -HexString '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f' -KeyPhrase $Key -AsString
#
# Burning 'em, if you ain't quick and nimble
# I go crazy when I hear a cymbal
rule zloader : Trojan
{
    meta:
        description = "NAC INTEL"
        author = "rs"
        date = "2020-10-22"
        reference = "https://app.any.run"
        hash1 = "9d7608e37a7fb81cb2e9806008a0e25e80f1e6faff49357d39880d99fe1569e8"
        hash2 = "e328b59a03281b6847e8b69c31833e912320972b7653e5824d6c081a356d2a63"
        hash3 = "c307f86ab5e3cc34c08e557ca6805bd8f0e024516c85b26516a5c35f1c516064"
    strings:
        $str1 = "kNT3rfecee42t96b2872ta3y" nocase
        $str2 = "publicKeyToken=\"6595b64144ccf1df\"" nocase
        $city1 = "New Jersey1" nocase
        $city2 = "Greater Manchester1" nocase
        $url = "http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" nocase
    
    condition:

        (all of ($city*)) and (any of ($str*) or ($url))

}

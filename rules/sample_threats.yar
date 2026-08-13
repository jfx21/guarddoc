rule Suspicious_Shell_In_Text {
    meta:
        description = "Wykryto potencjalnie złośliwy skrypt powłoki lub polecenie do pobierania plików"
        severity = "HIGH"
        author = "GuardDoc Team"
    strings:
        $curl_bash = /curl\s+-[sSL]*\s+http[s]?:\/\/[^\s]+\s*\|\s*(ba)?sh/
        $wget_exec = /wget\s+http[s]?:\/\/[^\s]+\s+-O\s+[^\s]+\s*&&\s*chmod\s+\+x/
    condition:
        any of them
}

rule EICAR_Test_File {
    meta:
        description = "Wykryto standardowy ciąg testowy antywirusa EICAR"
        severity = "CRITICAL"
        author = "GuardDoc Team"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

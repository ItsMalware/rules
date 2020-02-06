rule iceid
{
meta:
description = "Detects IcedID"
author = "Yaz"
date = "2019-11-21"
Hash = "0B0F71600A9D7E6AC806B04E8C5DABAD261EAD7A18DAE9032B3A817F85C49A10"
strings:
$header = { 4D 5A }
$magic1 = { 8B EC 83 EC 64 53 E8 E5  FD FF FF 85 C0 75 07 50 } //entry point in ida
$st01 = "rundll32.exe kernel32,Sleep -s" fullword nocase wide ascii
$st02 = "front://" fullword nocase wide ascii
$st03 = ".tmp" fullword nocase wide ascii
$st04 = "#3%@U4%2h1%" fullword nocase wide ascii
$st05 = "-None-Ma tch:" fullword nocase wide ascii
$bn01 = {68 74 00 74 70 3A 2F 2F}
//00003D97 string
$bn02 = {64 65 66 6C 00 61 74 65}
//00003DA8 string
$bn03 = {8D 45 E0 50 8D 45 9C 50  53 53 53 53 53 53 8D 45 F0 50 53 FF 15 30 20 40  00}
//00000A87 code
$bn04 = {68 04 01 00 00 8D 46 7D  50 57 FF 15 20 20 40 00 A1 18 B0 41 00 89 46 74  8D 46 78 6A 05 FF 35 18 B0 41 00 50 E8 35 03 00  00 68 00 01 00 00 8D 86 85 02 00 00 68 98 20 40  00 50 E8 1F 03 00 00 6A 04 89 7E 3C 68 F7 13 00  00 89 7E 40 55 89 7E 44}
//0000088E code
$bn05 = {68 00 75 74 64 6F 77 6E 50 72 00 69 76 69 6C 65 67 65}
//00004389 string
condition:
$header at 0 and all of ($magic*) and 4 of ($st0*) and 3 of ($bn*)
}

rule iceid_packed
{
meta:
description = "Detects IcedID packed var"
author = "Yaz"
date = "2019-11-22"
Hash = "a836dea002ee0847ef46b96f7750b65bf2bf321c636614da3e80cdc9aee4cd7e"
strings:
$header = { 4D 5A }
$magic1 = {E8 8E 5F 00 00 E9 39 FE FF FF}  //entry point in ida
$st01 = "Stuff.pdb" fullword nocase wide ascii
$st02 = "CV: " fullword wide ascii
$st03 = "regex_error(error_syntax)" fullword nocase wide ascii
$st04 = "AUIDWriteTextRenderer@@" fullword nocase wide ascii
$st05 = "@TdP4" fullword nocase wide ascii
$bn01 = {31 23 53 4E 41 4E 00 00 31 23 49 4E 44 00 00 00 31 23 49 4E 46 00 00 00 31 23 51 4E 41 4E}
//0003125C string
$bn02 = {55 8B EC 8B 45 08 83 F8 0E 77 70 FF 24 85 CB 75 F0 05}
//00006947 code
$bn03 = {6C 6F 67 00 6C 6F 67 31 30 00 00 00 73 69 6E 68}
//0002D060 string
$bn04 = {6A 40 68 00 30 00 00 68 00 A0 01 00 6A 00 FF 15 58 C0 F2 05 89 45 E4 68 00 A0 01 00 68 48 72 F3 05 8B 55 E4 52 E8 62 5D 00 00 83 C4 0C 8B 45 E4 8B 4D F8 8D 94 01 71 FB D2 FA 89 55 E0 FF 55 E0 8B E5 5D C3}
//00002144 code
$bn05 = {8B FF 59 75 F0 05 60 75  F0 05 67 75 F0 05 6E 75 F0 05 75 75 F0 05 7C 75  F0 05 83 75 F0 05 8A 75 F0 05 91 75 F0 05 98 75  F0 05 9F 75 F0 05 A6 75 F0 05 AD 75 F0 05 B4 75  F0 05 BB 75 F0 05 55 8B }
//000069C9 code
condition:
$header at 0 and all of ($magic*) and 4 of ($st0*) and 3 of ($bn*)
}

rule gozi_ursnif_PACKED
{
meta:
description = "Detects Gozi/Ursnif"
MITRE = "ID: S0386, Domain: Enterprise tactic: T1005,T1007,T1012,T1027,T1036,T1047,T1050,T1055,T1057,T1060,T1064,T1071,T1074,T1080,T1082,T1086,T1090,T1091,T1093,T1094,T1105,T1106,T1107,T1112,T1113,T1132,T1140,T1143,T1175,T1179,T1185,T1188,T1483,T1497 "
author = "Yaz"
date = "2019-12-10"
Hash = "891e049a76d40d402f822d5049ef0c84c4ec86cd03152bc2c050748bb69d7dac"
Hash = "232c8d4a53620fa6d5c296eebc014ea0cee78e54f9ac5707eefa08cf2bc29891"
strings:
$pdb_1 = "LnfjionJHijejLKok03ro0jfdskkLljf.pdb"
$pdb_2 =  "InventWord.pdb"
$str_1 =  "axppwpp"
$str_2 = "ole32.dll"
$str_3 = "snow %d  Order %srec"
$str_4 = "@superWinner@0"
$str_5 = "xpxxxx"
$str_6 = "TLOSS"  fullword nocase wide ascii
$str_7 = "SING"  fullword nocase wide ascii
$str_8 = "DOMAIN"  fullword nocase wide ascii
$str_9 = "R6034"  fullword nocase wide ascii
$bn_1 = {55 89 E5 56 ?? ?? 83 E4 F8 81 EC ?? 00 00 00 ?? 84 24 C4 00 00 00 ?? ?? ?? ?? ??}
   //of_1001C60  code 891e_exe
$bn_2 = {83 3D ?? ?? 00 01 00 B8 ?? ?? 00 01 74 0D 8B 10 3B D1 74 0B 8B C2 83 38 00 75 F3 39 08 75 04 8B 09 89 08 C3}
 //of_100179C code 891e_exe
$bn_3 = {54 83 04 24 04 55  89 2D ?? ?? 00 01 53 89 1D ?? ?? 00 01 E8 ?? FB FF FF C3}
//of_10014E0 code 891e_exe
$bn_4 = {8B FF 55 8B EC 8B 45 08 8A 08 40 84 C9 75 F9 2B 45 08 48 5D C2 04 00}
//of_11006F0 code 891e_exe
$bn_5 = {8B 7C 24 30 0F B6 F1 8B C6 99 89 44 24 38 89 54 24 3C 3B D5 0F 87 BB 00 00 00}
//more unpacking 891e_exe
//can't find this offset but it hits
$bn_6 = {8B 3D 88 51 47 00 66 C1 FE 10 66 C1 E6 10 03 CE 8B DF C0 E9 05 C0 E1 05 93 8B 5D C4 53 FF D0}
   //of_00406761 call before jump to unpacked section 232_exe
$bn_7 = {83 BD ?? ?? FF FF 03 ?? ?? }
 //of_00402C1C  jump table 232_exe
$bn_8 = {50 E8 ?? ?? FF FF C7 04 24 ?? ?? 4? 00 57 A3 ?? ?? ?? 00 FF D6 50 E8}
//of_0040DBEB fingerprint os 232_exe
$bn_9 = {8B FF 56 B8 ?? ?? ?? 00 BE ?? ?? ?? 00 57 8B F8 3B C6 73 0F}
// off_00409C41 232_exe
$pe = {E8 69 46 00 00 E9 89 FE FF FF 8B FF 55 8B EC 8B 55}
condition:
1 of ($pdb*) or 3 of ($st*) and 3 of ($bn*) or $pe
}

rule gozi_ursnif_1_unpacked
{
meta:
description = "Detects Gozi/Ursnif"
author = "Yaz"
date = "2020-1-20"
MITRE = "ID: S0386, Domain: Enterprise tactic: T1005,T1007,T1012,T1027,T1036,T1047,T1050,T1055,T1057,T1060,T1064,T1071,T1074,T1080,T1082,T1086,T1090,T1091,T1093,T1094,T1105,T1106,T1107,T1112,T1113,T1132,T1140,T1143,T1175,T1179,T1185,T1188,T1483,T1497 "
Hash = "bd445eb50b7a97a9c28da6adc3c2b1846736c34fa8206fd1c3b3e39b4563d09a"
strings:
$str_1 = "https://" fullword nocase wide ascii
$str_2 = "%08x%08x%08x%08x" fullword nocase wide ascii
$str_3 = "/images/" fullword nocase wide ascii
$str_4 = ".bmp" fullword nocase wide ascii
$str_5 = "attrib -h -r -s %%1" fullword nocase wide ascii
$str_6 = "type=%u&soft=%u&version=%u&user=%08x%08x%08x%08x&group=%u&id=%x&arc=%u&crc=%x&uptime=%u" fullword nocase wide ascii
$str_7 = "Mozilla/5.0 (Windows NT %u.%u;%s rv:50.0) Gecko/20100101 Firefox/50.0"
$str_8 = "file://" fullword nocase wide ascii
$str_9 = "%c%02X" fullword nocase wide ascii
$str_10 = "%s=%s&" fullword nocase wide ascii
$str_11 = "SUVWATAUAVAWH" fullword nocase wide ascii
$str_12 = "index.html" fullword nocase wide ascii
$str_13 = "Shell Folders" fullword nocase wide ascii
$str_14 = "Run" fullword nocase wide ascii
$str_15 = ".bat" fullword nocase wide ascii
$str_16 = "if exist %%1 goto %u"
$str_17 = "cmd /C"
$str_18 = "svchost.exe"
$str_20 = "Client"
$str_21 = "Client32"
$str_22 = "del %%0"
$str_23 = "321.txt"
$bn_1 = {7B 00 25 00 30 00 38 00 58 00 2D 00 25 00 30 00 34 00 58 00 2D 00 25 00 30 00 34 00 58 00 2D 00 25 00 30 00 34 00 58 00 2D 00 25 00 30 00 38 00 58 00 25 00 30 00 34 00 58 00 7D}
//string
$bn_2 = {68 74 74 70 73 3A 2F 2F}
//string
$bn_3 = {5C 00 70 00 69 00 70 00 65 00 5C}
//string
$bn_4 = {38 00 35 00 37 00 36 00 62 00 30 00 64 00 30}
//string
$bn_5 = {41 00 70 00 70 00 44 00 61 00 74 00 61 00}
//string
$bn_6 = {5A 00 6F 00 6E 00 65 00 2E 00 49 00 64 00 65 00 6E 00 74 00 69 00 66 00 69 00 65 00 72}
//string
$bn_7 = {20 2D 72 20 2D 73 20 2D 68 20 25 25 31 0D 0A 3A 25 75 0D 0A 64 65 6C 20 25 25 31 0D 0A 69 66 20 65 78 69 73 74 20 25 25 31 20 67 6F 74 6F 20 25 75 0D 0A 64 65 6C 20 25 25 30 0D 0A 00 3A 25 75 0D 0A 69 66 20 6E 6F 74 20 65 78 69 73 74 20 25 25 31 20 67 6F 74 6F 20 25 75 0D 0A 63 6D 64 20 2F 43 20 22 25 25 31 20 25 25 32 22}
//string
$bn_8 = {25 30 38 58 2D 25 30 34 58 2D 25 30 34 58 2D 25 30 34 58 2D 25 30 38 58 25 30 34 58 00 7B 25 30 38 58 2D 25 30 34 58 2D 25 30 34 58 2D 25 30 34 58 2D 25 30 38 58 25 30 34 58 7D}
//string
$bn_9 = {72 00 75 00 6E 00 61 00 73 00 00 00 63 00 6D 00 64}
//string
$bn_10 = {53 68 80 00 00 00 6A 03 53 [1-8] FF}
//offset_004016AE create file
condition:
9 of ($st*) and 3 of ($bn*)
}
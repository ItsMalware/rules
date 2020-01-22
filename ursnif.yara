rule gozi_ursnif_1
{
meta:
description = "Detects Gozi/Ursnif"
MITRE = "ID: S0386, Domain: Enterprise tactic: T1005,T1007,T1012,T1027,T1036,T1047,T1050,T1055,T1057,T1060,T1064,T1071,T1074,T1080,T1082,T1086,T1090,T1091,T1093,T1094,T1105,T1106,T1107,T1112,T1113,T1132,T1140,T1143,T1175,T1179,T1185,T1188,T1483,T1497 "
author = "Yaz"
date = "2019-12-10"
Hash = "891e049a76d40d402f822d5049ef0c84c4ec86cd03152bc2c050748bb69d7dac"
strings:
$str_1 = "LnfjionJHijejLKok03ro0jfdskkLljf.pdb"
$str_2 = "ole32.dll"
$str_3 = "snow %d  Order %srec"
$str_4 = "InventWord.pdb"
$str_5 = "xpxxxx"
$bn_1 = {55 89 E5 56 ?? ?? 83 E4 F8 81 EC ?? 00 00 00 ?? 84 24 C4 00 00 00 ?? ?? ?? ?? ??}
   //of_1C60 code
$bn_2 = {83 3D ?? ?? 00 01 00 B8 ?? ?? 00 01 74 0D 8B 10 3B D1 74 0B 8B C2 83 38 00 75 F3 39 08 75 04 8B 09 89 08 C3}
 //of_179C code
$bn_3 = {54 83 04 24 04 55  89 2D ?? ?? 00 01 53 89 1D ?? ?? 00 01 E8 ?? FB FF FF C3}
//of_14E0 code
$bn_4 = {8B FF 55 8B EC 8B 45 08 8A 08 40 84 C9 75 F9 2B 45 08 48 5D C2 04 00}
//of_16F0 code
$bn_5 = {59 5E 89 83 BB 14 42 00  89 C7 F3 A4 8B B3 C7 14 42 00 8D BB EF 14 42 00  29 F7 01 F8 FF E0}
//unpacking routine
$bn_6 = {8B 7C 24 30 0F B6 F1 8B C6 99 89 44 24 38 89 54 24 3C 3B D5 0F 87 BB 00 00 00}
//more unpacking
$bn_7 = {FF 93 D7 14 42 00}
//more unpacking
$pe = {E8 69 46 00 00 E9 89 FE FF FF 8B FF 55 8B EC 8B 55}
condition:
1 of ($st*) and 3 of ($bn*) or $pe
}
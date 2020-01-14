rule gozi_ursnif_1
{
meta:
description = "Detects Gozi/Ursnif"
author = "Yaz"
date = "2019-12-10"
Hash = "891e049a76d40d402f822d5049ef0c84c4ec86cd03152bc2c050748bb69d7dac"
strings:
$str_1 = "LnfjionJHijejLKok03ro0jfdskkLljf.pdb"
$str_2 = "ole32.dll"
$bn_1 = {55 89 E5 56 ?? ?? 83 E4 F8 81 EC ?? 00 00 00 ?? 84 24 C4 00 00 00 ?? ?? ?? ?? ??}
   //of_1C60 code
$bn_2 = {83 3D ?? ?? 00 01 00 B8 ?? ?? 00 01 74 0D 8B 10 3B D1 74 0B 8B C2 83 38 00 75 F3 39 08 75 04 8B 09 89 08 C3}
 //of_179C code
$bn_3 = {54 83 04 24 04 55  89 2D ?? ?? 00 01 53 89 1D ?? ?? 00 01 E8 ?? FB FF FF C3}
//of_14E0 code
$bn_4 = {8B FF 55 8B EC 8B 45 08 8A 08 40 84 C9 75 F9 2B 45 08 48 5D C2 04 00}
//of_16F0 code
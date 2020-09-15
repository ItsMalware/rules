rule valak
{
meta:
 description = "Detects valak"
 author = "Yaz"
 date = "2020-09-01"
 MITRE = "T1087.002, T1087.001, T1071.001, T1059.001, T1140, T1114.002, T1041, T1564.004, T1105, T1112, T1027, T1057, T1053.005, T1113, T1218.01, T1518.001, T1082, T1016, T1033, T1204.002"
 Hash = "2C75E5005993FFF65B5B8310C3C50C2E0AC219BA7014F5C480736636E7C5DCD5" // packed
strings:
$header = { 4D 5A }
$magic1 = {8B FF 55 8B EC 83 7D 0C 01 75 05 E8 9A 66 00 00 FF}  //entry point
$st01 = "fatorder.pdb" fullword nocase wide ascii 
$bn01 = {59 5E 89 83 BE 88 AD 00 89 C7 F3 A4 8B B3 CA 88 AD 00 8D BB EE 88 AD 00 29 F7 01 F8 FF E0}
//Jump to unpack
$bn02 = {E8 C3 F6 FF FF 8B 4D FC 03 F8 13 DA 8D 54 09 D9 89 3D 28 73 04 10 89 1D 2C 73 04 10 66 89 15 78 73 04 10 5F B8 49 02 00 00 2B C3 FF D7}
// unpacking
$bn03 = {4a 49 48 4f 34 37 59 36 74 75 76 77 74}
// string
condition:
$header at 0 and all of ($magic*) and all of ($st*) and 2 of ($bn*)
}
rule valak_unpacked
{
meta:
 description = "Detects valak unpacked binary"
 author = "Yaz"
 date = "2020-09-01"
 Hash = "7D43BB4170D7EF155413578E6D807C81C5777FD89844316200A36713709F8853" // unpacked
strings:
$header = { 4D 5A }
$magic1 = {55 8B EC 83 7D 0C 01 75 05 E8 87 01 00 00 FF 75 10}  //entry point
$st01 = "kbdusm.pdb" fullword nocase wide ascii 
$st02 = "WriteConsoleW" fullword wide ascii
$st03 = "CreateFileW" fullword nocase wide ascii
$st04 = "WriteFile" fullword nocase wide ascii
$st05 = "DllRegisterServer" fullword nocase wide ascii
condition:
$header at 0 and all of ($magic*) and all of ($st*)
}
rule valak_js
{
meta:
 description = "Detects valak loaded js file"
 author = "Yaz"
 date = "2020-09-01"
 Hash = "0EAB2D2538E95419E764BD23408AD7E0CB830B3DF3E3E1A77C71AF75E6184DD9" // JS nemucod
strings:
$st01 = "var config" fullword nocase wide ascii 
$st02 = "PRIMARY_C2" fullword wide ascii
$st03 = "SOFT_SIG" fullword nocase wide ascii
$st04 = "SOFT_VERSION" fullword nocase wide ascii
$st05 = "C2_REQUEST_SLEEP" fullword nocase wide ascii
$st06 = "C2_FAIL_SLEEP" fullword nocase wide ascii
$st07 = "C2_FAIL_COUNT" fullword nocase wide ascii
$st08 = "C2_OB_KEY" fullword nocase wide ascii
$st09 = "C2_PREFIX" fullword nocase wide ascii
condition:
all of ($st*)
}

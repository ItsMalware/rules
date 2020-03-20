rule Carberp_unpacked_injected
{
meta:
date = "2019-12-03"
names = "Carberp"
sample = "1f643b069b37a98f8a0a6d3501ec4d180cac727b831479d56cacf35129644f3d"
MITRE = "T1115, T1132, T1068, T1107, T1037, T1050, T1027, T1057, T1055, T1060, T1105, T1085, T1053, T1113, T1064, T1071,T1082, T1016"
strings:
$string_1 = "DeleteFileA" nocase 
$string_2 = "GetWindowThreadProcessId" nocase
$string_3 = "OutOfHibernation" nocase
$string_4 = "WS2_32.dll" nocase 
$string_5 = "AgentPassive.log" nocase 
$string_6 = "Amount" nocase 
$string_7 = "Account2" nocase 
$string_8 = "svchost.exe" nocase 
$string_9 = "err_bl.exe" nocase 
$string_10 = "mswsock.dll" nocase 
$string_11 = "NtQueryInformationFile" nocase 
$string_12 = "GET" nocase 
$string_13 = "update PAYDOCRU set DOCUMENTDATE=?, STATUS=30001 where PAYERACCOUNT=? and DOCUMENTDATE=? and DOCUMENTNUMBER like '%%%s%%'" nocase 
$string_14 = "update ACCOUNT set REST=%s where ACCOUNT=?" nocase 
$string_15 = "cbank_copy.txt" nocase 
$string_16 = "---> <TextLog%d> [%s]" nocase 
$string_17 = "DLL -> Login: '%s', Password system: '%s', Password keys: '%s', Path keys: %s, Client folder: %s" nocase 
$string_18 = " /stat?uptime=%d&downlink=%d&uplink=%d&id=%s&statpass=%s&comment=%s HTTP/1.0" nocase 
$string_19 = "select Param from Config where Code='MyBankId'" nocase 
$string_20 = "READY" nocase 
$string_21 = "HELLO" nocase 
$string_22 = "igxpdv32.dat" nocase 
$string_23 = "igxpgd32.dat" nocase 
$string_24 = "%bot_id%" nocase 
$string_25 = "cbank" nocase 
$string_26 = "hstbmld.sgl" nocase 
$string_27 = "bnk.list" nocase 
$string_28 = "nobnk.list" nocase 
$string_29 = "CBankClient" nocase
$string_30 = "cbrplstf01.dat" nocase
$tag_1 = "os31 os31"
$tag_2 = "os16 os16 ot is16"
$tag_3 = "HJGsdlk873d"
$tag_4 = {6F 73 31 36 00 00 00 00 69 73 31 36 20 69 74}
//string
$tag_5 = {4b 38 44 46 61 47 59 55 73 38 33 4b 46 30 35 54}
//string
condition:
uint16(0) == 0x5a4d and 10 of ($string*) and 1 of ($tag*)
}

rule nanocore_unpacked_client_mod
{
meta:
date = "2020-02-12"
author = "yaz"
names = "NanoCore RAT"
sample = "2f5e9944447519b5eeaeb6ec50c20703896977317b9247b9f00c76c71af362ba"
MITRE = "T1123,T1059,T1089,T1056,T1112,T1027,T1060,T1105,T1064,T1032,T1016,T1065,T1125"
Groups = "SilverTerrier, gorgon group, apt 33, group 5"
strings:
$str_1 = "NanoCore"
$str_2= "ClientPlugin"
$str_3  = "ProjectData"
$str_4  = "DESCrypto"
$str_5  = "KeepAlive"
$str_6 = "IPNETROW"
$str_7  = "LogClientMessage"
$str_8 = "|ClientHost"
$str_9 = "get_Connected"
$str_10 = "#=q"
$key = {43 6f 24 cb 95 30 38 39}

condition:  
(filesize < 4MB) and (7 of them)
}

rule nanocore_unpacked_surveillance_mod
{
meta:
date = "2020-02-12"
author = "yaz"
names = "NanoCore RAT surveillance module"
sample = "01e3b18bd63981decb384f558f0321346c3334bb6e6f97c31c6c95c4ab2fe354"
MITRE = "T1123,T1059,T1089,T1056,T1112,T1027,T1060,T1105,T1064,T1032,T1016,T1065,T1125"
Groups = "SilverTerrier, gorgon group, apt 33, group 5"
strings:
$str_1 = "SurveillanceExClientPlugin.dll"
$str_2= "KeyboardLogging"
$str_3  = "Lzma"
$str_4  = "DNSLogging"
$str_5  = "keyboardType"
$str_6 = "ExportLogs"
$str_7  = "LogToServer"
$str_8 = "HandleLoggingCommandDeleteLogs"
$str_9 = "ViewLogs"
$str_10 = "ApplicationLogging"
$str_11 = "<Module>"
$str_12 = "NanoCore"

condition:  
10 of ($str*)
}

rule nanocore_unpacked_clientplugin
{
meta:
date = "2020-02-12"
author = "yaz"
names = "NanoCore RAT client plugin"
sample = "61e9d5c0727665e9ef3f328141397be47c65ed11ab621c644b5bbf1d67138403"
MITRE = "T1123,T1059,T1089,T1056,T1112,T1027,T1060,T1105,T1064,T1032,T1016,T1065,T1125"
Groups = "SilverTerrier, gorgon group, apt 33, group 5"
strings:
$str_1 = "LogClientException"
$str_2= "Shutdown"
$str_3  = "IClientApp"
$str_4  = "Restart"
$str_5  = "NanoCore.My"
$str_6 = "IClientUIHost"
$str_7  = "ReadPacket"
$str_8 = "Disconnect"
$str_9 = "ClientPlugin.dll"
$str_10 = "Create__Instance__"
$str_11 = "<Module>"
$str_12 = "LogClientMessage"
$str_13 = "NanoCore"

condition:  
10 of ($str*)
}

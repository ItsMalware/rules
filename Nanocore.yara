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
$str_11 = "Connecting to {0}:{1}.." wide
$cmd1 = "/create /f /tn \"{0}\" /xml \"{1}\"" wide
$cmd2 = "/run /tn \"{0}\"" wide
$cmd3 = "delete /f /tn \"{0}\"" wide
$key = {43 6f 24 cb 95 30 38 39}

condition:  
7 of ($str*) or 3 of ($cmd*) or $key
//(filesize < 4MB) and (7 of them)
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


rule nanocore_unpacked_AdderallProtector
{
meta:
date = "2020-02-12"
author = "yaz"
names = "NanoCore RAT client plugin"
sample = "62ef08a5c74414efa2918b4e43450cae5c2e111ca1f9aa4071be1209b1c64307"
MITRE = "T1123,T1059,T1089,T1056,T1112,T1027,T1060,T1105,T1064,T1032,T1016,T1065,T1125"
Groups = "SilverTerrier, gorgon group, apt 33, group 5"
strings:
$str_1 = "AdderallProtector\\c__DisplayClass186_0.pdb"
$str_2= "DebuggableAttribute"
$str_3  = "DebuggingModes"
$str_4  = "get_EntryPoint"
$str_5  = "c__DisplayClass186_0"
$str_6 = "kernel32.dll"
$str_7  = "BlockCopy"
$str_8 = "Assembly"
$str_9 = "GetBytes"
$str_10 = "System.Runtime.CompilerServices"
$name  = "AdderallProtector"

condition:  
9 of ($str*) and $name
}



rule nanocore_unpacked_rivermod
{
meta:
date = "2020-02-12"
author = "yaz"
names = "NanoCore RAT client plugin"
sample = "1f371c8b5a90aa9296a2970cfe84121378ddb83313e87e8288e1db18916d3c1d"
MITRE = "T1123,T1059,T1089,T1056,T1112,T1027,T1060,T1105,T1064,T1032,T1016,T1065,T1125"
Groups = "SilverTerrier, gorgon group, apt 33, group 5"
strings:
$str_1 = "mYMQHdorwIIC"
$str_2= "cmd.exe"
$str_3  = "HoNaNttjyHxpJTCy.river.exe"
$str_4  = "UserProfile"
$str_5  = "powershell"
$str_6 = "URL=file:///"
$str_7  = "<Module>"
$str_8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
$str_9 = "DeleteFile"
$str_10 = "startURL"
$str_11 = "[InternetShortcut]"
$cmd1  = "/C choice /C Y /N /D Y /T 3 & Del \""
$cmd2 = " /MO 1 /tr "
$cmd3 = "/query"
$cmd4 = "/create /sc MINUTE /tn"


condition:  
9 of ($str*) and 2 of ($cmd*)
}

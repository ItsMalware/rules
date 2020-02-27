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
$str_1 = "NanoCore" nocase wide ascii
$str_2= "ClientPlugin" nocase wide ascii
$str_3  = "ProjectData" nocase wide ascii
$str_4  = "DESCrypto" nocase wide ascii
$str_5  = "KeepAlive" nocase wide ascii
$str_6 = "IPNETROW" nocase wide ascii
$str_7  = "LogClientMessage" nocase wide ascii
$str_8 = "|ClientHost" nocase wide ascii
$str_9 = "get_Connected" nocase wide ascii
$str_10 = "#=q" nocase wide ascii
$str_11 = "Connecting to {0}:{1}.." wide
$cmd1 = "/create /f /tn \"{0}\" /xml \"{1}\"" wide
$cmd2 = "/run /tn \"{0}\"" wide
$cmd3 = "delete /f /tn \"{0}\"" wide

condition:  
7 of ($str*) or 3 of ($cmd*)
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
$str_1 = "SurveillanceExClientPlugin.dll" nocase wide ascii
$str_2= "KeyboardLogging" nocase wide ascii
$str_3  = "Lzma" nocase wide ascii
$str_4  = "DNSLogging" nocase wide ascii
$str_5  = "keyboardType" nocase wide ascii
$str_6 = "ExportLogs" nocase wide ascii
$str_7  = "LogToServer" nocase wide ascii
$str_8 = "HandleLoggingCommandDeleteLogs" nocase wide ascii
$str_9 = "ViewLogs" nocase wide ascii
$str_10 = "ApplicationLogging" nocase wide ascii
$str_11 = "<Module>" nocase wide ascii
$str_12 = "NanoCore" nocase wide ascii

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
$str_1 = "LogClientException" nocase wide ascii
$str_2= "Shutdown" nocase wide ascii
$str_3  = "IClientApp" nocase wide ascii
$str_4  = "Restart" nocase wide ascii
$str_5  = "NanoCore.My" nocase wide ascii
$str_6 = "IClientUIHost" nocase wide ascii
$str_7  = "ReadPacket" nocase wide ascii
$str_8 = "Disconnect" nocase wide ascii
$str_9 = "ClientPlugin.dll" nocase wide ascii
$str_10 = "Create__Instance__" nocase wide ascii
$str_11 = "<Module>" nocase wide ascii
$str_12 = "LogClientMessage" nocase wide ascii
$str_13 = "NanoCore" nocase wide ascii

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
$str_1 = "AdderallProtector\\c__DisplayClass186_0.pdb" nocase wide ascii
$str_2= "DebuggableAttribute" nocase wide ascii
$str_3  = "DebuggingModes" nocase wide ascii
$str_4  = "get_EntryPoint" nocase wide ascii
$str_5  = "c__DisplayClass186_0" nocase wide ascii
$str_6 = "kernel32.dll" nocase wide ascii
$str_7  = "BlockCopy" nocase wide ascii
$str_8 = "Assembly" nocase wide ascii
$str_9 = "GetBytes" nocase wide ascii
$str_10 = "System.Runtime.CompilerServices" nocase wide ascii
$name  = "AdderallProtector" nocase wide ascii

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
$str_1 = "mYMQHdorwIIC" nocase wide ascii
$str_2= "cmd.exe" nocase wide ascii
$str_3  = "HoNaNttjyHxpJTCy.river.exe" nocase wide ascii
$str_4  = "UserProfile" nocase wide ascii
$str_5  = "powershell" nocase wide ascii
$str_6 = "URL=file:///" nocase wide ascii
$str_7  = "<Module>" nocase wide ascii
$str_8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide
$str_9 = "DeleteFile"  nocase wide ascii
$str_10 = "startURL"  nocase wide ascii
$str_11 = "[InternetShortcut]" wide
$cmd1  = "/C choice /C Y /N /D Y /T 3 & Del \"" wide
$cmd2 = " /MO 1 /tr "  wide
$cmd3 = "/query" wide
$cmd4 = "/create /sc MINUTE /tn" wide

condition:  
9 of ($str*) and 3 of ($cmd*)
}

rule nanocore_unpacked_decoder
{
meta:
date = "2020-02-12"
author = "yaz"
names = "NanoCore RAT decorder dll"
sample = "1f371c8b5a90aa9296a2970cfe84121378ddb83313e87e8288e1db18916d3c1d"
MITRE = "T1123,T1059,T1089,T1056,T1112,T1027,T1060,T1105,T1064,T1032,T1016,T1065,T1125"
Groups = "SilverTerrier, gorgon group, apt 33, group 5"
strings:
$str_1 = "Lzma#.dll" nocase wide ascii
$str_2= "<Module>" nocase wide ascii
$str_3  = "Decompress" nocase wide ascii
$str_4  = "Decoder" nocase wide ascii
$str_5  = "m_Decoders" nocase wide ascii
$str_6 = "Decoder2" nocase wide ascii
$str_7  = "Compression.LZ" nocase wide ascii
$str_8 = "Flush" nocase wide ascii
$str_9 = "MemoryStream"  nocase wide ascii
$str_10 = "SeekOrigin"  nocase wide ascii

condition:  
all of ($str*)
}

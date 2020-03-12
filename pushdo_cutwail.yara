rule pusho_cutwail
{
meta:
date = "2020-03-10"
author = "yaz"
names = "Pushdo"
sample = "apt 37, Gamaredon Group"
MITRE = "T1035,. T1215, T1060, T1055,  T1107, T1112, T1055, T1046,  T1120, T1057, T1012, T1076, T1114, T1002 "
Groups = ""
strings:
$str_1 = "USERPROFILE" nocase wide ascii
$str_2 = "%s\\%s.exe" nocase wide ascii
$str_3 = "software\\microsoft\\windows\\currentversion\\run" nocase wide ascii
$str_4 = "QkkXa" nocase wide ascii
$str_5 = "http://%s/" nocase wide ascii
$str_6 = "Accept-Encoding: gzip, deflate" nocase wide ascii
$str_7 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" nocase wide ascii
$str_8 = "Accept-Language: en-us" nocase wide ascii
$str_9 = "\\system32\\svchost.exe" nocase wide ascii
$str_10 = "Accept: */*" nocase wide ascii
$str_11 = "zxtsrqpnmlkgfdcb" nocase wide ascii
$trgt1 = "Win2K" nocase wide ascii
$trgt2 = "WinXP" nocase wide ascii
$trgt3  = "WinXP64" nocase wide ascii
$trgt4 = "WinServer2003" nocase wide ascii
$trgt5 = "WinServer2003R2" nocase wide ascii
$trgt6 = "WinHomeServer" nocase wide ascii
$trgt7 = "Vista" nocase wide ascii
$trgt8 = "WinServer2008" nocase wide ascii
$trgt9 = "WinServer2008R2" nocase wide ascii
$trgt10 = "WinServer2012" nocase wide ascii
$trgt11 = "UndefinedOS" nocase wide ascii
$cmd1 = "if exist %s goto :repeat" wide
$cmd2 = "del %%0" wide
$cmd3 = "%s:%u" wide
$cmd4 = ":repeat" wide

condition: 
7 of ($str*) and 4 of ($trgt*)or 3 of ($cmd*) and 4 of ($trgt*)
}

rule unpackedTrickBot {
meta:
  date = "2019-10-2019"
  names = "Trickbot"
  sample = ""
  MITRE = "ID: S0266 Domain: Enterprise tactic: T1087, T1043, T1503, T1081, T1214, T1024, T1005, T1140, T1089, T1482, T1114, T1106, T1083, T1179, T1185, T1112, T1027, T1055, T1060, T1105, T1053, T1064, T1045, T1193, T1071, T1082, T1016, T1007, T1065, T1204 "
  Groups = "TA505"
strings:
  $ua1 = "TrickLoader" ascii wide
  $ua2 = "TrickBot" ascii wide
  //$ua3 = "BotLoader" ascii wide
  $str1 = "<moduleconfig>*</moduleconfig>" ascii wide
  $str2 = "group_tag" ascii wide
  $str3 = "client_id" ascii wide
condition:
  any of ($ua*) or all of ($str*)
}
rule unpacked_TrickBot_ver1033 {
meta:
  date = "2019-10-2019"
  names = "Trickbot"
  sample = ""
  MITRE = "ID: S0266 Domain: Enterprise tactic: T1087, T1043, T1503, T1081, T1214, T1024, T1005, T1140, T1089, T1482, T1114, T1106, T1083, T1179, T1185, T1112, T1027, T1055, T1060, T1105, T1053, T1064, T1045, T1193, T1071, T1082, T1016, T1007, T1065, T1204 "
  Groups = "TA505"
strings:
  $rsrc1 = "CONFIG" wide
  $rsrc2 = "KEY" wide
  $str1 = "gtag" ascii
  $str2 = "serv" ascii
  $str3 = "auto" ascii
  $str4 = "ECS30" ascii
  $str5 = "64"
  $str6 = "32"
  $clsid_tasksch = {9f 36 87 0f e5 a4 fc 4c bd 3e 73 e6 15 45 72 dd}
  $iid_itasksvc = {c7 a4 ab 2f a9 4d 13 40 96 97 20 cc 3f d4 0f 85}
condition:
  all of ($str*) and (all of ($rsrc*) or ($clsid_tasksch and $iid_itasksvc))
}
rule MALW_trickbot_bankBot {
meta:
  date = "2019-10-2019"
  names = "Trickbot"
  sample = ""
  MITRE = "ID: S0266 Domain: Enterprise tactic: T1087, T1043, T1503, T1081, T1214, T1024, T1005, T1140, T1089, T1482, T1114, T1106, T1083, T1179, T1185, T1112, T1027, T1055, T1060, T1105, T1053, T1064, T1045, T1193, T1071, T1082, T1016, T1007, T1065, T1204 "
  Groups = "TA505"
strings:
  $str_trick_01 = "moduleconfig"
  $str_trick_02 = "Start"
  $str_trick_03 = "Control"
  $str_trick_04 = "FreeBuffer"
  $str_trick_05 = "Release"
condition:
  all of ($str_trick_*)
}
rule unpackedTrickLoader4 {
meta:
  date = "2019-10-2019"
  names = "Trickbot"
  MITRE = "ID: S0266 Domain: Enterprise tactic: T1087, T1043, T1503, T1081, T1214, T1024, T1005, T1140, T1089, T1482, T1114, T1106, T1083, T1179, T1185, T1112, T1027, T1055, T1060, T1105, T1053, T1064, T1045, T1193, T1071, T1082, T1016, T1007, T1065, T1204 "
  Groups = "TA505"
  packed_sha256="cd91143d8634199004677c14fd1919b8cf01397979e9839f5325d8beade1609b"
  unpacked_sha256="6e48c6814654f809a9d49e66eb4ccc009c85db5e9361a5332cb2410febe280a2"
str_decode_offset=401020
strings:
  $str_decode1 = {c0 f? 04 [0-2] 24 03 02 c0}
  $str_decode2 = {c0 f? 02 [0-2] c0 e? 04 80 e? 0f}
  $str_decode3 = {c0 f? 04 ?0 e? 03}
  $str_decode4 = {c0 f? 02 [0-2] c0 e? 06}
  $prng1 = {39 30 00 00}
  $prng2 = {29 e5 0a 00}
  $prng3 = {69 4d 02 00}
condition:
  3 of ($str_decode*) and any of ($prng*)
}

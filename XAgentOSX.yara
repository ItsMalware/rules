rule XAgentOSX {
   meta:
      description = "Malicious X-Agent Samples Targeting Mac Devices"
      author = "Insikt Group"
      date = "2019-03-15"
      MITRE = "T1503,T1106,T1083,T1107,T1056,T1120,T1057,T1113,T1071,T1082,T1033"
      Groups = "APT28"
      hash1 = "86a588672837afdc1900ad9e78c7d0ae7a842bdd972dbdc5bdff2574a37f5acc"
      hash2 = "7ecc0ab55a3f5e016f48eafafc26b7c7a1dd55db2d85d94f585618013b1fda4c"
      hash3 = "28ac812912a7517a4527d3a97c356207df1b3a4725838de99e1cc535dea64a05"
      hash4 = "2a854997a44f4ba7e307d408ea2d9c1d84dde035c5dab830689aa45c5b5746ea"
      hash5 = "140bfc2ca34c06ccd3572b2df73e1b3bffb963e1ee1ff0526471a93fb346e7fb"
   strings:
      $x1 = "SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins WHERE timePasswordChanged/1000 BETWEEN ? AND ?" fullword ascii
      $x2 = "/Users/kazak/Desktop/Project/XAgentOSX/XAgentOSX/Source/Modules/InjectApp/" fullword ascii
      $x3 = "/Users/kazak/Desktop/Project/XAgentOSX/XAgentOSX/Source/Modules/Keylogger/Keylogger.h" fullword ascii
      $x4 = "/Users/kazak/Desktop/Project/XAgentOSX/XAgentOSX/Source/Modules/Keylogger/" fullword ascii
      $x5 = "/Users/kazak/Desktop/Project/XAgentOSX/XAgentOSX/Source/Modules/RemoteShell/" fullword ascii
      $x6 = "/Users/kazak/Desktop/Project/XAgentOSX/XAgentOSX/Source/Channels/HTTP/HTTPChannel.h" fullword ascii
      $x7 = "/Users/kazak/Desktop/Project/XAgentOSX/XAgentOSX/Source/Library/Kernel/" fullword ascii
      $s8 = "__ZL58__arclite_NSMutableDictionary__setObject_forKeyedSubscriptP19NSMutableDictionaryP13objc_selectorP11objc_objectS3_" fullword ascii
      $s9 = "/Users/kazak/Desktop/Project/XAgentOSX/XAgentOSX/Source/Modules/FileSystem/" fullword ascii
      $s10 = "/Users/kazak/Desktop/Project/XAgentOSX/XAgentOSX/Source/Channels/HTTP/Https/" fullword ascii
      $s11 = "/Users/kazak/Desktop/Project/XAgentOSX/XAgentOSX/Source/Library/SBJSon/SBJsonStreamParserAccumulator.h" fullword ascii
      $s12 = "/Users/kazak/Desktop/Project/XAgentOSX/XAgentOSX/Source/Library/SBJSon/SBJsonStreamParserAdapter.h" fullword ascii
      $s13 = "/Users/kazak/Desktop/Project/XAgentOSX/XAgentOSX/Source/Library/SBJSon/SBJsonStreamWriterAccumulator.h" fullword ascii
      $s14 = "/Users/kazak/Desktop/Project/XAgentOSX/XAgentOSX/Source/Library/Kernel/../../Kernel/KernelStructs.h" fullword ascii
      $s15 = "-[RemoteShell executeShellCommand:]" fullword ascii
      $s16 = "/Users/kazak/Desktop/Project/XAgentOSX/XAgentOSX/Source/Channels/HTTP/" fullword ascii
      $s17 = "/Users/kazak/Desktop/Project/XAgentOSX/XAgentOSX/Source/Library/SBJSon/SBJsonTokeniser.h" fullword ascii
      $s18 = "/Users/kazak/Desktop/Project/XAgentOSX/XAgentOSX/Source/Library/SBJSon/SBJsonUTF8Stream.h" fullword ascii
      $s19 = "/Users/kazak/Desktop/Project/XAgentOSX/XAgentOSX/Source/Library/SBJSon/SBJsonStreamWriter.h" fullword ascii
      $s20 = "/Users/kazak/Desktop/Project/XAgentOSX/XAgentOSX/Source/Library/SBJSon/SBJsonStreamParser.h" fullword ascii
   condition:
      ( uint16(0) == 0xfacf and filesize < 2000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

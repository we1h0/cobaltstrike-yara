rule CS_encrypted_beacon_x86 {
    meta:
        author = "Etienne Maynier tek@randhome.io"

    strings:
        $s1 = { fc e8 ?? 00 00 00 }
        $s2 = { 8b [1-3] 83 c? 04 [0-1] 8b [1-2] 31 }
    condition:
        $s1 at 0 and $s2 in (0..200) and filesize < 300000
}

rule CS_encrypted_beacon_x86_64 {
    meta:
        author = "Etienne Maynier tek@randhome.io"

    strings:
        $s1 = { fc 48 83 e4 f0 eb 33 5d 8b 45 00 48 83 c5 04 8b }
    condition:
        $s1 at 0 and filesize < 300000
}

rule CS_beacon {
    meta:
        author = "Etienne Maynier tek@randhome.io"

    strings:
        $s1 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
        $s2 = "%s as %s\\%s: %d" ascii
        $s3 = "Started service %s on %s" ascii
        $s4 = "beacon.dll" ascii
        $s5 = "beacon.x64.dll" ascii
        $s6 = "ReflectiveLoader" ascii
        $s7 = { 2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f }
        $s8 = { 69 68 69 68 69 6b ?? ?? 69 6b 69 68 }
        $s9 = "%s (admin)" ascii
        $s10 = "Updater.dll" ascii
        $s11 = "LibTomMath" ascii
        $s12 = "Content-Type: application/octet-stream" ascii
    condition:
        6 of them and filesize < 300000
}

rule CobaltStrike_sleepmask {
	meta:
		description = "Static bytes in Cobalt Strike 4.5 sleep mask function that are not obfuscated"
		author = "CodeX"
		date = "2022-07-04"
	strings:
		$sleep_mask = {48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 45 33 DB 45 33 D2 33 FF 33 F6 48 8B E9 BB 03 00 00 00 85 D2 0F 84 81 00 00 00 0F B6 45 }
	condition:
		$sleep_mask
}

rule artifact_beacon {
   meta:
      description = "from files artifact.exe, beacon.exe"
      date = "2021-04-09"
   strings:
      $s = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii
   condition:
      $s
}

rule CobaltStrike_Malleable_C2_GIF : CobaltStrike GIF
{
	meta:
		description = "Detects the Cobalt Strike Malleable C2 fake GIF"
		author = "@nric0"
		reference = "https://github.com/rsmudge/Malleable-C2-Profiles/blob/master/normal/webbug_getonly.profile" 
		version = "2"
		date = "2019-06-30"

	strings:
		$gifmagic = { 47 49 46 38 39 61 01 00 01 00 80 00 00 00 00 FF FF FF 21 F9 04 01 00 00 00 2C 00 00 00 00 01 00 01 00 00 02 01 44 00 3B }
	condition:
		filesize > 10KB and $gifmagic at 0
}

rule CobaltStrike_beaconEye { 
  strings:  
    $cobaltStrikeRule64 = {  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00 (00|01|02|04|08|10) 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 00  02 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00  02 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00  01 00 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 00 } 
    $cobaltStrikeRule32 = {  00 00 00 00 00 00 00 00  01 00 00 00 (00|01|02|04|08|10) 00 00 00 01 00 00 00 ?? ?? 00 00  02 00 00 00 ?? ?? ?? ??  02 00 00 00 ?? ?? ?? ??  01 00 00 00 ?? ?? 00 00 }
  condition: any of them
}

rule cobaltstrike_beacon_4_2_sleepMask8
{
meta:
    author = "Elastic"
    description = "Identifies deobfuscation routine used in Cobalt Strike Beacon DLL version 4.2."
strings:
    $a_x64 = {89 C2 45 09 C2 74 1F 41 39 C0 76 E9 4C 8B 13 49 89 C3 41 83 E3 07 49 01 C2 46 8A 5C 1B 10 48 FF C0 45 30 1A}
    $a_x86 = {8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2}
condition:
     any of them
}

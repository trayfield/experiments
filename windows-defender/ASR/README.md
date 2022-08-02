# Attack Surface Reduction

[Attack Surface Reduction (ASR)](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/overview-attack-surface-reduction?view=o365-worldwide) is a Microsoft feature to *Reduce vulnerabilities (attack surfaces) in your applications with intelligent rules that help stop malware*.

This repository tries to describe what the rules are and what they actually check.
This is likely incomplete, and only limited to the author's understanding of ASR.

Note: A few ASR bypasses are already known (as the ones from [Emeric Nasi from SEVAGAS](https://blog.sevagas.com/IMG/pdf/bypass_windows_defender_attack_surface_reduction.pdf) or [this gist from infosecn1nja](https://gist.github.com/infosecn1nja/24a733c5b3f0e5a8b6f0ca2cf75967e3)). Still, one could argue that these rules might be a good way to limit low-level, widespread attack attempts.

## Finding ASR rules implementation

### Targeting the right binary

As the [overview](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/overview-attack-surface-reduction?view=o365-worldwide) page says:

>  (Requires Microsoft Defender Antivirus)

Another hint can be found in the [FAQ](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-faq?view=o365-worldwide):

> ASR was ....  introduced as a major update to Microsoft Defender Antivirus

It looks like ASR rules are implemented and enforced by Windows Defender.

Rules are configured through the following registry key: `HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`.

For instance, to enable the *Use advanced protection against ransomware* rule (GUID `c1db55ab-c21a-4637-bb3f-a12568109d35`), one adds a registry value `c1db55ab-c21a-4637-bb3f-a12568109d35` set to `1`, to the aforementioned registry key.

As expected, on `Windows Defender Service` start, `MsMpEng` (the Windows Defender engine) reads the registry key:
![](img/procmon_msmpeng.png)

### Looking for our GUIDs

Windows Defender is made of several components, including:

* WdFilter, the filter driver ([here](https://www.n4r1b.com/posts/2020/01/dissecting-the-windows-defender-driver-wdfilter-part-1/) is a good ressource about it)
* WdBoot, the ELAM part
* `MpSvc.dll`, `MpClient.dll`, `MpCmdRun.exe`: interfaces with the engine
* `mpengine.dll`: the actual engine implementation
* `mpasbase.vdm`, `mpavbase.vdm`: engine ressources (signatures, emulation ressources, etc.)

As the rules [are referenced with GUID](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction?view=o365-worldwide#attack-surface-reduction-rules), they can be looked for in these binaries. Unfortunately, this naive approach does not yield any result.

But we can look further in the VDM files. Their contents can be retrieved using [WDExtract](https://github.com/hfiref0x/WDExtract).

Looking for one of the GUID (`be9ba2d9-53ea-4cdc-84e5-9b1eeee46550`), we have a hit in `mpasbase.vdm.extracted`, more specifically in the DLL `module1025.dll`:

![](img/hex_guid_found.png)

Looking above:

![](img/hex_lua_sig.png)

`1B 4C 75 61` is the signature of a precompiled Lua script. The next byte, `51` indicates the Lua engine version (5.1).

So, it seems that at least a part of ASR is written using the Lua engine of MpEngine.

## Investigating the LUA engine

The Lua engine is able to call functions implemented in the MpEngine DLL. For instance, the `IsHipsRuleEnabled` that we saw above is implemented as:

![](img/ida_ishipsruleenabled.png)

Let's try to break on this function to ensure it is actually reached.

To debug Windows Defender, we'll need two things:
* It's a PPL process. We can remove this protection using Mimikatz:
```sh
mimikatz # !+
[*] 'mimidrv' service not present
[+] 'mimidrv' service successfully registered
[+] 'mimidrv' service ACL to everyone
[+] 'mimidrv' service started

mimikatz # !processprotect /process:msMpEng.exe /remove
Process : msMpEng.exe
PID 1936 -> 00/00 [0-0-0]
```
* The driver part registers a `ObRegisterCallback` to [defend itself against memory reads/writes from other processes](https://www.n4r1b.com/posts/2020/03/dissecting-the-windows-defender-driver-wdfilter-part-3/). One way to remove it is to attach a kernel debugger to our target system and "NOP" the function:
```
kd> a WdFilter!MpObPreOperationCallback
fffff801`beb3ef40 xor eax,eax
fffff801`beb3ef42 ret
fffff801`beb3ef43
```

(This method is also documented [here](https://qiita.com/msmania/items/19547606b9c197c64d70) and [here](https://github.com/Mattiwatti/PPLKiller/pull/6#issuecomment-346198366), and on some cheating forums :) )

Now we can set a breakpoint on `IsHipsRuleEnabled`. Upon manually scanning a file, our breakpoint is reached; looking at the call stack, it indeed comes from the Lua interpretor, especially the `luaD_precall` and `luaD_call` functions.

### Decompiling the scripts

Let's extract the script starting at `\x1bLua`.
Trying to decompile it using standard tools as [luadec](https://github.com/viruscamp/luadec) unfortunately fails on:
```
out.1.luac: bad header in precompiled chunk
```

Still, the project works on sample scripts compiled with `lua-5.1`.

Digging into the format, according to [A No-Frills Introduction to Lua 5.1 VM Instructions](http://luaforge.net/docman/83/98/ANoFrillsIntroToLua51VMInstructions.pdf) ([mirror](http://underpop.free.fr/l/lua/docs/a-no-frills-introduction-to-lua-5.1-vm-instructions.pdf)), the difference seems to be in the header and data structure sizes.

Using a [naive script](https://github.com/commial/experiments/tree/master/windows-defender/lua), one can convert the Lua from VDM files into a precompiled script that `luadec` can deal with.

As a result, we obtain:
```lua
-- params : ...
-- function num : 0
local l_0_0 = function(l_1_0, l_1_1)
  -- function num : 0_0
  local l_1_2 = {}
  l_1_2[1952539182] = ""
  l_1_2[1684890414] = ""
  l_1_2[1836016430] = ""
  l_1_2[1819304750] = ""
  l_1_2[1702389038] = ""
  l_1_2[1718186030] = ""
  l_1_2[1919120174] = ""
  l_1_2[1935832622] = ""
  l_1_2[1802398766] = ""
  l_1_2[1718843182] = ""
  l_1_2[1700951598] = ""
  l_1_2[1702062638] = ""
  l_1_2[1635018798] = ""
  l_1_2[1936338432] = ""
  l_1_2[1819042862] = ""
  l_1_2[2019782446] = ""
  l_1_2[1918986798] = ""
  l_1_2[1668511534] = ""
  l_1_2[1752397614] = ""
  local l_1_3 = (mp.bitor)((mp.readu_u32)(l_1_0, l_1_1), 538976288)
  if l_1_2[l_1_3] or l_1_2[(mp.bitand)(l_1_3, 4294967040)] then
    return true
  end
  return false
end

if not (mp.IsHipsRuleEnabled)("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550") then
  return mp.CLEAN
end
if (mp.get_contextdata)(mp.CONTEXT_DATA_SCANREASON) ~= mp.SCANREASON_ONMODIFIEDHANDLECLOSE then
  return mp.CLEAN
end
if (mp.get_contextdata)(mp.CONTEXT_DATA_NEWLYCREATEDHINT) ~= true then
  return mp.CLEAN
end
if mp.HEADERPAGE_SZ < 1024 then
  return mp.CLEAN
end
if (mp.readu_u32)(headerpage, 1) ~= 67324752 then
  return mp.CLEAN
end
if (mp.bitand)((mp.readu_u16)(headerpage, 7), 1) ~= 1 then
  return mp.CLEAN
end
local l_0_2 = function(l_2_0)
  -- function num : 0_1 , upvalues : l_0_0
  if (mp.readu_u32)(footerpage, l_2_0 + 1) == 33639248 and l_2_0 + 48 < mp.FOOTERPAGE_SZ then
    local l_2_1 = 47
    local l_2_2 = (mp.readu_u16)(footerpage, l_2_0 + 29)
    if (mp.bitand)((mp.readu_u16)(footerpage, l_2_0 + 9), 1) == 1 and l_2_2 > 4 and l_2_0 + l_2_1 + l_2_2 < mp.FOOTERPAGE_SZ and l_0_0(footerpage, l_2_0 + l_2_1 + l_2_2 - 4) then
      return true, 0
    end
    local l_2_3 = l_2_0 + l_2_1 + l_2_2 + (mp.readu_u16)(footerpage, l_2_0 + 31) - 1
    return false, l_2_3
  end
end

local l_0_3 = 31
if (mp.readu_u16)(headerpage, 27) > 4 and l_0_3 + (mp.readu_u16)(headerpage, 27) < mp.HEADERPAGE_SZ and l_0_0(headerpage, l_0_3 + (mp.readu_u16)(headerpage, 27) - 4) then
  (mp.set_mpattribute)("Lua:ZipHasEncryptedFileWithExeExtension")
  return mp.CLEAN
end
local l_0_4 = nil
local l_0_5 = (mp.getfilesize)()
do
  if (mp.readu_u32)(footerpage, mp.FOOTERPAGE_SZ - 21) ~= 101010256 then
    local l_0_6 = nil
    if (tostring(footerpage)):find("PK\005\006", 1, true) == nil then
      return mp.CLEAN
    end
  end
  -- DECOMPILER ERROR at PC121: Confused about usage of register: R5 in 'UnsetPending'

  local l_0_7 = nil
  local l_0_8 = (mp.readu_u32)(footerpage, l_0_6 + 16)
  -- DECOMPILER ERROR at PC128: Overwrote pending register: R7 in 'AssignReg'

  -- DECOMPILER ERROR at PC133: Overwrote pending register: R7 in 'AssignReg'

  if l_0_5 < mp.FOOTERPAGE_SZ then
    local l_0_9 = 0
    do
      local l_0_10 = 0
      while 1 do
        -- DECOMPILER ERROR at PC147: Overwrote pending register: R9 in 'AssignReg'

        if l_0_10 < 3 and l_0_9 + 4 < mp.FOOTERPAGE_SZ then
          if nil then
            (mp.set_mpattribute)("Lua:ZipHasEncryptedFileWithExeExtension")
            return mp.CLEAN
          end
          l_0_10 = l_0_10 + 1
          -- DECOMPILER ERROR at PC158: LeaveBlock: unexpected jumping out IF_THEN_STMT

          -- DECOMPILER ERROR at PC158: LeaveBlock: unexpected jumping out IF_STMT

        end
      end
      do return mp.CLEAN end
      -- DECOMPILER ERROR at PC162: freeLocal<0 in 'ReleaseLocals'

    end
  end
end
```

There are still a few decompilation errors, but the code is now understandable.

The first function `l_0_0` returns if the parameter is one of the following extensions (`1952539182` is `.bat` in ASCII under the proper endianness):
```
.bat, .cmd, .com, .cpl, .exe, .pif, .scr, .vbs, .lnk, .wsf, .vbe, .jse, .hta, .js, .dll, .ocx, .jar, .wsc, .wsh
```

The main code first checks if the rules are enabled in the `HipsManager`.

Then, it checks the reason it has been called (`mp.SCANREASON_ONMODIFIEDHANDLECLOSE`, `mp.SCANREASON_ONOPEN`, etc.), if it is fresh data, the header page size, a magic (`PK\x03\x04`), and so on.

Note that at one point it sets an attribute:
```lua
(mp.set_mpattribute)("Lua:ZipHasEncryptedFileWithExeExtension")
```

From the understanding of the author, this attribute can then be reused by other scripts, in their own checks.

## ASR specific rules

### Rule registration

By looking through the different scripts that can be extracted, we find a lot of different things:

* "Infrastructure" scripts, used to check some configurations, restore host files, etc.:
```lua
Infrastructure_FixHostsFile = function()
  -- function num : 0_100
  if Info.OSMajorVersion == nil or Info.OSMinorVersion == nil then
    return false
  end
  local l_101_0 = Infrastructure_GetEnvironmentPath("%windir%")
  local l_101_1 = l_101_0 .. "\\System32\\drivers\\etc\\hosts"
  local l_101_2 = "# Copyright (c) 1993-2006 Microsoft Corp." .. "\r\n" .. "#" .. "\r\n" .. "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows." .. "\r\n" .. "#" .. "\r\n" .. "# This file contains the mappings of IP addresses to host names. Each" .. "\r\n" .. "# entry should be kept on an individual line. The IP address should" .. "\r\n" .. "# be placed in the first column followed by the corresponding host name." .. "\r\n" .. "# The IP address and the host name should be separated by at least one" .. "\r\n" .. "# space." .. "\r\n" .. "#" .. "\r\n" .. "# Additionally, comments (such as these) may be inserted on individual" .. "\r\n" .. "# lines or following the machine name denoted by a \'#\' symbol." .. "\r\n" .. "#" .. "\r\n" .. "# For example:" .. "\r\n" .. "#" .. "\r\n" .. "#      102.54.94.97     rhino.acme.com          # source server" .. "\r\n" .. "#       38.25.63.10     x.acme.com              # x client host" .. "\r\n" .. "# localhost name resolution is handle within DNS itself." .. "\r\n" .. "#       127.0.0.1       localhost" .. "\r\n" .. "#       ::1             localhost" .. "\r\n"
  local l_101_3 = "# Copyright (c) 1993-2006 Microsoft Corp." .. "\r\n" .. "#" .. "\r\n" .. "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows." .. "\r\n" .. "#" .. "\r\n" .. "# This file contains the mappings of IP addresses to host names. Each" .. "\r\n" .. "# entry should be kept on an individual line. The IP address should" .. "\r\n" .. "# be placed in the first column followed by the corresponding host name." .. "\r\n" .. "# The IP address and the host name should be separated by at least one" .. "\r\n" .. "# space." .. "\r\n" .. "#" .. "\r\n" .. "# Additionally, comments (such as these) may be inserted on individual" .. "\r\n" .. "# lines or following the machine name denoted by a \'#\' symbol." .. "\r\n" .. "#" .. "\r\n" .. "# For example:" .. "\r\n" .. "#" .. "\r\n" .. "#      102.54.94.97     rhino.acme.com          # source server" .. "\r\n" .. "#       38.25.63.10     x.acme.com              # x client host" .. "\r\n" .. "" .. "\r\n" .. "# localhost name resolution is handle within DNS itself." .. "\r\n" .. "#       127.0.0.1       localhost" .. "\r\n" .. "#       ::1             localhost" .. "\r\n"
...
```

* Malware scanning / heuristic scripts, used to check against known signatures or behaviors:

```lua
if ((((((((((((mp.get_mpattribute)("SCRIPT:PowerShell/Mikatz!cert") and not (mp.get_mpattribute)("SCRIPT:PowerShell/Mikatz!mz")) or (mp.get_mpattribute)("SCRIPT:PowerShell/Mikatz!dllcheck")) and not (mp.get_mpattribute)("SCRIPT:PowerShell/Mikatz!MachineType")) or (mp.get_mpattribute)("SCRIPT:PowerShell/Mikatz!MagicType")) and not (mp.get_mpattribute)("SCRIPT:PowerShell/Mikatz!VirtualAlloc")) or (mp.get_mpattribute)("SCRIPT:PowerShell/Mikatz!memcpy")) and not (mp.get_mpattribute)("SCRIPT:PowerShell/Mikatz!CreateThread")) or (mp.get_mpattribute)("SCRIPT:PowerShell/Mikatz!IsWow64Process")) and not (mp.get_mpattribute)("SCRIPT:PowerShell/Mikatz!WriteShellCode")) or (mp.get_mpattribute)("SCRIPT:PowerShell/Mikatz!GetProcAddressSCx64")) and not (mp.get_mpattribute)("SCRIPT:PowerShell/Mikatz!GetProcAddressSCx86")) or (mp.get_mpattribute)("SCRIPT:PowerShell/Mikatz!Invoke") then
```

* Helpers:

```lua
GetCtxOfficeProc = function()
  -- function num : 0_0
  local l_1_0 = {}
  l_1_0["excel.exe"] = "productivity"
  l_1_0["onenote.exe"] = "productivity"
  l_1_0["outlook.exe"] = "communication"
  l_1_0["powerpnt.exe"] = "productivity"
  l_1_0["winword.exe"] = "productivity"
  l_1_0["lync.exe"] = "communication2"
  l_1_0["msaccess.exe"] = "productivity2"
  l_1_0["mspub.exe"] = "productivity2"
  l_1_0["visio.exe"] = "productivity2"
  local l_1_1 = (mp.get_contextdata)(mp.CONTEXT_DATA_PROCESSNAME)
  l_1_1 = (l_1_1 == nil and "" or l_1_1):lower()
  if l_1_0[l_1_1] == nil then
    return ""
  end
  local l_1_2 = (mp.PathToWin32Path)((mp.get_contextdata)(mp.CONTEXT_DATA_PROCESSDEVICEPATH))
  l_1_2 = (l_1_2 == nil and "" or l_1_2):lower()
  local l_1_3 = (mp.ContextualExpandEnvironmentVariables)("%programfiles%")
  l_1_3 = (l_1_3 == nil and "" or l_1_3):lower()
  local l_1_4 = (mp.ContextualExpandEnvironmentVariables)("%programfiles(x86)%")
  l_1_4 = (l_1_4 == nil and "" or l_1_4):lower()
  if l_1_2 == l_1_3 .. "\\microsoft office\\root\\office14" or l_1_2 == l_1_3 .. "\\microsoft office\\root\\office15" or l_1_2 == l_1_3 .. "\\microsoft office\\root\\office16" or l_1_2 == l_1_3 .. "\\microsoft office\\office14" or l_1_2 == l_1_3 .. "\\microsoft office\\office15" or l_1_2 == l_1_3 .. "\\microsoft office\\office16" or l_1_2 == l_1_4 .. "\\microsoft office\\root\\office14" or l_1_2 == l_1_4 .. "\\microsoft office\\root\\office15" or l_1_2 == l_1_4 .. "\\microsoft office\\root\\office16" or l_1_2 == l_1_4 .. "\\microsoft office\\office14" or l_1_2 == l_1_4 .. "\\microsoft office\\office15" or l_1_2 == l_1_4 .. "\\microsoft office\\office16" or l_1_2:find(l_1_3 .. "\\windowsapps\\microsoft.office.desktop.", 1, true) ~= nil or l_1_2:find(l_1_4 .. "\\windowsapps\\microsoft.office.desktop.", 1, true) ~= nil then
    return l_1_0[l_1_1]
  end
  return ""
end

```

* ...

Eventually, we find generic scripts for the ASR rules. These scripts define a few functions that provide generic ASR parameters for each rules.

For instance:
```lua
GetRuleInfo = function()
  -- function num : 0_0
  local l_1_0 = {}
  l_1_0.Name = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
  l_1_0.Description = "Windows Defender Exploit Guard detected an attempt to extract credentials from LSASS."
  return l_1_0
end

GetMonitoredLocations = function()
  -- function num : 0_1
  local l_2_0 = {}
  l_2_0["%windir%\\system32\\lsass.exe"] = 2
  return 7, l_2_0
end

GetPathExclusions = function()
  -- function num : 0_2
  local l_3_0 = {}
  l_3_0["%windir%\\system32\\WerFault.exe"] = 2
  l_3_0["%windir%\\system32\\WerFaultSecure.exe"] = 2
  l_3_0["%windir%\\system32\\mrt.exe"] = 2
  l_3_0["%windir%\\system32\\svchost.exe"] = 2
  l_3_0["%windir%\\system32\\wbem\\WmiPrvSE.exe"] = 2
  l_3_0["%programfiles(x86)%\\Microsoft Intune Management Extension\\Microsoft.Management.Services.IntuneWindowsAgent.exe"] = 2
  return l_3_0
end
```

These functions are called from the MpEngine side, in: `HipsManager::LoadRulesFromDatabase` > `CallInitScripts`:
![](img/ida_callinitscripts.png)

We can track the structure instantiated in this function to see it used in `HipsManager::IsASRExcludedTarget` > `HipsManager::IsRuleExcludedTarget`, for instance.

### Rule example 2: Block Adobe Reader from creating child processes

Here is a rule with more monitored locations, and exceptions:

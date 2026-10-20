# Tarsier

![tarsier](/Tarsier/img/tarsier.jpg "tarsier")

Cute isn't he ?

> **Legal Disclaimer**
> All the content posted here is for **educational purpose only** and authorized security research only. Running this programme against systems you do not own or lack written permission to test is illegal.


### What is this PoC about ?

> TL;DR : Tarsier is PoC of recent Defense Evasion technique that can inject into a process an executable without using VirtualAllocEx and WriteProcessMemory APIs.

Process injection is a very known technique for evasion and persistance. The goal is to force a trusted Windows process to run arbitrary code [T1055](https://attack.mitre.org/techniques/T1055/).
The classic way to achieve this technique is to use some Windows API calls like: `OpenProcess`, `WriteProcessMemory` and `CreateRemoteThread`.
Nowadays the counter-mesures for find thoses evils behavior are getting better and better. A classic way to trigger alert is to hook API's call particularly the most suspicious. Then verifying the callstack for find the succession of: `OpenProcess` -> `VirtualAllocEx` -> `WriteProcessMemory` -> `CreateRemoteThread`.

This new technique was discovered by two researcher of Orange Cyberdefense [here](https://sensepost.com/blog/2026/process-parameter-poisoning/) and modifying by [ZeroSalarium](https://www.zerosalarium.com/2026/09/edr-evasion-process-injection-without-WriteProcessMemory.html). The goal is to inject a process without relying on the above API calls named before.

For accomplish that, we will use the STDIN of the programme and the Pipe (or NamedPipe). The prerequisite is to target a program that require a interactive console (netsh.exe or nslookup.exe for example). The global idea is to send our payload to a newly created process with named pipe throught the STDIN without executing it. The payload stay in memory, then we need to find it, change the memory region protection and hijack the RIP for redirect the execution to our payload.

### Usage
```
$ > ./tarsier.exe c:\Windows\System32\nslookup.exe
```

### Sources

#### Main ressources
- [https://sensepost.com/blog/2026/process-parameter-poisoning/](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [https://www.zerosalarium.com/2026/09/edr-evasion-process-injection-without-WriteProcessMemory.html](https://www.zerosalarium.com/2026/09/edr-evasion-process-injection-without-WriteProcessMemory.html)

#### Helpful ressources for Rust Developpement on this project
- [https://fluxsec.red/remote-process-dll-injection](https://fluxsec.red/remote-process-dll-injection)
- [https://fluxsec.red/winapi-rust-intro](https://fluxsec.red/winapi-rust-intro)
- [https://microsoft.github.io/windows-docs-rs/doc/windows](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Memory/fn.VirtualProtectEx.html)

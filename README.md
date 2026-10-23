# Tarsier

<p align="center">
  <img src="/img/tarsier.jpg" alt="tarsier" width="500">
  <br>
  <em>A Tarsier</em>
</p>

Cute isn't he ?

#### Disclaimer

This project is published for **educational and security research purposes
only**. It is intended to be used on systems you own or for which you have
**explicit written authorization** to test.

Unauthorized access to computer systems, interference with their operation,
or tampering with data is a criminal offense in most jurisdictions.

The author does not encourage or condone any illegal or malicious use of
this code and accepts no responsibility for any damage or misuse. The
software is provided "as is", without warranty of any kind, express or
implied. You use this project at your own risk and are solely responsible
for complying with all applicable laws.

### What is this PoC about?

> TL;DR: Tarsier is a PoC of a recent Defense Evasion technique that can inject an executable into a process without using the OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread APIs.

Process injection is a well-known technique for evasion and persistence. The goal is to force a trusted Windows process to run arbitrary code ([T1055](https://attack.mitre.org/techniques/T1055/)).
The classic way to achieve this is to use Windows API calls such as `OpenProcess`, `WriteProcessMemory`, and `CreateRemoteThread`.
Nowadays, countermeasures for detecting this kind of malicious behavior are getting better and better. A common way to trigger an alert is to hook API calls — particularly the most suspicious ones — and then check the call stack for the following sequence:

`OpenProcess` -> `VirtualAllocEx` -> `WriteProcessMemory` -> `CreateRemoteThread`.

This new technique was discovered by two researchers at Orange Cyberdefense [here](https://sensepost.com/blog/2026/process-parameter-poisoning/) and later adapted by [ZeroSalarium](https://www.zerosalarium.com/2026/09/edr-evasion-process-injection-without-WriteProcessMemory.html). The goal is to inject into a process without relying on the API calls mentioned above.

To achieve this, we use the target program's STDIN and a (named) pipe. The prerequisite is to target a program that requires an interactive console (e.g., `netsh.exe` or `nslookup.exe`). The general idea is to send our payload to a newly created process via a named pipe through STDIN, without executing it. The payload stays in memory; we then need to locate it, change the memory region's protection, and hijack RIP to redirect execution to our payload.


### Usage
```
$ > ./tarsier.exe c:\Windows\System32\nslookup.exe
```

<p align="center">
  <img src="/img/tarsier_running.png" alt="tarsier running" width="500">
  <br>
  <em>Tarsier injecting into nslookup.exe</em>
</p>


<p align="center">
  <img src="/img/tarsier_log.png" alt="tarsier log" width="500">
  <br>
  <em>Run tarsier.exe targeting nslookup.exe</em>
</p>

### Remarks

This PoC was tested on Windows 11 25H2 with only Windows Defender enabled. Feedback on how it performs against other EDRs is welcome (IN AN AUTHORIZED ENVIRONMENT, of course).

### Links

#### Main ressources
- [https://sensepost.com/blog/2026/process-parameter-poisoning/](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [https://www.zerosalarium.com/2026/09/edr-evasion-process-injection-without-WriteProcessMemory.html](https://www.zerosalarium.com/2026/09/edr-evasion-process-injection-without-WriteProcessMemory.html)

#### Helpful ressources for Rust Developpement on this project
- [https://fluxsec.red/remote-process-dll-injection](https://fluxsec.red/remote-process-dll-injection)
- [https://fluxsec.red/winapi-rust-intro](https://fluxsec.red/winapi-rust-intro)
- [https://microsoft.github.io/windows-docs-rs/doc/windows](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Memory/fn.VirtualProtectEx.html)
- And of course the Windows documentations

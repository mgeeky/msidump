## msidump test cases

- `sample1-run-autoruns64.msi.bin` - launches MS Sysinternals Autoruns64.exe from `C:\Windows\Installer\MSXXXX.msi`
- `sample2-run-calc-script.msi.bin` - executes VBScript that runs `calc` over `Wscript.Shell.Exec` method
- `sample3-run-calc-shellcode-via-dotnet.msi.bin` - bundles specially crafted CustomAction .NET DLL, that when executed, runs shellcode which spawns `calc`
- `sample4-customaction-run-calc.msi.bin` - simple MSI that runs system commands after installation is complete, here runs `calc`
- `putty-backdoored.msi.bin` - runs `calc` during PuTTY installation

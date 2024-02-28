# Boromir

Inspired in persistence sniper, Boromir fue construido a partir de la necesidad de la creacion de un timeline de todas las persistencias existentes en un sistema, de tal manera que un analista este en capacidad tanto de un analisis completo como de concentrarse en la zona roja del incidente.

![image](https://github.com/skyg4mb/boromir/assets/16138308/838c4346-2ac0-46da-8536-89280c143695)


# Execution

python 3 boromir.py [-h] [--version] [--source-evidence SOURCE_EVIDENCE] [--csv-output CSV_OUTPUT] [--timezone TIMEZONE] [--users-directory USERS_DIRECTORY] {all,Get-Run,Get-RunOnce,Get-RunEx}

* --users-directory Solo es necesario en dado caso que el directorio de usuarios este en una ubicacion diferente

#Detect this types of persistences

- Run
- RunOnce
- RunEx
- RunOnceEx
- ImageFileExecutionOptions
- NLDPDllOverridePath
- WerFaultHangs
- CmdAutorun
- ExplorerLoad
- WinlogonUserinit
- WinlogonShell
- TerminalProfileStartOnUserLogin
- TerminalProfileStartOnUserLogin
- AppCertDlls
- AppPaths
- ServiceDlls
- GPExtensionDlls
- WinlogonMPNotify
- CHMHelperDll
- StartupPrograms
- ScheduledTasks
- WindowsServices
- UserInitMprScript
- HHCtrlHijacking

#Credits 

- @skyg4mb
- @jupyterjones
  

# Boromir

Inspired in persistence sniper, Boromir was built from the need to create a timeline of all existing persistencies in a system, so that an analyst is able both to perform a complete analysis and to focus on the red zone of the incident.

![image](https://github.com/skyg4mb/Persistence_Boromir/assets/16138308/68ffaefe-0270-4e1c-af00-f08c1c5fdb53)


# Execution

python3 boromir.py [-h] [--version] [--source-evidence SOURCE_EVIDENCE] [--csv-output CSV_OUTPUT] [--timezone TIMEZONE] [--users-directory USERS_DIRECTORY] {all,Get-Run,Get-RunOnce,Get-RunEx}

* --users-directory It is only necessary if the user directory is in a different location.
* --source-evidence Path where the windows disk is mounted

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
  

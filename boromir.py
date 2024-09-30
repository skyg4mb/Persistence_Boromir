import os
from enum import Enum
from Registry import Registry
import sys
import argparse
import csv
from csv import writer
import pathlib
import platform
import datetime
import csv

class Persistence(object):
    Timestamp = ""
    Hostname = ""
    Technique = ""
    Classification = ""
    Path = ""
    Value = ""
    AccessGained = ""
    Note = ""
    Reference = ""
    Signature = ""

__author__    = "Alejandro Gamboa" 
__copyright__ = "GNU"
__version__   = "0.1"

format_date = ("%Y-%m-%d %H:%M:%S.%f")[:-3]
hives = []
persistences = []


def parse_arguments():
    parser = argparse.ArgumentParser(description="Extract artifacts related with persitence")
    parser.add_argument('--version', action='version', version='%(prog)s 0.1')
    parser.add_argument("--source-evidence", help="Directory of windows machine was mount")
    parser.add_argument("--csv-output", help="Resulting CSV")
    parser.add_argument("--timezone", help="All date will be converted to the specific timezone")
    parser.add_argument("action", help="choose the action to perform",choices=['all', 'Get-Run', 'Get-RunOnce', 'Get-RunEx', 'Get-RunOnceEx', 'Get-ImageFileExecutionOptions', 'Get-NLDPDllOverridePath', 'Get-Aedebug', 'Get-WerFaultHangs', 'Get-CmdAutorun', 'Get-ExplorerLoad', 'Get-WinlogonUserinit', 'Get-WinlogonShell', 'Get-TerminalProfileStartOnUserLogin', 'Get-AppCertDlls', 'Get-AppPaths', 'Get-ServiceDlls', 'Get-GPExtensionDlls', 'Get-WinlogonMPNotify', 'Get-CHMHelperDll', 'Get-StartupPrograms', 'Get-ScheduledTasks', 'Get-WindowsServices', 'Get-UserInitMprScript', 'Get-HHCtrlHijacking'])

    args = parser.parse_args()

    if args.action=="all" and (args.source_evidence is None):
        parser.error("parse option requires and evidence")


    args = parser.parse_args()
    return args

def creation_date(path_to_file):
    if platform.system() == 'Windows':
        return os.path.getctime(path_to_file)
    else:
        stat = os.stat(path_to_file)
        try:
            return stat.st_birthtime
        except AttributeError:
            return stat.st_mtime

def modification_date(path_to_file):
    if platform.system() == 'Windows':
        return os.path.getmtime(path_to_file)
    else:
        stat = os.stat(path_to_file)
        try:
            return stat.st_mtime
        except AttributeError:
            return stat.st_mtime

def access_date(path_to_file):
    if platform.system() == 'Windows':
        return os.path.getatime(path_to_file)
    else:
        stat = os.stat(path_to_file)
        try:
            return stat.st_atime
        except AttributeError:
            return stat.st_atime

def change_date(path_to_file):
    if platform.system() == 'Windows':
        return os.path.getatime(path_to_file)
    else:
        stat = os.stat(path_to_file)
        try:
            return stat.st_ctime
        except AttributeError:
            return stat.st_ctime
        
def Get_Run():
    print("+ Getting Run Persistence")
    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            key = reg.open("SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
            timestamp = key.timestamp().strftime(format_date)
            
            for value in [v for v in key.values() \
                   if v.value_type() == Registry.RegSZ or \
                      v.value_type() == Registry.RegExpandSZ]:
                    persistence = Persistence()
                    persistence.Timestamp = timestamp
                    persistence.Path = hive
                    persistence.AccessGained = "User"
                    persistence.Technique = 'Registry Run Key'
                    persistence.Classification = 'MITRE ATT&CK T1547.001'
                    persistence.Reference = "https://attack.mitre.org/techniques/T1547/001/"
                    persistence.Value = value.value()
                    
            print("\t" + persistence.Value)
            persistences.append(persistence)
                
        except:
            None
        
        try:
            reg = Registry.Registry(hive)
            key = reg.open("Microsoft\Windows\CurrentVersion\Run")
            timestamp = key.timestamp().strftime(format_date)
            
            for value in [v for v in key.values() \
                   if v.value_type() == Registry.RegSZ or \
                      v.value_type() == Registry.RegExpandSZ]:
                    persistence = Persistence()
                    persistence.Timestamp = timestamp
                    persistence.Path = hive
                    persistence.AccessGained = "System"
                    persistence.Technique = 'Registry Run Key'
                    persistence.Classification = 'MITRE ATT&CK T1547.001'
                    persistence.Reference = "https://attack.mitre.org/techniques/T1547/001/"
                    persistence.Value = value.value()
            
            persistences.append(persistence)
                    
            print("\t" + persistence.Value)
                
        except:
            None

def Get_RunOnce():
    print("+ Getting RunOnce Persistence")
    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            key = reg.open("SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
            timestamp = key.timestamp().strftime(format_date)
            
            for value in [v for v in key.values() \
                   if v.value_type() == Registry.RegSZ or \
                      v.value_type() == Registry.RegExpandSZ]:
                    persistence = Persistence()
                    persistence.Timestamp = timestamp
                    persistence.Path = hive
                    persistence.AccessGained = "User"
                    persistence.Technique = 'Registry RunOnce Key'
                    persistence.Classification = 'MITRE ATT&CK T1547.001'
                    persistence.Reference = "https://attack.mitre.org/techniques/T1547/001/"
                    persistence.Value = value.value()
                    
            print("\t" + persistence.Value)
            persistences.append(persistence)
                
        except:
            None
        
        try:
            reg = Registry.Registry(hive)
            key = reg.open("Microsoft\Windows\CurrentVersion\RunOnce")
            timestamp = key.timestamp().strftime(format_date)
            
            for value in [v for v in key.values() \
                   if v.value_type() == Registry.RegSZ or \
                      v.value_type() == Registry.RegExpandSZ]:
                    persistence = Persistence()
                    persistence.Timestamp = timestamp
                    persistence.Path = hive
                    persistence.AccessGained = "System"
                    persistence.Technique = 'Registry RunOnce Key'
                    persistence.Classification = 'MITRE ATT&CK T1547.001'
                    persistence.Reference = "https://attack.mitre.org/techniques/T1547/001/"
                    persistence.Value = value.value()
                    
            print("\t" + persistence.Value)
            persistences.append(persistence)
                
        except:
            None

def Get_RunEx():
    print("+ Getting RunEx Persistence")
    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            key = reg.open("SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx")
            timestamp = key.timestamp().strftime(format_date)
            
            for value in [v for v in key.values() \
                   if v.value_type() == Registry.RegSZ or \
                      v.value_type() == Registry.RegExpandSZ]:
                    persistence = Persistence()
                    persistence.Timestamp = timestamp
                    persistence.Path = hive
                    persistence.AccessGained = "User"
                    persistence.Technique = 'Registry RunEx Key'
                    persistence.Classification = 'MITRE ATT&CK T1547.001'
                    persistence.Reference = "https://attack.mitre.org/techniques/T1547/001/"
                    persistence.Value = value.value()
                    
            print("\t" + persistence.Value)
            persistences.append(persistence)
                
        except:
            None
        
        try:
            reg = Registry.Registry(hive)
            key = reg.open("Microsoft\Windows\CurrentVersion\RunEx")
            timestamp = key.timestamp().strftime(format_date)
            
            for value in [v for v in key.values() \
                   if v.value_type() == Registry.RegSZ or \
                      v.value_type() == Registry.RegExpandSZ]:
                    persistence = Persistence()
                    persistence.Timestamp = timestamp
                    persistence.Path = hive
                    persistence.AccessGained = "System"
                    persistence.Technique = 'Registry RunEx Key'
                    persistence.Classification = 'MITRE ATT&CK T1547.001'
                    persistence.Reference = "https://attack.mitre.org/techniques/T1547/001/"
                    persistence.Value = value.value()
                    
            print("\t" + persistence.Value)
            persistences.append(persistence)
                
        except:
            None

def Get_RunOnceEx():
    print("+ Getting RunOnceEx Persistence")
    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            key = reg.open("SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx")
            timestamp = key.timestamp().strftime(format_date)
            
            for value in [v for v in key.values() \
                   if v.value_type() == Registry.RegSZ or \
                      v.value_type() == Registry.RegExpandSZ]:
                    persistence = Persistence()
                    persistence.Timestamp = timestamp
                    persistence.Path = hive
                    persistence.AccessGained = "User"
                    persistence.Technique = 'Registry RunOnceEx Key'
                    persistence.Classification = 'MITRE ATT&CK T1547.001'
                    persistence.Reference = "https://attack.mitre.org/techniques/T1547/001/"
                    persistence.Value = value.value()
                    
            print("\t" + persistence.Value)
            persistences.append(persistence)
                
        except:
            None
        
        try:
            reg = Registry.Registry(hive)
            key = reg.open("Microsoft\Windows\CurrentVersion\RunOnceEx")
            timestamp = key.timestamp().strftime(format_date)
            
            for value in [v for v in key.values() \
                   if v.value_type() == Registry.RegSZ or \
                      v.value_type() == Registry.RegExpandSZ]:
                    persistence = Persistence()
                    persistence.Timestamp = timestamp
                    persistence.Path = hive
                    persistence.AccessGained = "System"
                    persistence.Technique = 'Registry RunOnceEx Key'
                    persistence.Classification = 'MITRE ATT&CK T1547.001'
                    persistence.Reference = "https://attack.mitre.org/techniques/T1547/001/"
                    persistence.Value = value.value()
                    
            print("\t" + persistence.Value)
            persistences.append(persistence)
                
        except:
            None

def Get_ImageFileExecutionOptions():
    print("+ Getting Image File Execution Options")

    for hive in hives:
        try:    
            reg = Registry.Registry(hive)
            imageFileExecutions = reg.open("Microsoft\Windows NT\CurrentVersion\Image File Execution Options")
            for image in imageFileExecutions.subkeys():
                
                for value in [v for v in image.values() \
                    if v.value_type() == Registry.RegSZ or \
                      v.value_type() == Registry.RegExpandSZ]:
                    
                    if (value.name() == "Debugger"): 
                        persistence = Persistence()
                        persistence.Timestamp = image.timestamp().strftime(format_date)
                        persistence.Path = value.value()
                        persistence.AccessGained = "System/User"
                        persistence.Technique = "Image file execution options"
                        persistence.Classification = 'MITRE ATT&CK T1546.012'
                        persistence.Reference = "https://attack.mitre.org/techniques/T1546/012/"
                        persistence.Value = value.value()
                        print("\t" + persistence.Value)
                        persistences.append(persistence)
                        
        except:
             None

def Get_NLDPDllOverridePath():
    print("+ Getting Natural Language Development Platform DLL path override properties.")

    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            select = reg.open("Select")
            current = select.value("Current").value()
            languages = reg.open("ControlSet00%d\\Control\\ContentIndex\\Language" % (current))
           

            for languages in languages.subkeys():
                try :
                    timestamp = languages.timestamp().strftime(format_date) 
                except:
                    display_name = "???"
                
                try:
                    NoiseFile = languages.value("NoiseFile").value()
                except:
                    NoiseFile = "???"
                    
                try:
                    StemmerDLLPathOverride = languages.value("StemmerDLLPathOverride").value()
                except:
                    StemmerDLLPathOverride = "No"

                try:
                    WBDLLPathOverride = languages.value("WBDLLPathOverride").value()
                except:
                    WBDLLPathOverride = "No"

                
                if StemmerDLLPathOverride != "No" or WBDLLPathOverride != "No":
                    persistence = Persistence()
                    persistence.Timestamp = languages.timestamp().strftime(format_date)
                    persistence.Path = StemmerDLLPathOverride
                    persistence.AccessGained = ""
                    persistence.Technique = 'Natural Language Development Platform 6 DLL Override Path'
                    persistence.Classification = "'Hexacorn Technique N.98'"
                    persistence.Reference = 'https://www.hexacorn.com/blog/2018/12/30/beyond-good-ol-run-key-part-98/'
                    persistence.Value = WBDLLPathOverride
                    print("\t" + persistence.Value)
                    persistences.append(persistence)
        except:
            None

def Get_Aedebug():
    print("+ Getting AeDebug properties.")


    for hive in hives:
        try:    
            reg = Registry.Registry(hive)
            aedebug = reg.open("Microsoft\Windows NT\CurrentVersion\AeDebug")

            for subaedebug in aedebug.subkeys():
                for value in subaedebug.values():                 
                    persistence = Persistence()
                    persistence.Timestamp = subaedebug.timestamp().strftime(format_date)
                    persistence.Path = "Name: " + str(value.name()) + " Value: " + str(value.value())
                    persistence.AccessGained = "System"
                    persistence.Technique = "AEDebug Custom Debugger"
                    persistence.Classification = "Hexacorn Technique N.4"
                    persistence.Reference = "https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4"
                    persistence.Value = "AeDebug"
                    print("\t" + persistence.Path)
                    persistences.append(persistence)
        except Exception as e:
            None
        
    for hive in hives:
        try:    
            reg = Registry.Registry(hive)
            aedebug = reg.open("Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug")

            for subaedebug in aedebug.subkeys():
                for value in subaedebug.values():                 
                    persistence = Persistence()
                    persistence.Timestamp = subaedebug.timestamp().strftime(format_date)
                    persistence.Path = "Name: " + str(value.name()) + " Value: " + str(value.value())
                    persistence.AccessGained = "System"
                    persistence.Technique = "AEDebug Custom Debugger"
                    persistence.Classification = "Hexacorn Technique N.4"
                    persistence.Reference = "https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4"
                    persistence.Value = "AeDebug"
                    print("\t" + persistence.Path)
                    persistences.append(persistence)
        except Exception as e:
            None

def Get_WerFaultHangs():
    print("+ Getting WerFault Hangs registry key Debug property.")
    
    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            werfaultDebuggger = reg.open("Microsoft\Windows\Windows Error Reporting\Hangs")

            for SubwerfaultDebuggger in werfaultDebuggger.subkeys():
                for value in SubwerfaultDebuggger.values():          
                    persistence = Persistence()
                    persistence.Timestamp = SubwerfaultDebuggger.timestamp().strftime(format_date)
                    persistence.Path = "Name: " + str(value.name()) + " Value: " + str(value.value())
                    persistence.AccessGained = "System"
                    persistence.Technique = "Windows Error Reporting Debugger"
                    persistence.Classification = "Hexacorn Technique N.116"
                    persistence.Reference = "https://www.hexacorn.com/blog/2019/09/20/beyond-good-ol-run-key-part-116/"
                    persistence.Value = "werfaultDebuggger"   
                    print("\t" + persistence.Path)     
                    persistences.append(persistence)
        except:
            None

    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            werfaultDebuggger = reg.open("SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs")
            
            for SubwerfaultDebuggger in werfaultDebuggger.subkeys():
                for value in SubwerfaultDebuggger.values():          
                    persistence = Persistence()
                    persistence.Timestamp = SubwerfaultDebuggger.timestamp().strftime(format_date)
                    persistence.Path = "Name: " + str(value.name()) + " Value: " + str(value.value())
                    persistence.AccessGained = "System"
                    persistence.Technique = "Windows Error Reporting Debugger"
                    persistence.Classification = "Hexacorn Technique N.116"
                    persistence.Reference = "https://www.hexacorn.com/blog/2019/09/20/beyond-good-ol-run-key-part-116/"
                    persistence.Value = "werfaultDebuggger"   
                    print("\t" + persistence.Path)     
                    persistences.append(persistence)
        except:
            None

def Get_CmdAutorun():
    print("+ Getting Command Processor's AutoRun property.")

    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            cmdAutoRun = reg.open("Software\Microsoft\Command Processor")      
            for value in cmdAutoRun.values():
                if (str(value.name()) == "Autorun"):
                    persistence = Persistence()
                    persistence.Timestamp = cmdAutoRun.timestamp().strftime(format_date)
                    persistence.Path = "Name: " + str(value.value())
                    persistence.AccessGained = "User"
                    persistence.Technique = "Command Processor AutoRun key"
                    persistence.Classification = "Uncatalogued Technique N.1"
                    persistence.Reference = "https://persistence-info.github.io/Data/cmdautorun.html"
                    persistence.Value = "CmdAutoRun"
                    print("\t" + persistence.Path)
                    persistences.append(persistence)
        except Exception as e:
            None


        try:
            reg = Registry.Registry(hive)
            cmdAutoRun = reg.open("Microsoft\Command Processor")      
            
            for value in cmdAutoRun.values():
                if (str(value.name()) == "Autorun"):  
                    persistence = Persistence()
                    persistence.Timestamp = cmdAutoRun.timestamp().strftime(format_date)
                    persistence.Path = "Name: " + str(value.value())
                    persistence.AccessGained = "User"
                    persistence.Technique = "Command Processor AutoRun key"
                    persistence.Classification = "Uncatalogued Technique N.1"
                    persistence.Reference = "https://persistence-info.github.io/Data/cmdautorun.html"
                    persistence.Value = "CmdAutoRun"
                    print("\t" + persistence.Path)
                    persistences.append(persistence)
        except Exception as e:
            None

def Get_ExplorerLoad():
    print("+ Getting Explorer's Load property.")
    
    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            explorerLoad = reg.open("Software\Microsoft\Windows NT\CurrentVersion\Windows")

            for value in explorerLoad.values():      
                if value.name() == "Load":          
                    persistence = Persistence()
                    persistence.Timestamp = explorerLoad.timestamp().strftime(format_date)
                    persistence.Path = "Name: " + str(value.name()) + " Value: " + str(value.value())
                    persistence.AccessGained = "System"
                    persistence.Technique = "Explorer Load Property"
                    persistence.Classification = "Uncatalogued Technique N.2"
                    persistence.Reference = "https://persistence-info.github.io/Data/windowsload.html"
                    persistence.Value = "ExplorerLoad"   
                    print("\t" + persistence.Path)    
                    persistences.append(persistence) 
        except:
            None

    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            explorerLoad = reg.open("Microsoft\Windows NT\CurrentVersion\Windows")
            
            for value in explorerLoad.values():    
                if value.name() == "Load":      
                    persistence = Persistence()
                    persistence.Timestamp = explorerLoad.timestamp().strftime(format_date)
                    persistence.Path = "Name: " + str(value.name()) + " Value: " + str(value.value())
                    persistence.AccessGained = "System"
                    persistence.Technique = "Explorer Load Property"
                    persistence.Classification = "Uncatalogued Technique N.2"
                    persistence.Reference = "https://persistence-info.github.io/Data/windowsload.html"
                    persistence.Value = "ExplorerLoad"   
                    print("\t" + persistence.Path)     
                    persistences.append(persistence)
        except:
            None

def Get_WinlogonUserinit():
    print("+ Getting Winlogon's Userinit property.")
    
    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            explorerLoad = reg.open("SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")

            for value in explorerLoad.values():      
                if value.name() == "Userinit":
                    persistence = Persistence()
                    persistence.Timestamp = explorerLoad.timestamp().strftime(format_date)
                    persistence.Path = "Name: " + str(value.name()) + " Value: " + str(value.value())
                    persistence.AccessGained = "System"
                    persistence.Technique = "Winlogon Userinit Property"
                    persistence.Classification = "MITRE ATT&CK T1547.004"
                    persistence.Reference = "https://attack.mitre.org/techniques/T1547/004/"
                    persistence.Value = "WinLogonUserInit"   
                    print("\t" + persistence.Path)    
                    persistences.append(persistence) 
        except:
            None

    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            explorerLoad = reg.open("Microsoft\Windows NT\CurrentVersion\Winlogon")
            
            for value in explorerLoad.values():   
                if value.name() == "Userinit": 
                    persistence = Persistence()
                    persistence.Timestamp = explorerLoad.timestamp().strftime(format_date)
                    persistence.Path = str(value.name()) + " " + str(value.value())
                    persistence.AccessGained = "System"
                    persistence.Technique = "Winlogon Userinit Property"
                    persistence.Classification = "MITRE ATT&CK T1547.004"
                    persistence.Reference = "https://attack.mitre.org/techniques/T1547/004/"
                    persistence.Value = "WinLogonUserInit"   
                    print("\t" + persistence.Path)     
                    persistences.append(persistence)
        except:
            None

def Get_WinlogonShell():
    print("+ Getting Winlogon's Shell property.")
    
    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            explorerLoad = reg.open("SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")

            for value in explorerLoad.values():      
                if value.name() == "Shell":
                    persistence = Persistence()
                    persistence.Timestamp = explorerLoad.timestamp().strftime(format_date)
                    persistence.Path = str(value.name()) + " " + str(value.value())
                    persistence.AccessGained = "System"
                    persistence.Technique = "Winlogon shell Property"
                    persistence.Classification = "MITRE ATT&CK T1547.004"
                    persistence.Reference = "https://attack.mitre.org/techniques/T1547/004/"
                    persistence.Value = "WinLogonShell"   
                    print("\t" + persistence.Path)    
                    persistences.append(persistence) 
        except:
            None

    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            explorerLoad = reg.open("Microsoft\Windows NT\CurrentVersion\Winlogon")
            
            for value in explorerLoad.values():   
                if value.name() == "Shell": 
                    persistence = Persistence()
                    persistence.Timestamp = explorerLoad.timestamp().strftime(format_date)
                    persistence.Path = str(value.name()) + " " + str(value.value())
                    persistence.AccessGained = "System"
                    persistence.Technique = "Winlogon shell Property"
                    persistence.Classification = "MITRE ATT&CK T1547.004"
                    persistence.Reference = "https://attack.mitre.org/techniques/T1547/004/"
                    persistence.Value = "WinLogonShell"   
                    print("\t" + persistence.Path)     
                    persistences.append(persistence)
        except:
            None
    
def Get_TerminalProfileStartOnUserLogin(files):
    print ("+ Checking if users' Windows Terminal Profile's settings.json contains a startOnUserLogin value.")


    try:
        for file in files:
            with open(file) as setFile:
                for item in setFile:
                    if "commandline" in item:
                        persistence = Persistence()
                        persistence.Timestamp = datetime.datetime.fromtimestamp(modification_date(file))
                        persistence.Path = item.replace('\n', '').strip()
                        persistence.AccessGained = "System"
                        persistence.Technique = "Windows Terminal startOnUserLogin"
                        persistence.Classification = "Uncatalogued Technique N.3"
                        persistence.Reference = "https://twitter.com/nas_bench/status/1550836225652686848"
                        persistence.Value = "startOnUserLogin"   
                        print("\t" + persistence.Path)     
                        persistences.append(persistence)
    except:
        print("Windows terminal startOnUserLogin not detected")

def Get_AppCertDlls():
    print("+ Getting AppCertDlls properties.")

    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            AppCertDlls = reg.open("SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls")
            for value in AppCertDlls.values():      
                    persistence = Persistence()
                    persistence.Timestamp = AppCertDlls.timestamp().strftime(format_date)
                    persistence.Path = str(value.name()) + " " + str(value.value())
                    persistence.AccessGained = "User"
                    persistence.Technique = "AppCertDlls properties."
                    persistence.Classification = "MITRE ATT&CK T1546.009"
                    persistence.Reference = "https://attack.mitre.org/techniques/T1546/009/"
                    persistence.Value = "AppCertDlls"   
                    print("\t" + persistence.Path)    
                    persistences.append(persistence) 
        except:
            None

    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            AppCertDlls = reg.open("CurrentControlSet\Control\Session Manager\AppCertDlls")
            for value in AppCertDlls.values():   
                    persistence = Persistence()
                    persistence.Timestamp = AppCertDlls.timestamp().strftime(format_date)
                    persistence.Path = str(value.name()) + " " + str(value.value())
                    persistence.AccessGained = "System"
                    persistence.Technique = "AppCertDlls properties."
                    persistence.Classification = "MITRE ATT&CK T1546.009"
                    persistence.Reference = "https://attack.mitre.org/techniques/T1546/009/"
                    persistence.Value = "AppCertDlls"   
                    print("\t" + persistence.Path)     
                    persistences.append(persistence)
        except:
            None

def Get_AppPaths():
    print("+ Getting App Paths inside the registry.")

    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            AppPaths = reg.open("SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths")
            for value in AppPaths.values():      
                    persistence = Persistence()
                    persistence.Timestamp = AppPaths.timestamp().strftime(format_date)
                    persistence.Path = str(value.name()) + " " + str(value.value())
                    persistence.AccessGained = "User"
                    persistence.Technique = "App Paths"
                    persistence.Classification = "Hexacorn Technique N.3"
                    persistence.Reference = "https://www.hexacorn.com/blog/2013/01/19/beyond-good-ol-run-key-part-3/"
                    persistence.Value = "App Paths"   
                    print("\t" + persistence.Path)    
                    persistences.append(persistence) 
        except:
            None

    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            AppPaths = reg.open("Microsoft\Windows\CurrentVersion\App Paths")
            for value in AppPaths.values():   
                    persistence = Persistence()
                    persistence.Timestamp = AppPaths.timestamp().strftime(format_date)
                    persistence.Path = str(value.name()) + " " + str(value.value())
                    persistence.AccessGained = "System"
                    persistence.Technique = "App Paths"
                    persistence.Classification = "Hexacorn Technique N.3"
                    persistence.Reference = "https://www.hexacorn.com/blog/2013/01/19/beyond-good-ol-run-key-part-3/"
                    persistence.Value = "App Paths"   
                    print("\t" + persistence.Path)     
                    persistences.append(persistence)
        except:
            None

def Get_ServiceDlls():
    print("+ Getting Service DLLs inside the registry.")
    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            select = reg.open("Select")
            current = select.value("Current").value()
            services = reg.open("ControlSet00%d\\Services" % (current))
            for service in services.subkeys():
                try:
                    timestamp = service.timestamp().strftime(format_date)
                except:
                    timestamp = "???"

                try:
                    display_name = service.value("DisplayName").value()
                except:
                    display_name = "???"

                try:
                    description = service.value("Description").value()
                except:
                    description = "???"

                try:
                    image_path = service.value("ImagePath").value()
                except:
                    image_path = "???"

                try:
                    SeviceDll = service.value("ServiceDll").value()
                except:
                    SeviceDll = "???"

                try:
                    dll = service.subkey("Parameters").value("ServiceDll").value()
                except:
                    dll = "???"


                if dll != "???":
                    persistence = Persistence()
                    persistence.Timestamp = service.timestamp().strftime(format_date)
                    persistence.Path = dll
                    persistence.AccessGained = "System"
                    persistence.Technique = "ServiceDll Hijacking"
                    persistence.Classification = "Hexacorn Technique N.4"
                    persistence.Reference = "https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/"
                    persistence.Value = "ServiceDlls"   
                    print("\t" + dll)    
                    persistences.append(persistence) 
                
        except:
            None

def Get_GPExtensionDlls():
    print("+ Getting Group Policy Extension DLLs inside the registry.")

    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            key = reg.open("SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions")
            timestamp = key.timestamp().strftime(format_date)
            
            for gpextensions in key.subkeys():
                for value in [v for v in gpextensions.values() \
                   if v.value_type() == Registry.RegSZ or \
                      v.value_type() == Registry.RegExpandSZ]:
                    persistence = Persistence()
                    persistence.Timestamp = timestamp
                    persistence.Path = value.value()
                    persistence.AccessGained = "User"
                    persistence.Technique = 'Group Policy Extension DLL'
                    persistence.Classification = 'Uncatalogued Technique N.4'
                    persistence.Reference = "https://persistence-info.github.io/Data/gpoextension.html"
                    persistence.Value = 'Group Policy Extension DLL'
                    print("\t" + persistence.Value)
                    persistences.append(persistence)
                
        except Exception as e:
            None
        
        try:
            reg = Registry.Registry(hive)
            key = reg.open("Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions")
            timestamp = key.timestamp().strftime(format_date)
            #rec(key)

            for gpextensions in key.subkeys():
                for value in [v for v in gpextensions.values() \
                   if v.value_type() == Registry.RegSZ or \
                      v.value_type() == Registry.RegExpandSZ]:
                    if value.name() == 'DllName':
                        persistence = Persistence()
                        persistence.Timestamp = timestamp
                        persistence.Path = value.value()
                        persistence.AccessGained = "System"
                        persistence.Technique = 'Group Policy Extension DLL'
                        persistence.Classification = 'Uncatalogued Technique N.4'
                        persistence.Reference = "https://persistence-info.github.io/Data/gpoextension.html"
                        persistence.Value = 'Group Policy Extension DLL'
                        print("\t" + persistence.Path)
                        persistences.append(persistence)
        except Exception as e:
            None

def Get_WinlogonMPNotify():
    print("+ Getting Winlogon MPNotify property.")

    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            AppPaths = reg.open("SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")
            for value in AppPaths.values():      
                if value.name() == "mpnotify":
                    persistence = Persistence()
                    persistence.Timestamp = AppPaths.timestamp().strftime(format_date)
                    persistence.Path = str(value.name()) + " " + str(value.value())
                    persistence.AccessGained = "User"
                    persistence.Technique = "MPNotify"
                    persistence.Classification = "Uncatalogued Technique N.5"
                    persistence.Reference = 'https://persistence-info.github.io/Data/mpnotify.html'
                    persistence.Value = "MPNotify"   
                    print("\t" + persistence.Path)    
                    persistences.append(persistence) 
        except:
            None

    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            AppPaths = reg.open("Microsoft\Windows NT\CurrentVersion\Winlogon")
            for value in AppPaths.values(): 
                if value.name() == "mpnotify": 
                    persistence = Persistence()
                    persistence.Timestamp = AppPaths.timestamp().strftime(format_date)
                    persistence.Path = str(value.name()) + " " + str(value.value())
                    persistence.AccessGained = "System"
                    persistence.Technique = "MPNotify"
                    persistence.Classification = "Uncatalogued Technique N.5"
                    persistence.Reference = 'https://persistence-info.github.io/Data/mpnotify.html'
                    persistence.Value = "MPNotify"   
                    print("\t" + persistence.Path)     
                    persistences.append(persistence)
        except:
            None

def Get_CHMHelperDll():
    print("+ Getting CHM Helper DLL inside the registry.")

    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            AppPaths = reg.open("Software\Microsoft\HtmlHelp Author")
            for value in AppPaths.values():      
                    persistence = Persistence()
                    persistence.Timestamp = AppPaths.timestamp().strftime(format_date)
                    persistence.Path = str(value.name()) + " " + str(value.value())
                    persistence.AccessGained = "User"
                    persistence.Technique = "CHMHelperDll"
                    persistence.Classification = "CHM Helper DLL"
                    persistence.Reference = 'https://www.hexacorn.com/blog/2018/04/22/beyond-good-ol-run-key-part-76/'
                    persistence.Value = "CHMHelperDll"   
                    print("\t" + persistence.Path)    
                    persistences.append(persistence) 
        except:
            None

    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            AppPaths = reg.open("Microsoft\HtmlHelp Author")
            for value in AppPaths.values(): 
                    persistence = Persistence()
                    persistence.Timestamp = AppPaths.timestamp().strftime(format_date)
                    persistence.Path = str(value.name()) + " " + str(value.value())
                    persistence.AccessGained = "System"
                    persistence.Technique = "CHMHelperDll"
                    persistence.Classification = "CHM Helper DLL"
                    persistence.Reference = 'https://www.hexacorn.com/blog/2018/04/22/beyond-good-ol-run-key-part-76/'
                    persistence.Value = "CHMHelperDll"   
                    print("\t" + persistence.Path)     
                    persistences.append(persistence)
        except:
            None

def Get_StartupPrograms(files):
    print("+ Checking if users' Startup folder contains interesting artifacts.")

    
    for program in files:
        persistence = Persistence()
        persistence.Timestamp = datetime.datetime.fromtimestamp(creation_date(program))
        persistence.Path = program
        persistence.AccessGained = "User"
        persistence.Technique = "Startup Folder"
        persistence.Classification = "MITRE ATT&CK T1547.001"
        persistence.Reference = 'https://attack.mitre.org/techniques/T1547/001/'
        persistence.Value = "Startup Folder"   
        print("\t" + persistence.Path)    
        persistences.append(persistence) 

def Get_ScheduledTasks():
    
    print("+ Getting scheduled tasks.")
    
    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            tasks = reg.open("Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks")
    
            for task in tasks.subkeys():
                try:
                    timestamp = task.timestamp().strftime(format_date)
                except:
                    timestamp = "???"

                try:
                    path = task.value("Path").value()
                except:
                    path = "???"

                if path != "???":
                    persistence = Persistence()
                    persistence.Timestamp = timestamp
                    persistence.Path = path
                    persistence.AccessGained = "System"
                    persistence.Technique = "Scheduled Task"
                    persistence.Classification = "MITRE ATT&CK T1053.005"
                    persistence.Reference = 'https://attack.mitre.org/techniques/T1053/005/'
                    persistence.Value = "Scheduled Task"   
                    print("\t" + persistence.Path)     
                    persistences.append(persistence)   
        except:
            None

        try:
            reg = Registry.Registry(hive)
            tasks = reg.open("SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks")
            

            for task in tasks.subkeys():
                try:
                    timestamp = task.timestamp().strftime(format_date)
                except:
                    timestamp = "???"

                try:
                    path = task.value("Path").value()
                except:
                    path = "???"

                if path != "???":
                    persistence = Persistence()
                    persistence.Timestamp = timestamp
                    persistence.Path = path
                    persistence.AccessGained = "User"
                    persistence.Technique = "Scheduled Task"
                    persistence.Classification = "MITRE ATT&CK T1053.005"
                    persistence.Reference = 'https://attack.mitre.org/techniques/T1053/005/'
                    persistence.Value = "Scheduled Task"   
                    print("\t" + persistence.Path)     
                    persistences.append(persistence)   
        except:
            None

def Get_WindowsServices():
    print("+ Checking Windows Services.")
    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            select = reg.open("Select")
            current = select.value("Current").value()
            services = reg.open("ControlSet00%d\\Services" % (current))
            for service in services.subkeys():
                try:
                    timestamp = service.timestamp().strftime(format_date)
                except:
                    timestamp = "???"

                try:
                    display_name = service.value("DisplayName").value()
                except:
                    display_name = "???"

                try:
                    description = service.value("Description").value()
                except:
                    description = "???"

                try:
                    image_path = service.value("ImagePath").value()
                except:
                    image_path = "???"

                try:
                    SeviceDll = service.value("ServiceDll").value()
                except:
                    SeviceDll = "???"

                try:
                    dll = service.subkey("Parameters").value("ServiceDll").value()
                except:
                    dll = "???"


                if dll == "???" and image_path != "???":
                    persistence = Persistence()
                    persistence.Timestamp = service.timestamp().strftime(format_date)
                    persistence.Path = image_path
                    persistence.AccessGained = "System"
                    persistence.Technique = "Windows Service"
                    persistence.Classification = "MITRE ATT&CK T1543.003"
                    persistence.Reference = "https://attack.mitre.org/techniques/T1543/003/"
                    persistence.Value = display_name   
                    print("\t" + image_path)    
                    persistences.append(persistence) 
        except:
            None

def Get_UserInitMprScript():
    print("+ Getting users' UserInitMprLogonScript property.")

    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            AppPaths = reg.open("Environment")
            for value in AppPaths.values():      
                if value.name() == "UserInitMprLogonScript":
                    persistence = Persistence()
                    persistence.Timestamp = AppPaths.timestamp().strftime(format_date)
                    persistence.Path = str(value.name()) + " " + str(value.value())
                    persistence.AccessGained = "User"
                    persistence.Technique = "User Init Mpr Logon Script"
                    persistence.Classification = "MITRE ATT&CK T1037.001"
                    persistence.Reference = 'https://attack.mitre.org/techniques/T1037/001/'
                    persistence.Value = value.value()   
                    print("\t" + persistence.Path)    
                    persistences.append(persistence) 
        except:
            None

    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            AppPaths = reg.open("Environment")
            for value in AppPaths.values(): 
                if value.name() == "UserInitMprLogonScript":
                    persistence = Persistence()
                    persistence.Timestamp = AppPaths.timestamp().strftime(format_date)
                    persistence.Path = str(value.name()) + " " + str(value.value())
                    persistence.AccessGained = "User"
                    persistence.Technique = "User Init Mpr Logon Script"
                    persistence.Classification = "MITRE ATT&CK T1037.001"
                    persistence.Reference = 'https://attack.mitre.org/techniques/T1037/001/'
                    persistence.Value = value.value()   
                    print("\t" + persistence.Path)    
                    persistences.append(persistence) 
        except:
            None


def Get_HHCtrlHijacking():
    print("+ Getting the hhctrl.ocx library inside the registry.")

    for hive in hives:
        try:
            reg = Registry.Registry(hive)
            hhcrtlocx = reg.open("Classes\\CLSID\\{52A2AAAE-085D-4187-97EA-8C30DB990436}\\InprocServer32")

            for value in hhcrtlocx.values(): 
                if value.name() == "(default)":
                    persistence = Persistence()
                    persistence.Timestamp = hhcrtlocx.timestamp().strftime(format_date)
                    persistence.Path = str(value.name()) + " " + str(value.value())
                    persistence.AccessGained = "System"
                    persistence.Technique = "Hijacking of hhctrl.ocx"
                    persistence.Classification = "Hexacorn Technique N.77"
                    persistence.Reference = 'https://www.hexacorn.com/blog/2018/04/23/beyond-good-ol-run-key-part-77/'
                    persistence.Value = value.value()   
                    print("\t" + persistence.Path)    
                    persistences.append(persistence) 
            
        except Exception as e:
            None


def rec(key):
    for value in key.values():
        print("%s : %s : %s" % (key.path(), value.name(), value.value_type_str()))
        
    for subkey in key.subkeys():
        rec(subkey)

def get_settings_json_files(args):

    users_list = os.listdir(args.source_evidence + "/Users/")
    settings_json = []

    for user in users_list:
        try:
            packages = os.listdir(args.source_evidence + "/Users/" + user + "/AppData/Local/Packages/")
            for package in packages:
                if "Microsoft.WindowsTerminal" in package:
                    settings_json.append(args.source_evidence + "/Users/" + user + "/AppData/Local/Packages/" + package + "/LocalState/settings.json")
        except:
            None

    return settings_json

def get_startupfiles(args):
    users_list = os.listdir(args.source_evidence + "/Users/")
    startup_files = []
    
    for user in users_list:
        print(user)
        try:
            startup = os.listdir(args.source_evidence + "/Users/" + user + "/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/")
            for program in startup:
                startup_files.append(args.source_evidence + "/Users/" + user + "/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/" + program)
        except:
            None
    
    return startup_files

def get_startupfiles2(args):
    users_list = os.listdir(args.source_evidence + "/Users/")
    startup_files = []

    for user in users_list:
        try:
            startup = os.listdir(args.source_evidence + "/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/")
            for program in startup:
                startup_files.append(args.source_evidence + "/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/" + program)
        except:
            None

    return startup_files



def Get_Hives(args):
    print ("+ Getting hives...")
    configDir = "/Windows/System32/config"
    UsersDir = "/Users"
    dir_list = os.listdir(args.source_evidence + configDir)

    
    for file in dir_list:
        hives.append(args.source_evidence + configDir + "/" + file)

    user_list = os.listdir(args.source_evidence + "/Users")

    for user in user_list:
        user_dir = args.source_evidence + UsersDir + "/" + user
        try:
            userhives = os.listdir(user_dir)
            for hive in userhives:
                if "ntuser" in hive or "NTUSER" in hive:
                    try:
                        hives.append(user_dir + "/" + hive)
                    except:
                        None

        except:
            None
        

    for hive in hives:
        print("\t" + hive)

def output(args):
    #Definicion de output, puede ser escribir en un archivo de texto o solo print.
    if args.csv_output:
        with open(args.csv_output + 'boromir.output.csv', 'a', newline='') as f_object:
            for persistence in persistences:
                writer_object = writer(f_object)
                writer_object.writerow([persistence.Timestamp, persistence.Path, persistence.AccessGained, persistence.Technique, persistence.Classification, persistence.Value])
            f_object.close()


def run_all(args):
    Get_Run()
    Get_RunOnce()
    Get_RunEx()
    Get_RunOnceEx()
    Get_ImageFileExecutionOptions()
    Get_NLDPDllOverridePath()
    Get_Aedebug()   
    Get_WerFaultHangs()
    Get_CmdAutorun()
    Get_ExplorerLoad()
    Get_WinlogonUserinit()
    Get_WinlogonShell()
    files = get_settings_json_files(args)
    Get_TerminalProfileStartOnUserLogin(files)
    Get_AppCertDlls()
    Get_AppPaths()
    Get_ServiceDlls()
    Get_GPExtensionDlls()
    Get_WinlogonMPNotify()
    Get_CHMHelperDll()
    startup = get_startupfiles(args)
    Get_StartupPrograms(startup)
    startup = get_startupfiles2(args)
    Get_StartupPrograms(startup)
    Get_ScheduledTasks()
    Get_WindowsServices()
    Get_UserInitMprScript()
    Get_HHCtrlHijacking()

def main(arguments):
    Get_Hives(arguments)
    if arguments.action == "all":
        run_all(arguments)
    elif arguments.action == "Get-Run":
        Get_Run()
    elif arguments.action == "Get-RunOnce":
        Get_RunOnce()
    elif arguments.action == "Get-RunEx":
        Get_RunEx()
    elif arguments.action == "Get-RunOnceEx":
        Get_RunOnceEx()
    elif arguments.action == "Get-ImageFileExecutionOptions":
        Get_ImageFileExecutionOptions()
    elif arguments.action == "Get-NLDPDllOverridePath":
        Get_NLDPDllOverridePath()
    elif arguments.action == "Get-Aedebug":
        Get_Aedebug()
    elif arguments.action == "Get-WerFaultHangs":
        Get_WerFaultHangs()
    elif arguments.action == "Get-CmdAutorun":
        Get_CmdAutorun()
    elif arguments.action == "Get-ExplorerLoad":
        Get_ExplorerLoad()
    elif arguments.action == "Get-WinlogonUserinit":
        Get_WinlogonUserinit()
    elif arguments.action == "Get-WinlogonShell":
        Get_WinlogonShell()
    elif arguments.action == "Get-TerminalProfileStartOnUserLogin":
        files = get_settings_json_files(arguments)
        Get_TerminalProfileStartOnUserLogin(files)
    elif arguments.action == "Get-AppCertDlls":
        Get_AppCertDlls()
    elif arguments.action == "Get-AppPaths":
        Get_AppPaths()
    elif arguments.action == "Get-ServiceDlls":
        Get_ServiceDlls()
    elif arguments.action == "Get-GPExtensionDlls":
        Get_GPExtensionDlls()
    elif arguments.action == "Get-WinlogonMPNotify":
        Get_WinlogonMPNotify()
    elif arguments.action == "Get-CHMHelperDll":
        Get_CHMHelperDll()
    elif arguments.action == "Get-StartupPrograms":
        startup = get_startupfiles(arguments)
        Get_StartupPrograms(startup)
        startup = get_startupfiles2(arguments)
        Get_StartupPrograms(startup)
    elif arguments.action == "Get-ScheduledTasks":
        Get_ScheduledTasks()
    elif arguments.action == "Get-WindowsServices":
        Get_WindowsServices()
    elif arguments.action == "Get-UserInitMprScript":
        Get_UserInitMprScript()
    elif arguments.action == "Get-HHCtrlHijacking":
        Get_HHCtrlHijacking()

    if arguments.csv_output:
        output(arguments)

if __name__ == "__main__":
    arguments = parse_arguments()
    main(arguments)

#!/usr/bin/python3
#
# Written by Mariusz Banach <mb@binary-offensive.com>, @mariuszbit / mgeeky
#

import sys
import os
import re
import glob
import pefile
import argparse
import hashlib
import random
import string
import tempfile
import textwrap
import cabarchive
import shutil
import atexit
import urllib
from collections import OrderedDict
from textwrap import fill

if sys.platform != 'win32':
    print('\n\n[!] FATAL: This script can only be used in Windows system as it works with Win32 COM/OLE interfaces.\n\n')

import pythoncom
import win32com.client
from win32com.shell import shell, shellcon
from win32com.client import constants

USE_SSDEEP = False

try:
    import ssdeep
    USE_SSDEEP = True
except:
    quiet = False
    # for a in sys.argv:
    #     if a == '-q' or a == '--quiet':
    #         quiet = True
    #         break
    # if not quiet:
    #     print("[!] 'ssdeep' not installed. Will not use it.")

try:
    import colorama
    import magic
    import yara
    import olefile
    from prettytable import PrettyTable

except ImportError as e:
    print(f'\n[!] Requirements not installed: {e}\n\tInstall them with:\n\tcmd> pip install -r requirements.txt\n')
    sys.exit(1)

#########################################################

VERSION = '0.1 ALPHA'

#########################################################

options = {
    'debug' : False,
    'verbose' : False,
}

logger = None

try:
    colorama.init()
except:
    pass

class Logger:
    colors_map = {
        'red':      colorama.Fore.RED, 
        'green':    colorama.Fore.GREEN, 
        'yellow':   colorama.Fore.YELLOW,
        'blue':     colorama.Fore.BLUE, 
        'magenta':  colorama.Fore.MAGENTA, 
        'cyan':     colorama.Fore.CYAN,
        'white':    colorama.Fore.WHITE, 
        'grey':     colorama.Fore.WHITE,
        'reset':    colorama.Style.RESET_ALL,
    }
    
    def __init__(self, opts):
        self.opts = opts

    @staticmethod
    def colorize(txt, col):
        if type(txt) is not str:
            txt = str(txt)
        if not col in Logger.colors_map.keys() or options.get('nocolor', False):
            return txt
        return Logger.colors_map[col] + txt + Logger.colors_map['reset']

    @staticmethod
    def stripColors(txt):
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        result = ansi_escape.sub('', txt)
        return result

    def fatal(self, txt):
        self.text('[!] ' + txt, color='red')
        sys.exit(1)

    def info(self, txt):
        self.text('[.] ' + txt, color='yellow')

    def err(self, txt):
        self.text('[-] ' + txt, color='red')

    def ok(self, txt):
        self.text('[+] ' + txt, color='green')

    def verbose(self, txt):
        if self.opts.get('verbose', False) or self.opts.get('debug', False):
            self.text('[>] ' + txt, color='cyan')

    def dbg(self, txt):
        if self.opts.get('debug', False):
            self.text('[dbg] ' + txt, color='magenta')

    def text(self, txt, color='none'):
        if color != 'none':
            txt = Logger.colorize(txt, color)

        if not self.opts.get('quiet', False):
            print(txt)


class MSIDumper:
    # https://learn.microsoft.com/pl-pl/windows/win32/msi/custom-action-return-processing-options?redirectedfrom=MSDN
    CustomActionReturnType = {
        'check' : 0,
        'ignore' : 64,
        'asyncWait' : 128,
        'asyncNoWait' : 192,
    }

    # https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-execution-scheduling-options
    CustomActionExecuteType = {
        'always' : 0,
        'firstSequence' : 256,
        'oncePerProcess' : 512,
        'clientRepeat' : 768
    }

    #
    # https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options
    # Deferred, rollback and commit custom actions can only be placed between InstallInitialize and InstallFinalize
    #
    CustomActionInScriptExecute = {
        'immediate' : 0,
        'deferred' : 1,
        'rollback' : 1280,
        'commit' : 1536,
        'deferred-no-impersonate' : 3072,
        'rollback-no-impersonate' : 3328,
        'commit-no-impersonate' : 3584,
    }

    # https://learn.microsoft.com/en-us/windows/win32/msi/summary-list-of-all-custom-action-types
    CustomActionNativeTypes = {
        'dll-in-binary-table' : 1,
        'exe-in-binary-table' : 2,
        'jscript-in-binary-table' : 5,
        'vbscript-in-binary-table' : 6,
        'dll-installed-with-product' : 17,
        'exe-installed-with-product' : 18,
        'jscript-installed-with-product' : 21,
        'vbscript-installed-with-product' : 22,
        'exe-with-directory-path-in-target' : 34,
        'directory-set' : 35,
        'jscript-in-sequence-table' : 37,
        'vbscript-in-sequence-table' : 38,
        'exe-command-line' : 50,
        'jscript-with-funcname-in-property' : 53,
        'vbscript-with-funcname-in-property' : 55,
    }

    OpenMode = {
        'msiOpenDatabaseModeReadOnly' : 0,
        'msiOpenDatabaseModeTransact' : 1,
    }

    SkipColumns = (
        'extendedtype',
    )

    ListModes = (
        'all', 'olestream', 'cabs', 'binary', 'stats', 'olestreams',
    )

    ExtractModes = (
        'all', 'binary', 'files', 'cabs', 'scripts',
    )

    KnownCOMErrors = {
        0x80004005 : 'Could not process input database',
    }

    KnownTables = (
		'ActionText', 'AdminExecuteSequence', 'AdminUISequence', 'AdvtExecuteSequence', 'AdvtUISequence', 
        'AppId', 'AppSearch', 'BBControl', 'Billboard', 'Binary', 'BindImage', 'CCPSearch', 'CheckBox', 
        'Class', 'ComboBox', 'CompLocator', 'Complus', 'Component', 'Condition', 'Control', 'ControlCondition',
         'ControlEvent', 'CreateFolder', 'CustomAction', 'Dialog', 'Directory', 'DrLocator', 
         'DuplicateFile', 'Environment', 'Error', 'EventMapping', 'Extension', 'Feature', 'FeatureComponents', 
         'File', 'FileSFPCatalog', 'Font', 'Icon', 'IniFile', 'IniLocator', 'InstallExecuteSequence', 
         'InstallUISequence', 'IsolatedComponent', 'LaunchCondition', 'ListBox', 'ListView', 'LockPermissions', 
         'Media', 'MIME', 'MoveFile', 'MsiAssembly', 'MsiAssemblyName', 'MsiDigitalCertificate', 
         'MsiDigitalSignature', 'MsiEmbeddedChainer', 'MsiEmbeddedUI', 'MsiFileHash', 'MsiLockPermissionsEx', 
         'MsiPackageCertificate', 'MsiPatchCertificate', 'MsiPatchHeaders', 'MsiPatchMetadata', 'MsiPatchOldAssemblyFile', 
         'MsiPatchOldAssemblyName', 'MsiPatchSequence', 'MsiServiceConfig', 'MsiServiceConfigFailureActions', 
         'MsiSFCBypass', 'MsiShortcutProperty', 'ODBCAttribute', 'ODBCDataSource', 'ODBCDriver', 'ODBCSourceAttribute', 
         'ODBCTranslator', 'Patch', 'PatchPackage', 'ProgId', 'Property', 'PublishComponent', 'RadioButton', 
         'Registry', 'RegLocator', 'RemoveFile', 'RemoveIniFile', 'RemoveRegistry', 'ReserveCost', 'SelfReg', 
         'ServiceControl', 'ServiceInstall', 'SFPCatalog', 'Shortcut', 'Signature', 'TextStyle', 'TypeLib', 'UIText', 
         'Upgrade', 'Verb', '_Columns', '_Storages', '_Streams', '_Tables', '_TransformView', '_Validation',
    )

    ImportantTables = (
        'CustomAction', 'InstallExecuteSequence', '_Streams', 'Media', 'InstallUISequence', 'Binary', '_TransformView',
        'Component', 'Registry', 'Shortcut', 'RemoveFile', 'File',
    )

    SuspiciousTables = (
        'CustomAction', 'Binary', '_Streams', 
    )

    #
    # Approach based on assessing CustomAction Type numbers is prone to being evaded.
    # TODO: Rework it to properly consume Type number and decompose it onto flags:
    #  https://learn.microsoft.com/en-us/windows/win32/msi/summary-list-of-all-custom-action-types
    #
    CustomActionTypes = {
        'Execute' : {
            'color' : 'red',
            'types': (1250, 3298, 226),
            'desc' : 'Will execute system commands or other executables',
        },
        'VBScript' : {
            'color' : 'red',
            'types': (1126, 102),
            'desc' : 'Will run VBScript in-memory',
        }, 
        'JScript' : {
            'color' : 'red',
            'types': (1125, 101),
            'desc' : 'Will run JScript in-memory',
        },
        'Run-Exe' : {
            'color' : 'red',
            'types': (1218, 194),
            'desc' : 'Will extract executable from inner Binary table, drop it to:\n  C:\\Windows\\Installer\\MSIXXXX.tmp\nand then run it.',
        },
        'Load-DLL' : {
            'color' : 'red',
            'types': (65, ),
            'desc' : 'Will load DLL in memory and invoke its exported function.\nThat may also include .NET DLL',
        },
        'Run-Dropped-File' : {
            'color' : 'red',
            'types': (1746,),
            'desc' : 'Will run file extracted as a result of installation',
        },
        'Set-Directory' : {
            'color' : 'cyan',
            'types': (51,),
            'desc' : 'Will set Directory to a specific path',
        },
    }

    MimeTypesThatIncreasSuspiciousScore = (
        "application/hta",
        "application/js",
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/vns.ms-appx",
        "application/x-ms-shortcut",
        "application/x-vbs",
        'application/vnd.ms-excel', 
        'application/vnd.openxmlformats-officedocument.presentationml.presentation', 
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/x-dosexec',
    )

    RecognizedInnerFileTypes = {
        'cabinet' : {
            'indicator' : 'MS Cabinet archive (.CAB)',
            'safe-extension' : '.cab',
            'color' : 'yellow',
            'magic' : ('Microsoft Cabinet',)
        },
        'executable' : {
            'indicator' : 'PE executable (EXE)',
            'safe-extension' : '.exe.bin',
            'color' : 'red',
            'magic' : (
                'executable (console)', 
                'executable (GUI)', 
            )
        },
        'dll' : {
            'indicator' : 'PE executable (DLL)',
            'safe-extension' : '.dll.bin',
            'color' : 'red',
            'magic' : (
                'executable (DLL)', 
            )
        },
        'unsure-executable' : {
            'indicator' : 'PE executable (?)',
            'safe-extension' : '.exe.bin',
            'color' : 'red',
            'min-keywords' : 3,
            'keywords' : (
                'This program', 'cannot be', 'run in', 'dos mode',
            ),
        },
        'unsure-cabinet' : {
            'indicator' : 'CAB archive (?)',
            'safe-extension' : '.cab',
            'color' : 'yellow',
            'min-keywords' : 1,
            'keywords' : (
                'MSCF',
            ),
        },
        'unsure-vbscript' : {
            'indicator' : 'VBScript (?)',
            'safe-extension' : '.vbs.bin',
            'color' : 'red',
            'printable' : True,
            'min-keywords' : 3,
            'keywords' : (
                'dim', 'function ', 'sub ', 'createobject', 'getobject', 'with', 'string',
                'object', 'set', 'then', 'end if', 'end function', 'end sub'
            ),
            'not-keywords' : (
                '<?xml',
            )
        },
        'unsure-jscript' : {
            'indicator' : 'JScript (?)',
            'safe-extension' : '.js.bin',
            'color' : 'red',
            'printable' : True,
            'min-keywords' : 3,
            'keywords' : (
                'var', 'activexobject', 'try {', 'try{', '}catch', '} catch', 'return ',
            'function ',
            ),
            'not-keywords' : (
            )
        }
    }

    DangerousExtensions = (
        '.lnk', '.exe', '.cpl', '.xll', '.url', '.vbs', '.ps1', '.bat', '.psm', 
        '.wsc', '.wsf', '.dll', '.js', '.vbe', '.jse', '.hta', '.msi', '.cmd',
    )

    TableSortBy = {
        'InstallExecuteSequence' : 2,
        'InstallUISequence' : 2,
        'File' : 7,
        'Feature' : 4,
        'Media' : 0,
    }

    DefaultTableWidth = 128

    def __init__(self, options, logger):
        self.options = options
        self.logger = logger
        self.disinfectionMode = False
        self.report = []
        self.infile = ''
        self.csvDelim = ','
        self.maxWidth = self.options.get('print_len', -1)
        self.format = self.options.get('format', 'text')
        self.errorsCache = set()
        self.nativedb = None
        self.outdir = ''
        self.verdict = f'[.] Verdict: {Logger.colorize("Benign", "green")}'
        self.installer = None
        self.extractedCount = 0
        self.grade = 0

        self.specificTableAlignment = {
            'stats' : {
                'type' : 'r',
                'value' : 'l',
            },
            'report' : {
                'description': 'l',
                'context': 'l',
            }
        }

    @staticmethod
    def isprintable(data):
        if type(data) is str:
            data = data.encode()
        for a in data:
            if a not in string.printable.encode():
                return False
        return True

    @staticmethod
    def fromHexdumpToRaw(txt):
        raw = []
        if not re.match(r'[0-9a-f]+ \| [0-9a-f]{2}.*', txt.split('\n')[0], re.I):
            return txt.encode()

        for line in txt.split('\n'):
            line = line.strip()

            if re.match(r'[0-9a-f]+ \| [0-9a-f]{2}.*', line, re.I):
                parts = line.split('|')
                bytesPart = parts[1].strip()

                for m in re.finditer(r'([0-9a-f]{2})', bytesPart, re.I):
                    raw.append(int(m.group(1), 16))
        return bytes(raw)

    @staticmethod
    def hexdump(data, addr = 0, num = 0):
        s = ''
        n = 0
        lines = []
        if num == 0: num = len(data)

        if len(data) == 0:
            return '<empty>'

        if type(data) is str:
            data = data.encode()

        for i in range(0, num, 16):
            line = ''
            line += '%04x | ' % (addr + i)
            n += 16

            for j in range(n-16, n):
                if j >= len(data): break
                line += '%02x ' % (int(data[j]) & 0xff)

            line += ' ' * (3 * 16 + 7 - len(line)) + ' | '

            for j in range(n-16, n):
                if j >= len(data): break
                c = data[j] if not (data[j] < 0x20 or data[j] > 0x7e) else '.'
                line += '%c' % c

            lines.append(line)
        return '\n'.join(lines)

    def parseCOMException(self, message, error, additional=''):
        code = error.hresult + 2**32
        code2 = 0

        try:
            code2 = error.excepinfo[-1] + 2**32
        except:
            pass

        if code2 != 0:
            if code in MSIDumper.KnownCOMErrors:
                additional += MSIDumper.KnownCOMErrors[code]

            if code2 in MSIDumper.KnownCOMErrors:
                additional += MSIDumper.KnownCOMErrors[code2]

            self.logger.err(f'''{message}:

    {error}

    HRESULT 1: 0x{code:08X}          <-- General exception code

    HRESULT 2: 0x{code2:08X}          <-- COM exception code. Google up that error number: 
                                        https://google.com/?q={urllib.parse.quote_plus(f"COM exception 0x{code2:08X}")}

    {additional}
''')

        else:
            if code in MSIDumper.KnownCOMErrors:
                additional += MSIDumper.KnownCOMErrors[code]

            self.logger.err(f'''{message}:

    {error}

    HRESULT: 0x{code:08X}          <-- General exception code

    {additional}
''')

    def open(self, infile):
        self.infile = os.path.abspath(os.path.normpath(infile))
        self.outdir = os.path.abspath(os.path.normpath(self.options.get('outdir', '')))

        if not os.path.isfile(self.infile):
            self.logger.fatal(f'Input file does not exist: {self.infile}')

        mode = MSIDumper.OpenMode['msiOpenDatabaseModeReadOnly']

        if self.disinfectionMode:
            self.logger.fatal('MSI Disinfection is not yet implemented.')
            mode = MSIDumper.OpenMode['constants.msiOpenDatabaseModeTransact']

        self.initCOM()

        try:
            self.logger.dbg(f'Opening database {self.infile} ...')
            self.nativedb = self.installer.OpenDatabase(
                self.infile, 
                mode
            )

            return True

        except pythoncom.com_error as error:
            if self.options['debug']:
                self.parseCOMException(
                    message=f"Could not open MSI database natively via COM",
                    error=error
                )

            return False

    def close(self):
        if self.nativedb is not None:
            self.nativedb = None
        
        if self.installer is not None:
            try:
                self.installer.Release()
            except:
                pass

            self.installer = None

    def initCOM(self):
        if self.installer is not None:
            return

        try:
            #
            # Logic borrowed from:
            #   https://github.com/orestis/python/blob/master/Tools/msi/msilib.py#L60
            #

            self.logger.dbg('Initializing COM and instantiating WindowsInstaller.Installer ...')
            pythoncom.CoInitialize()

            win32com.client.gencache.EnsureModule('{000C1092-0000-0000-C000-000000000046}', 1033, 1, 0)

            self.installer = win32com.client.Dispatch(
                'WindowsInstaller.Installer',
                resultCLSID='{000C1090-0000-0000-C000-000000000046}'
            )

            if self.installer is None:
                self.logger.fatal('Could not instantiate WindowsInstaller.Installer!')

        except Exception as e:
            self.logger.fatal(f'Could not instantiate WindowsInstaller.Installer. Exception:\n\n\t{e}')

    def collectEntries(self, table, dontSort = False):
        entries = []

        try:
            entries = self._collectEntries(
                table, 
                dontSort
            )
        except Exception as e:
            self.logger.dbg(f'Error: Table {table} did not contain any records.')

            if self.options.get('debug', False):
                raise

        return entries

    def _collectEntries(self, table, dontSort = False):
        assert self.nativedb is not None, "Database is not opened"
        entries = []

        view = self.nativedb.OpenView(f"SELECT * FROM {table}")
        view.Execute(None)

        types = view.ColumnInfo(constants.msiColumnInfoTypes)
        names = view.ColumnInfo(constants.msiColumnInfoNames)
        columns = []

        for i in range(1, types.FieldCount+1):
            t = types.StringData(i)
            n = names.StringData(i)

            if t[0] in 'slSL':
                columns.append((n, 'str'))
            elif t[0] in 'iI':
                columns.append((n, 'int'))
            elif t[0] == 'v':
                columns.append((n, 'bin'))
            else:
                self.logger.dbg(f'Unsupported column type: table {table}, column: {i}. Type: {t}, Name: {n}')
                columns.append((n, '?'))

        while True:
            r = view.Fetch() 
            if not r:
                break

            rec = OrderedDict()
            for i in range(1, r.FieldCount+1):
                val = None
                name = columns[i-1][0]

                if r.IsNull(i):
                    val = ''

                elif columns[i-1][1] == 'str': 
                    try:
                        val = r.StringData(i)

                    except Exception as e:
                        txt = f'Could not convert {table} column {columns[i-1][0]} value to string (type: {columns[i-1][1]}): {e}'
                        if txt not in self.errorsCache:
                            self.logger.dbg(txt)
                            self.errorsCache.add(txt)
                        val = ''

                elif columns[i-1][1] == 'int': 
                    try:
                        val = r.IntegerData(i)
                    except Exception as e:
                        txt = f'Could not convert {table} column {columns[i-1][0]} value to integer (type: {columns[i-1][1]}): {e}'
                        if txt not in self.errorsCache:
                            self.logger.dbg(txt)
                            self.errorsCache.add(txt)
                        val = 0

                elif columns[i-1][1] == 'bin': 
                    size = r.DataSize(i)
                    val = r.ReadStream(i, size, constants.msiReadStreamBytes)

                rec[columns[i-1][0].lower()] = val

            entries.append(rec)

        view.Close()

        if not dontSort and table in MSIDumper.TableSortBy:
            entries = sorted(entries, key=lambda x: list(x.values())[MSIDumper.TableSortBy[table]] )

        self.logger.dbg(f'Collected {len(entries)} entries from {table} ...')
        return entries

    def getMaxValueFromTable(self, table, columnNum):
        maxVal = -1
        entries = self.collectEntries(table)

        for entry in entries:
            if maxVal < entry[columnNum]:
                maxVal = entry[columnNum]

        return maxVal

    def analyse(self):
        assert self.nativedb is not None, "Database is not opened"

        try:
            ret = self.analysisWorker()

            if self.grade > 0:
                self.verdict = f'[.] Verdict: {Logger.colorize("SUSPICIOUS", "red")}'

            self.logger.verbose(f'Verdict grade: {self.grade}')

            return ret

        except Exception as e:
            if self.nativedb is not None:
                self.nativedb = None

            if self.options['debug']: 
                raise
            else:
                Logger.err(f'Could not analyse input MSI. Enable --debug to learn more. Exception: {e}')

            return False

        finally:
            pass

    def listTable(self, table):
        assert self.nativedb is not None, "Database is not opened"

        records = None

        if table.lower() not in [x.lower() for x in MSIDumper.KnownTables + MSIDumper.ListModes]:
            self.logger.fatal(f'Unsupported --list setting: {table}')

        if table == 'streams':  table = '_Streams'
        if table == 'stream':   table = '_Streams'
        if table == 'binary':   table = 'Binary'
        if table == 'cabs':     table = 'Media'
        if table == 'olestreams':table = 'olestream'

        if table.lower() in [x.lower() for x in MSIDumper.KnownTables]:
            try:
                if table not in MSIDumper.KnownTables:
                    for t in MSIDumper.KnownTables:
                        if table.lower() == t.lower():
                            table = t
                            break

                index = self.options.get('record', -1)
                if index != -1:
                    records0 = self.collectEntries(table)

                    try:
                        index = int(index)
                        if index < 0 or index-1 > len(records0):
                            self.logger.fatal(f'Invalid --record specified. There were only {len(records0)} records returned from {table}.\n\t\tUse value between --record 1 and --record {len(records0)}')
                        records = [ records0[index-1], ]
                    except:
                        records = []
                        for a in records0:
                            vals = list(a.values())
                            if len(vals) > 0 and vals[0].lower() == index.lower():
                                records.append(a)
                                break

                        if len(records) == 0:
                            self.logger.fatal(f'Invalid --record specified. Could not find {table} record entry based on its index number nor ID name.')
                else:
                    records = self.collectEntries(table)  
     
            except Exception as e:
                self.logger.err(f'Exception occurred while enumerating {table} entries: {e}')

                if self.options.get('debug', False):
                    raise
        else:
            table = table.lower()

            try:
                if table == 'stats':
                    records = self.collectStats()
                elif table == 'all':
                    return self.collectAll()
                elif table == 'olestream':
                    records = self.collectStreams()
                else:
                    self.logger.fatal(f'Unsupported --list setting: {table}')

            except Exception as e:
                self.logger.err(f'Exception occurred while pulling MSI metadata {table}: {e}')

                if self.options.get('debug', False):
                    raise

        if records is not None:
            self.tableSpecificHighlighting(table, records)
            return self.printTable(table, records)

        else:
            if table in MSIDumper.KnownTables:
                return f'No records found in {Logger.colorize(table, "green")} table.'
            else:
                return f'No {Logger.colorize(table, "green")} metadata was extracted.'

    def tableSpecificHighlighting(self, table, records):
        if table.lower() == 'customaction':
            for i in range(len(records)):
                rec = records[i]
                for k, v in rec.items():
                    if k == 'type':
                        col = ''
                        for a, b in MSIDumper.CustomActionTypes.items():
                            if v in b['types']:
                                col = b['color']
                                break
                        if col != '':
                            records[i][k] = Logger.colorize(v, col)
                            records[i]['source'] = Logger.colorize(records[i]['source'], col)

        if table.lower() == 'binary':
            for i in range(len(records)):
                records[i]['Magic type'] = self.sniffDataType(records[i]['data'], color=True)
        
    def extract(self, what):
        assert self.nativedb is not None, "Database is not opened"

        what = what.lower()

        if what == 'script':
            what = 'scripts'

        if what not in [x.lower() for x in MSIDumper.ExtractModes]:
            self.logger.fatal(f'Unsupported --extract setting: {what}')

        self.outdir = os.path.normpath(os.path.abspath(self.options.get('outdir', '')))
        if len(self.outdir) == 0:
            self.outdir = os.getcwd()

        if not os.path.isdir(self.outdir):
            os.makedirs(self.outdir)

        if what == 'all':
            return self.extractAll()
        elif what == 'binary':
            return self.extractBinary()
        elif what == 'files':
            return self.extractFiles()
        elif what == 'cabs':
            return self.extractCABs()
        elif what == 'scripts':
            return self.extractScripts()

    def extractAll(self):
        output = ''

        outs = self.extractBinary()
        if len(outs) > 0:
            output += outs + '\n'
        
        outs = self.extractFiles()
        if len(outs) > 0:
            output += outs + '\n'

        outs = self.extractCABs()
        if len(outs) > 0:
            output += outs + '\n'

        outs = self.extractScripts()
        if len(outs) > 0:
            output += outs + '\n'

        output += f'\nExtracted in total {self.extractedCount} objects.\n'

        return output

    def sanitizeName(self, name):
        windowsNames = (
            'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 
            'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 
            'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 
            'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9', 
        )

        for a in ('..', '\\', '/', '"', "'", '?', '*', ':'):
            name = name.replace(a, '')

        for a in windowsNames:
            name = name.replace(a, '')
        
        if len(name) == 0:
            name = 'bin-' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))

        return name

    def extractBinary(self):
        binary = self.collectEntries('Binary')
        num = 0
        output = ''

        self.logger.verbose('Extracting data from Binary table...')

        if len(binary) == 0:
            self.logger.err('Input MSI does not contain any embedded Binary data.')

        for elem in binary:
            sniffed = self.sniffDataType(elem['data'])
            name = self.sanitizeName(elem['name']) + self.sniffDataExt(sniffed)
            outp = os.path.join(self.outdir, name)

            with open(outp, 'wb') as f:
                f.write(elem['data'].encode())

            num += 1
            output += f'\n{Logger.colorize("[+]","green")} Extracted {Logger.colorize(len(elem["data"]),"green")} bytes of {Logger.colorize(elem["name"],"green")} object to: {Logger.colorize(outp,"yellow")}'

        self.extractedCount += num
        if num > 0 and self.options.get('extract', '') != 'all':
            output += f'\n\nExtracted in total {num} objects.\n'

        return output

    def extractCab(self, infile, outdir, files):
        with open(infile, "rb") as f:
            arc = cabarchive.CabArchive(f.read())

        self.logger.verbose('Extracting Cabinets from MSI...')

        output = f'Extracting files from CAB ({infile}):\n\n'
        num = 0

        for k, v in arc.items():
            fn = v.filename

            for _file in files:
                if fn == _file['file']:
                    fn = _file['filename']

            p, ext = os.path.splitext(fn)
            if ext.lower() in MSIDumper.DangerousExtensions:
                fn += '.bin'

            lp = os.path.join(outdir, fn)

            lp1 = os.path.join(outdir, os.path.dirname(lp))
            if not os.path.isdir(lp1):
                output += f'\t{Logger.colorize("[+]","green")} Creating temp dir: {lp1}\n'
                os.makedirs(lp1, exist_ok=True)

            output += f'{Logger.colorize("[+]","green")} {v.filename:20} => {lp}\n'
            with open(lp, 'wb') as f:
                f.write(v.buf)
                num += 1

        return num, output

    def extractFiles(self, overrideOutdir=''):
        outdir = self.outdir
        if len(overrideOutdir) > 0:
            dirpath = overrideOutdir
        else:
            dirpath = tempfile.mkdtemp()

        self.outdir = dirpath
        self.extractCABs()
        self.outdir = outdir

        self.logger.verbose('Extracting files from MSI...')

        cabsNum = 0
        num = 0
        output = ''
        files = self.collectEntries('File')

        path = os.path.join(dirpath, '*.cab')
        for cab in glob.glob(path, recursive=True):
            cabPath = os.path.join(path, cab)
            cabsNum += 1
            outp = os.path.join(dirpath, os.path.basename(cabPath).replace('.cab', ''))

            try:
                num0, output0 = self.extractCab(cabPath, outp, files)
                num += num0
                output += output0

            except Exception as e:
                self.logger.err(f'Could not extract files from CABinet: {cabPath}. Error: {e}')
                if self.options.get('debug', False):
                    raise
            finally:
                if os.path.isfile(cabPath):
                    os.remove(cabPath)

        if dirpath != overrideOutdir:
            shutil.rmtree(dirpath)

        self.extractedCount += num
        if num > 0 and self.options.get('extract', '') != 'all':
            output += f'\nExtracted in total {num} files from {cabsNum} cabinets.\n'

        return output

    def extractCABs(self):
        binary = self.collectEntries('Binary')
        num = 0
        output = ''

        if len(binary) == 0:
            self.logger.err('Input MSI does not contain any embedded Binary data.')

        for elem in binary:
            sniffed = self.sniffDataType(elem['data'])
            if '.cab' not in sniffed.lower():
                continue

            name = self.sanitizeName(elem['name']) + '.cab'
            outp = os.path.join(self.outdir, name)

            with open(outp, 'wb') as f:
                f.write(elem['data'].encode())

            num += 1

        # source: https://github.com/decalage2/oletools/blob/master/oletools/oledir.py#L245
        ole = olefile.OleFileIO(self.infile)
        for entry in ole.listdir():
            name = entry[-1]
            name = repr(name)[1:-1]
            entry_id = ole._find(entry)
            try:
                size = ole.get_size(entry)
            except:
                size = '-'

            data0 = ole.openstream(entry).getvalue()
            data = data0.decode(errors='ignore')

            sniffed = self.sniffDataType(data)
            if '.cab' not in sniffed.lower():
                continue

            name = f'ole-stream-{entry_id}.cab'
            outp = os.path.join(self.outdir, name)

            with open(outp, 'wb') as f:
                f.write(data0)

            num += 1
            output += f'\n{Logger.colorize("[+]","green")} Extracted {Logger.colorize(len(elem["data"]), "green")} bytes of {Logger.colorize(elem["name"],"green")} object to: {Logger.colorize(outp,"yellow")}'

        self.extractedCount += num
        if num > 0 and self.options.get('extract', '') != 'all':
            output += f'\n\nExtracted in total {num} objects.\n'

        return output

    def extractScripts(self):
        binary = self.collectEntries('Binary')
        actions = self.collectEntries('CustomAction')
        num = 0
        output = ''

        self.logger.verbose('Extracting scripts from CustomAction and Binary tables...')

        if len(binary) == 0:
            self.logger.err('Input MSI does not contain any embedded Binary data.')

        for elem in actions:
            sniffed = self.sniffDataType(elem['target'])
            if 'vbscript' not in sniffed.lower() and 'jscript' not in sniffed.lower():
                continue

            name = self.sanitizeName(elem['action'])
            outp = os.path.join(self.outdir, name) + self.sniffDataExt(sniffed)

            with open(outp, 'wb') as f:
                f.write(elem['target'].encode())

            num += 1
            output += f'\n{Logger.colorize("[+]","green")} Extracted {Logger.colorize(len(elem["target"]),"green")} bytes of {Logger.colorize(elem["action"],"green")} CustomAction script to: {Logger.colorize(outp,"yellow")}'

        for elem in binary:
            sniffed = self.sniffDataType(elem['data'])
            if 'vbscript' not in sniffed.lower() and 'jscript' not in sniffed.lower():
                continue
                
            name = self.sanitizeName(elem['name'])
            outp = os.path.join(self.outdir, name) + self.sniffDataExt(sniffed)

            with open(outp, 'wb') as f:
                f.write(elem['data'].encode())

            num += 1
            output += f'\n{Logger.colorize("[+]","green")} Extracted {Logger.colorize(len(elem["data"]),"green")} bytes of {Logger.colorize(elem["name"],"green")} binary object script to: {Logger.colorize(outp,"yellow")}'

        self.extractedCount += num
        if num > 0 and self.options.get('extract', '') != 'all':
            output += f'\n\nExtracted in total {num} objects.\n'

        return output

    def formatTable(self, tbl, table, records):
        if self.maxWidth > -1 and len(records) > 0:
            for k in records[0].keys():
                tbl._max_width[k] = self.maxWidth

        tbl.align['YARA Results'] = 'l'

        if table.lower() in self.specificTableAlignment.keys():
            for k, v in self.specificTableAlignment[table.lower()].items():
                tbl.align[k] = v

        if table.lower() in [x.lower() for x in MSIDumper.TableSortBy] and len(records) > 0:
            tbl.sortby = list(records[0].keys())[MSIDumper.TableSortBy[table]]

        return tbl

    def collectAll(self):
        output = ''

        self.logger.info('Dumping all MSI tables...')

        for table in MSIDumper.KnownTables:
            recs = self.collectEntries(table)

            if not self.options.get('verbose', False) and len(recs) == 0 and table not in MSIDumper.ImportantTables:
                continue

            output += '\n\n'
            output += Logger.colorize(f'===============[ {table} : {len(recs)} records ]===============', 'green')
            output += '\n\n'
            output += self.printTable(table, recs)

        return output
    
    def collectStreams(self):
        records = []

        ole = olefile.OleFileIO(self.infile)
        for entry in ole.listdir(storages=True):
            name = entry[-1]
            name = repr(name)[1:-1]
            entry_id = ole._find(entry)
            try:
                size = ole.get_size(entry)
            except:
                size = '-'
            typeid = ole.get_type(entry)
            clsid = ole.getclsid(entry)
            
            data0 = ole.openstream(entry).getvalue()
            data = data0.decode(errors='ignore')
            sniffed = self.sniffDataType(data, color=True)

            records.append({
                'entry_id' : entry_id,
                'data type' : sniffed,
                'name' : Logger.colorize(name, 'yellow'),
                'size' : size,
                'typeid' : typeid,
                'CLSID' : clsid,
            })

        return sorted(records, key=lambda x: x['entry_id'])

    def collectStats(self):
        records = []
        hashes = (
            'md5', 'sha1', 'sha256', 'ssdeep'
        )

        self.logger.info('Computing MSI file hashes...')

        with open(self.infile, 'rb') as f:
            data = f.read()

            for h in hashes:
                if h == 'ssdeep':
                    if USE_SSDEEP:
                        hsh = ssdeep.hash(data)
                    else:
                        hsh = 'err: ssdeep module not installed'
                else:
                    m = hashlib.new(h)
                    m.update(data)
                    hsh = m.hexdigest()

                records.append({
                    'type' : Logger.colorize(f'Hash {h}', 'cyan'),
                    'value' : Logger.colorize(hsh, 'cyan'),
                })

        del data

        self.logger.info('Collecting MSI tables stats...')

        for table in MSIDumper.KnownTables:
            recs = self.collectEntries(table)
            val = f'{len(recs)} records'

            if table in MSIDumper.SuspiciousTables:
                table = Logger.colorize(table, 'red')
                val = Logger.colorize(val, 'red')

            elif table in MSIDumper.ImportantTables:
                table = Logger.colorize(table, 'yellow')
                val = Logger.colorize(val, 'yellow')

            else:
                if len(recs) == 0 and not self.options.get('verbose', False):
                    continue

            records.append({
                'type' : table,
                'value' : val,
            })

        return records

    def analysisWorker(self):
        self.processActions()
        self.lookForIOCs()

        return self.printReport()

    def normalizeDataForOutput(self, val, num=0, table=''):
        if num == 0:
            num = self.options.get('print_len', MSIDumper.DefaultTableWidth)

        if num != -1:
            val = val[:num]

        printable = MSIDumper.isprintable(val)

        if not printable and table not in ('olestream', ):
            printable2 = MSIDumper.isprintable(Logger.stripColors(val))
            if not printable2:
                val = MSIDumper.hexdump(val) + '\n'

        return val
    
    def cleanString(self, txt):
        txt = txt.replace('\r', '')
        txt = txt.replace('\t', '  ')
        return txt

    def printTable(self, table, records):
        if len(records) == 0:
            return f'\n\nNo records found in table {Logger.colorize(table, "green")}.'

        yaraColumn = ''
        self.logger.dbg(f'Dumping {table} table results...')

        rules = None
        if len(self.options.get('yara', '')) > 0 and table != 'YARA Results':
            yaraColumn = 'YARA Results'
            matchesReport = []
            rules = self.initYara()

        if len(records) == 1:
            output = '\n'

            for k, v in records[0].items():
                k0 = Logger.colorize(k, "green")
                output += f'- {k0:20} : '

                if type(v) is str:
                    v = self.normalizeDataForOutput(v, -1, table=table)

                    if len(v) < 50:
                        output += v
                    else:
                        spacer = Logger.colorize('=' * MSIDumper.DefaultTableWidth, 'yellow')
                        output += '\n\n' + spacer + '\n\n' + v + '\n\n' + spacer + '\n'
                else:
                    output += str(v)

                if table in ('binary', ):
                    output += '\n'

            if len(yaraColumn) > 0:
                k0 = Logger.colorize(yaraColumn, "green")
                output += f'- {k0:20} : '

                for k, v in records[0].items(): 
                    if type(v) is not str:
                        continue
                    matches = rules.match(data = v)
                    if matches:
                        ms = ''
                        for m in matches:
                            ms += f'- {m.rule}\n'
                        output += Logger.colorize(f'YARA rule match on column {k}:', 'green') + '\n' + ms + '\n'
        else:
            output = ''
            numCol = ['#',]
            yarCol = []
            if table == 'olestream':
                numCol = []

            if len(yaraColumn) > 0:
                yarCol = [yaraColumn, ]

            tbl = PrettyTable(numCol + list(records[0].keys()) + yarCol)
            num = 0

            index = self.options.get('record', -1)
            if index != -1:
                num = index - 1

            tbl = self.formatTable(tbl, table, records)

            for rec in records:
                num += 1
                vals = []
                i = 0
                for v in [num, ] + list(rec.values()):
                    if i == 0 and 'entry_id' in rec.keys():
                        i += 1
                        continue
                    if type(v) is str:
                        v = self.normalizeDataForOutput(v, table=table)
                        s = self.cleanString(v).strip()
                        n = ''

                        if table.lower() in ('binary', ):
                            n = '\n'

                        vals.append(s + n)
                    else:
                        vals.append(v)
                    i += 1

                if len(yaraColumn) > 0:
                    i = 0
                    val = ''
                    for v in list(rec.values()): 
                        if type(v) is not str:
                            i += 1
                            continue
                        matches = rules.match(data = v)
                        if matches:
                            ms = ''
                            for m in matches:
                                ms += f'- {m.rule}\n'
                            k = list(rec.keys())[i]
                            val += Logger.colorize(f'YARA rule match on column {k}:', 'green') + '\n' + ms + '\n'
                        i += 1
                    vals.append(val)

                tbl.add_row(vals)

            output += str(tbl)

            if table != 'YARA Results':
                output += f'\n\nFound {Logger.colorize(str(len(records)), "green")} records in {Logger.colorize(table, "green")} table.'

        return output + '\n'

    def printReport(self):
        output = ''
        cols = [
            '#',
            'threat',
            'location',
            'context',
            'description'
        ]
        tbl = PrettyTable(cols)
        tbl = self.formatTable(tbl, 'report', self.report)

        num = 0

        for report in self.report:
            num += 1
            rec = [
                num,
                report['name'],
                report['location'],
                report['context'],
                report['desc'],
            ]
            vals = []
            for v in rec:
                if type(v) is str:
                    vals.append(self.cleanString(v))
                else:
                    vals.append(v)

            tbl.add_row(vals)

        output += str(tbl)
        return output

    def printRecord(self, rec, indent=''):
        out = ''
        keyLen = -1

        if type(rec) is str:
            return rec

        for k, v in rec.items():
            if len(k) > keyLen:
                keyLen = len(Logger.colorize(k, 'yellow')) + 1

        if self.format == 'text':
            for k, v in rec.items():
                if k.lower() in MSIDumper.SkipColumns:
                    continue

                if type(v) is str or type(v) is bytes:
                    printable = MSIDumper.isprintable(v)

                    if not printable and v[0] != '\x1b':
                        v = '\n\n' + MSIDumper.hexdump(v) + '\n'

                    if self.options.get('record', -1) == -1 and len(v) > 256: 
                        v = '\n\n' + v[:256].strip() + '\n\t[CUT FOR BREVITY]\n'

                k = Logger.colorize(k, 'yellow')
                out += indent + f'- {k:{keyLen}}: {v}\n'

        elif self.format == 'csv':
            out = self.csvDelim.join([x.replace(self.csvDelim, '') for x in rec.values()])

        return out

    @staticmethod
    def isValidPE(data):
        pe = None
        try:
            pe = pefile.PE(data=data.encode(), fast_load=True)
            _format = MSIDumper.RecognizedInnerFileTypes['executable']['indicator']

            if pe.OPTIONAL_HEADER.DllCharacteristics != 0:
                _format = MSIDumper.RecognizedInnerFileTypes['dll']['indicator']

            pe.close()
            return (True, _format)
        except pefile.PEFormatError as e:
            logger.dbg(f'pefile error: {e}')
            return (False, '')
        finally:
            if pe:
                pe.close()

    def sniffDataExt(self, sniffed):
        for k, v in MSIDumper.RecognizedInnerFileTypes.items():
            if v['indicator'].lower() == sniffed.lower():
                return MSIDumper.RecognizedInnerFileTypes[k]['safe-extension']

        return ''

    def gradeFoundIndicator(self, indicator, data='', color='', mime=''):
        if color != '':
            if color == 'red':
                return 1
        
        if mime != '' and mime.lower() in MSIDumper.MimeTypesThatIncreasSuspiciousScore:
            return 1

        return 0

    def sniffDataType(self, data, color=False):
        mime = self.options.get('mime', False)
        magicOut = magic.from_buffer(data, mime=mime)

        pe, petype = MSIDumper.isValidPE(data)
        if pe:
            if mime and magicOut in ('data', 'application/octet-stream'):
                indicator = 'application/x-dosexec'
            if color:
                indicator = Logger.colorize(petype, 'red')
            self.grade += self.gradeFoundIndicator(indicator, data, color='red')
            return indicator

        for format, predicate in MSIDumper.RecognizedInnerFileTypes.items():
            indicator = predicate.get('indicator', '')
            predColor = predicate.get('color', '')

            if format == 'unsure-executable':
                if data[:2] != 'MZ' and data[:2] != 'ZM':
                    continue
            elif format == 'unsure-cabinet':
                if data[:4] != 'MSCF':
                    continue

            if mime:
                indicator = magicOut

            if color:
                indicator = Logger.colorize(indicator, predColor)
                
            magicVals = predicate.get('magic', [])
            if len(magicVals) > 0:
                for m in magicVals:
                    if m.lower() in magicOut.lower():
                        self.grade += self.gradeFoundIndicator(indicator, data, color=predColor)
                        return indicator

            keywords = predicate.get('keywords', [])
            minkeywords = predicate.get('min-keywords', 0)
            
            printable = predicate.get('printable', 0)
            printableMet = False
            if printable:
                if MSIDumper.isprintable(data):
                    printableMet = True

            if printable and not printableMet:
                continue

            if len(keywords) > 0 and minkeywords > 0:
                skip = False
                found = 0
                for keyword in keywords:
                    if re.search(r'\b' + re.escape(keyword) + r'\b', data, re.I):
                        found += 1

                if found >= minkeywords:
                    foundNots = 0
                    notkeywords = predicate.get('not-keywords', [])

                    if len(notkeywords) > 0:
                        for keyword in notkeywords:
                            if re.search(r'\b' + re.escape(keyword) + r'\b', data, re.I):
                                foundNots += 1

                    if foundNots == 0:
                        self.grade += self.gradeFoundIndicator(indicator, data, color=predColor)
                        return indicator

        if magicOut == 'data':
            return ''

        return magicOut

    def lookForIOCs(self):
        binary = self.collectEntries('Binary')
        customActions = self.collectEntries('CustomAction')
        i = 0

        streams = self.collectEntries('_Streams')
        if len(streams) == 0:
            self.report.append({
                'name' : Logger.colorize('Missing _Streams', 'yellow'),
                'location' : f'_Streams table',
                'context' : '',
                'desc' : f'Typically MSIs contain _Streams table referring .CAB archives.\nThis sample however didn\'t contain such table, making it unusual/mangled.\n',
            })

        for data in binary:
            i += 1
            sniffed = self.sniffDataType(data['data'], color=True)

            if len(sniffed) > 0:
                data['size'] = len(data['data'])
                runByCa = False
                desc = ''

                i = 0
                for ca in customActions:
                    i += 1
                    if ca['source'] == data['name']:
                        runByCa = True
                        desc = f'\nThat data will be used during installation by CustomAction {Logger.colorize(i, "yellow")}. {Logger.colorize(ca["action"], "yellow")}'
                        break

                if not runByCa:
                    self.grade -= 1
                    sniffed = Logger.stripColors(sniffed)
                    sniffed = Logger.colorize(sniffed, 'yellow')
                    desc = '\nHowever that data doesn\'t seem to be used in CustomActions, decreasing impact.'

                self.report.append({
                    'name' : sniffed,
                    'location' : f'Binary table',
                    'context' : self.printRecord(data),
                    'desc' : f'MSI contains {sniffed} data in Binary table entry {Logger.colorize(str(i), "yellow")}. {Logger.colorize(data["name"], "yellow")}' + desc,
                })

    def processActions(self):
        actions = self.collectEntries('CustomAction')
        execSeq = self.collectEntries('InstallExecuteSequence')
        uiSeq = self.collectEntries('InstallUISequence')

        for action in actions:
            self.logger.dbg(f'Parsing CustomAction {action["action"]} ...')

            for suspAction, data in MSIDumper.CustomActionTypes.items():
                if action['type'] in data['types']:
                    desc = data['desc']
                    color = MSIDumper.CustomActionTypes[suspAction].get('color', 'white')

                    fieldToHighlight = ''

                    if 'vbscript' in suspAction.lower() or 'jscript' in suspAction.lower():
                        if len(action['source']) > 0:
                            fieldToHighlight = 'source'
                            self.grade += self.gradeFoundIndicator(suspAction, color=color)
                            desc += f".\nScript is located in {Logger.colorize(action['source'],'yellow')} Binary table record."

                    elif 'run-dll' in suspAction.lower():
                        fieldToHighlight = 'source'
                        self.grade += self.gradeFoundIndicator(suspAction, color=color)
                        desc += f".\nDLL is located in {Logger.colorize(action['source'],'yellow')} Binary table record."
                    
                    elif 'run-exe' in suspAction.lower():
                        fieldToHighlight = 'source'
                        self.grade += self.gradeFoundIndicator(suspAction, color=color)
                        desc += f"\nEXE is located in {Logger.colorize(action['source'],'yellow')} Binary table record."

                    elif 'set-directory' in suspAction.lower():
                        fieldToHighlight = 'target'

                    elif 'execute' in suspAction.lower():
                        fieldToHighlight = 'target'
                        self.grade += self.gradeFoundIndicator(suspAction, color=color)
                        desc += f".\nCommand that will be executed:\ncmd> {Logger.colorize(action['target'],'red')}"

                    foundInSeq = False
                    for seq in execSeq:
                        if seq['action'] == action['action']:
                            foundInSeq = True
                            cond = ''
                            if len(seq['condition']) > 0:
                                cond = f" with condition:\n- {Logger.colorize(seq['condition'],'yellow')}"

                            desc += f"\nThat action is scheduled to run in {Logger.colorize('InstallExecuteSequence','yellow')} table" + cond + '\n'
                            break

                    for seq in uiSeq:
                        if seq['action'] == action['action']:
                            foundInSeq = True
                            cond = ''
                            if len(seq['condition']) > 0:
                                cond = f" with condition:\n- {Logger.colorize(seq['condition'],'yellow')}"

                            desc += f"\nThat action is scheduled to run in {Logger.colorize('InstallUISequence','yellow')} table" + cond + '\n'
                            break

                    if not foundInSeq:
                        self.grade -= 1
                        color = 'yellow'
                        desc = '\nHowever that action doesn\'t seem to be invoked anywhere, decreasing impact.'

                    if len(fieldToHighlight) > 0:
                        action[fieldToHighlight] = Logger.colorize(action[fieldToHighlight], color)

                    self.report.append({
                        'name' : Logger.colorize(suspAction, color),
                        'location' : f'CustomAction table',
                        'context' : self.printRecord(action),
                        'desc' : desc
                    })
                    break

    def initYara(self):
        yaraPath = self.options.get('yara', '')
        if len(yaraPath) == 0:
            return None

        yaraPath = os.path.abspath(os.path.normpath(yaraPath))

        if not os.path.isfile(yaraPath) and not os.path.isdir(yaraPath):
            self.logger.fatal(f'Specified --yara path does not exist.')

        rules = None
        try:
            rules = yara.compile(yaraPath)
        except Exception as e:
            self.logger.fatal(f'Could not compile YARA rules. Exception: {e}')

        return rules

    def yaraScan(self, scanBinary=True, scanActions=True, scanFiles=True):
        matchesReport = []
        rules = self.initYara()

        if scanBinary:
            binary = self.collectEntries('Binary')
            output = ''

            if len(binary) > 0:
                i = 0
                for elem in binary:
                    i += 1
                    matches = rules.match(data = elem['data'].encode())
                    if matches:
                        matchesReport.append({
                            'where' : f'Binary record {Logger.colorize(i, "yellow")}. {Logger.colorize(elem["name"], "yellow")}',
                            'rules' : '\n'.join([x.rule for x in matches])
                        })

        if scanActions:
            actions = self.collectEntries('CustomAction')
            output = ''

            if len(actions) > 0:
                i = 0
                for elem in actions:
                    sniffed = self.sniffDataType(elem['target'])
                    if 'vbscript' not in sniffed.lower() and 'jscript' not in sniffed.lower():
                        continue
                    i += 1
                    matches = rules.match(data = elem['data'])
                    if matches:
                        matchesReport.append({
                            'where' : f'CustomAction record {Logger.colorize(i, "yellow")}. {Logger.colorize(elem["name"], "yellow")}',
                            'rules' : '\n'.join([x.rule for x in matches])
                        })

        if scanFiles:
            try:
                dirpath = tempfile.mkdtemp()
                self.logger.verbose(f'Extracting all files from MSI into temp dir: {dirpath} ...')

                out = self.extractFiles(overrideOutdir = dirpath)

                for _file in glob.glob(os.path.join(dirpath, '**/*.*'), recursive=True):
                    path = os.path.join(dirpath, _file)

                    matches = rules.match(path)
                    if matches:
                        matchesReport.append({
                            'where' : f'File extracted from MSI: {Logger.colorize(os.path.basename(path), "yellow")}',
                            'rules' : '\n'.join([x.rule for x in matches])
                        })

            except Exception as e:
                self.logger.err(f'Could not extract files from MSI for YARA scanning. Exception: {e}')
                if self.options.get('debug', False):
                    raise

            finally:
                if os.path.isdir(dirpath):
                    shutil.rmtree(dirpath)

        if len(matchesReport) > 0:
            output += Logger.colorize(f'[+] Got {len(matchesReport)} YARA rules matches on this MSI:\n\n', 'green')
            output += self.printTable('YARA Results', matchesReport)

        return output

def getoptions():
    global logger
    global options

    epilog = f'''

------------------------------------------------------

- What can be listed:
    --list CustomAction     - Specific table
    --list stats            - Print MSI database statistics
    --list all              - All tables and their contents
    --list olestream        - Prints all OLE streams & storages. 
                              To display CABs embedded in MSI try: --list _Streams
    --list cabs             - Lists embedded CAB files
    --list binary           - Lists binary data embedded in MSI for its own purposes.
                              That typically includes EXEs, DLLs, VBS/JS scripts, etc

- What can be extracted:
    --extract all           - Extracts Binary data, all files from CABs, scripts from CustomActions
    --extract binary        - Extracts Binary data
    --extract files         - Extracts files
    --extract cabs          - Extracts cabinets
    --extract scripts       - Extracts scripts

------------------------------------------------------

'''

    usage = '\nUsage: msidump.py [options] <infile.msi>\n'
    opts = argparse.ArgumentParser(
        usage=usage,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(epilog)
    )

    req = opts.add_argument_group('Required arguments')
    req.add_argument('infile', help='Input MSI file (or directory) for analysis.')
    
    opt = opts.add_argument_group('Options')
    opt.add_argument('-q', '--quiet', default=False, action='store_true', help='Surpress banner and unnecessary information. In triage mode, will display only verdict.')
    opt.add_argument('-v', '--verbose', default=False, action='store_true', help='Verbose mode.')
    opt.add_argument('-d', '--debug', default=False, action='store_true', help='Debug mode.')
    opt.add_argument('-N', '--nocolor', default=False, action='store_true', help='Dont use colors in text output.')
    opt.add_argument('-n', '--print-len', default=MSIDumper.DefaultTableWidth, type=int, help='When previewing data - how many bytes to include in preview/hexdump. Default: 128')
    opt.add_argument('-f', '--format', default='text', choices=['text', 'json', 'csv'], help='Output format: text, json, csv. Default: text')
    opt.add_argument('-o', '--outfile', metavar='path', default='', help='Redirect program output to this file.')
    opt.add_argument('-m', '--mime', default=False, action='store_true', help='When sniffing inner data type, report MIME types')
    
    mod = opts.add_argument_group('Analysis Modes')
    mod.add_argument('-l', '--list', metavar='what', default='', help='List specific table contents. See help message to learn what can be listed.')
    mod.add_argument('-x', '--extract', metavar='what', default='', help='Extract data from MSI. For what can be extracted, refer to help message.')

    spec = opts.add_argument_group('Analysis Specific options')
    spec.add_argument('-i', '--record', metavar='number|name', type=str, default=-1, help='Can be a number or name. In --list mode, specifies which record to dump/display entirely. In --extract mode dumps only this particular record to --outdir')
    spec.add_argument('-O', '--outdir', metavar='path', default='', help='When --extract mode is used, specifies output location where to extract data.')
    spec.add_argument('-y', '--yara', metavar='path', default='', help='Path to YARA rule/directory with rules. YARA will be matched against Binary data, streams and inner files')

    args = opts.parse_args()
    options.update(vars(args))

    logger = Logger(options)

    if len(args.list) > 0:
        if args.list.lower() not in [x.lower() for x in MSIDumper.ListModes + MSIDumper.KnownTables]:
            logger.err(f'WARNING: Requested {args.list} table is not recognized: parser will probably crash!')

    args.infile = os.path.abspath(os.path.normpath(args.infile))

    if not os.path.isfile(args.infile) and not os.path.isdir(args.infile):
        logger.fatal(f'--infile does not exist!')

    exclusive = sum([len(args.list) > 0, len(args.extract) > 0])
    if exclusive > 1:
        logger.fatal(f'--list and --extract are mutually exclusive options. Pick one.')

    if len(args.extract) > 0 and len(args.outdir) == 0:
        logger.fatal('-O/--outdir telling where to extract files to is required when working in --extract mode.')

    options.update(vars(args))
    return args

@atexit.register
def goodbye():
    try:
        colorama.deinit()
    except:
        pass

def terminalWidth():
    n = shutil.get_terminal_size((80, 20))  # pass fallback
    return n.columns

def banner():
    print(f'''
                   _     _                       
     _ __ ___  ___(_) __| |_   _ _ __ ___  _ __  
    | '_ ` _ \/ __| |/ _` | | | | '_ ` _ \| '_ \ 
    | | | | | \__ \ | (_| | |_| | | | | | | |_) |
    |_| |_| |_|___/_|\__,_|\__,_|_| |_| |_| .__/ 
                                        |_|    
    version: {Logger.colorize(VERSION, "green")}
    author : Mariusz Banach (mgeeky, @mariuszbit)
             <mb [at] binary-offensive.com>
''')

def processFile(args, path):
    msir = MSIDumper(options, logger)

    if not msir.open(path):
        logger.err(f'Could not open database (use -d to learn more): {path}')
        return ''

    report = ''
    if not args.quiet:
        report += f'{Logger.colorize("[+]","green")} Analyzing : {path}\n\n'

    if len(args.list) > 0:
        report += msir.listTable(args.list)

    elif len(args.extract) > 0:
        report += msir.extract(args.extract)

    else:
        rep = msir.analyse()

        if len(args.yara) > 0:
            rep += '\n\n' + msir.yaraScan()

        if not args.quiet:
            report += rep
            report += '\n\n' + msir.verdict.strip() + '\n'
        else:
            verd = msir.verdict.strip()
            pos = verd.find(':')
            if pos != -1:
                verd = verd[pos+1:].strip()

            report += verd + ' : ' + path

    logger.ok(f'Database processed : {path}')
    msir.close()

    return report

def processDir(args, infile):
    report = ''

    logger.verbose(f'Process files from directory: {infile}')

    for file in glob.glob(os.path.join(infile, '**/**'), recursive=True):
        path = os.path.join(infile, file)
        if os.path.isfile(path):
            try:
                report += processFile(args, path)
                report += '\n\n'

            except Exception as e:
                logger.err('Analysis of "{}" failed. Exception: {}'.format(
                    path, str(e)
                ))

    return report

def main():
    global options
    args = getoptions()
    if not args:
        return False

    if not args.quiet:
        banner()

    if len(args.outfile) > 0:
        options['nocolor'] = True

    options['max_width'] = terminalWidth()

    if os.path.isfile(args.infile):
        report = processFile(args, args.infile)

    else:
        report = processDir(args, args.infile)

    if len(args.outfile) > 0:
        with open(args.outfile, 'wb') as f:
            rep = Logger.stripColors(report)
            f.write(rep.encode())
    else:
        print(report)

if __name__ == '__main__':
    main()

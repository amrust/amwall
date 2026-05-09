' amwall — embed an MST language transform into an MSI as a substorage.
' Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
'
' Usage: cscript //nologo embed-transform.vbs <msi> <mst> <lcid>
'
' Inserts the .mst file into the MSI database's _Storages table named by
' the LCID (numeric, e.g. 1031 for de-DE). Combined with set-languages.vbs
' setting the Template summary property to list every embedded LCID,
' Windows Installer auto-applies the matching transform at install time
' based on the user's UI language. See:
' https://learn.microsoft.com/en-us/windows/win32/msi/multiple-language-distribution
'
' Done in VBScript rather than PowerShell because pwsh.EXE 7's COM
' threading model conflicts with WindowsInstaller.Installer; cscript
' has no such issue.

Option Explicit

Const msiOpenDatabaseModeTransact = 1

If WScript.Arguments.Count <> 3 Then
    WScript.StdErr.WriteLine "Usage: embed-transform.vbs <msi> <mst> <lcid>"
    WScript.Quit 1
End If

Dim msiPath, mstPath, lcid
msiPath = WScript.Arguments(0)
mstPath = WScript.Arguments(1)
lcid    = WScript.Arguments(2)

Dim installer, database, view, record
Set installer = CreateObject("WindowsInstaller.Installer")
Set database  = installer.OpenDatabase(msiPath, msiOpenDatabaseModeTransact)
Set view      = database.OpenView("INSERT INTO `_Storages` (`Name`, `Data`) VALUES (?, ?)")

Set record = installer.CreateRecord(2)
record.StringData(1) = lcid
record.SetStream 2, mstPath

view.Execute record
view.Close
database.Commit

WScript.Echo "Embedded " & mstPath & " as transform " & lcid

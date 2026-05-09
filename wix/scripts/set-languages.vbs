' amwall — overwrite an MSI's Template summary property with a list of LCIDs.
' Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
'
' Usage: cscript //nologo set-languages.vbs <msi> <lcid-csv>
'
'   <lcid-csv> example: "1033,1031,1036,1041,2052"
'
' The Template summary property has the form "<platform>;<lcid-csv>".
' Listing every LCID whose .mst transform was embedded by
' embed-transform.vbs is what makes Windows Installer treat the package
' as multilingual and auto-apply the matching transform at install time.
'
' Property index 7 is PID_TEMPLATE per the Windows Installer SDK.
' Done in VBScript for the same threading reason as embed-transform.vbs.

Option Explicit

Const msiOpenDatabaseModeTransact = 1
Const PID_TEMPLATE                = 7

If WScript.Arguments.Count <> 2 Then
    WScript.StdErr.WriteLine "Usage: set-languages.vbs <msi> <lcid-csv>"
    WScript.Quit 1
End If

Dim msiPath, lcidsCsv
msiPath  = WScript.Arguments(0)
lcidsCsv = WScript.Arguments(1)

Dim installer, database, sumInfo, template
Set installer = CreateObject("WindowsInstaller.Installer")
Set database  = installer.OpenDatabase(msiPath, msiOpenDatabaseModeTransact)
Set sumInfo   = database.SummaryInformation(20)

template = "Intel;" & lcidsCsv
sumInfo.Property(PID_TEMPLATE) = template
sumInfo.Persist
database.Commit

WScript.Echo "Set Template summary to: " & template

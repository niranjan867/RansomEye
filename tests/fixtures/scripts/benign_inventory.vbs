' Lists files in a folder. No execution, no network.
Dim fso, folder, f
Set fso = CreateObject("Scripting.FileSystemObject")
Set folder = fso.GetFolder("C:\Reports")
For Each f In folder.Files
    WScript.Echo f.Name
Next

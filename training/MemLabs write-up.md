# Lab 1
Start with windows.pslist and windows.cmdline, I've found mspaint.exe, Winrar with a file named "Important.rar"
For the mspaint.exe, I dumped out the whole process from the memory for investigation with windows.memmap, and change the extension from .dmp to .data to open it with GIMP
```
>python3 vol.py -f ~/Lab1.raw windows.memmap.Memmap --pid 2424 --dump
>cp pid.2424.dmp pid.2424.data
```
Gotta play with the offset, width and height a lil' bit to get the flag
>flag{G00d_BoY_good_girL}

Back to the Important.rar, just dump the file out, open it up and we need the password. The comment in the rar file said password is the NTLM hash of the user, then let's dump the hash out
```
>python3 vol.py -f ~/Lab1.raw windows.hashdump
Volatility 3 Framework 2.5.2
Progress:  100.00               PDB scanning finished                        
User    rid     lmhash  nthash

Administrator   500     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
Guest   501     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
SmartNet        1001    aad3b435b51404eeaad3b435b51404ee        4943abb39473a6f32c11301f4987e7e0
HomeGroupUser$  1002    aad3b435b51404eeaad3b435b51404ee        f0fc3d257814e08fea06e63c5762ebd5
Alissa Simpson  1003    aad3b435b51404eeaad3b435b51404ee        f4ff64c8baac57d22f22edc681055ba6
```
The hash we need is `F4FF64C8BAAC57D22F22EDC681055BA6`, open the rar file and we got the flag
>flag{w3ll_3rd_stage_was_easy}

Ok so where is the first flag?
Back to windows.pslist, I found the cmd.exe running which is kinda sussy, so I dump out the process to inspect
```
>python3 vol.py -f ~/Lab1.raw windows.pslist.PsList --pid 1984 --dump
>strings -a -el 1984.cmd.exe.0x4a9d0000.dmp > cmd.txt
```
And found a base64-type string `mxhZ3t0aDFzXzFzX3RoM18xc3Rfc3Q0ZzMhIX0=` Decode it and we got the first flag
>flag{th1s_1s_th3_1st_st4g3!!}
# Lab 2
As the description said: "He is supposedly a very popular "environmental" activist", I went straight for the windows.envars plugin to inspect and found a weird looking string
```
>python3 vol.py -f ~/Lab2.dmp windows.envars
3852    conhost.exe     0x131970        NEW_TMP C:\Windows\ZmxhZ3t3M2xjMG0zX1QwXyRUNGczXyFfT2ZfTDRCXzJ9
```
Use base64 decode the string and we got the flag
>flag{w3lc0m3_T0_$T4g3_!_Of_L4B_2}

"he told us that his go to applications are browsers, his password managers"
Now I went for the windows.pslist and found Chrome and Keepass running. I also checked windows.cmdline and found
```
3008    KeePass.exe     "C:\Program Files (x86)\KeePass Password Safe 2\KeePass.exe" "C:\Users\SmartNet\Secrets\Hidden.kdbx"
```
Dump the Hidden.kdbx file out and open it using KeePass, but I still need the password for it, I tried filescan and grep to see if I can find anything related
```
>python3 vol.py -f ~/Lab2.raw windows.filescan | grep -i "password"
0x3e868370 100.0\Program Files (x86)\KeePass Password Safe 2\KeePass.exe.config 216
0x3e873070      \Program Files (x86)\KeePass Password Safe 2\KeePass.exe        216
0x3e8ef2d0      \Program Files (x86)\KeePass Password Safe 2\KeePass.exe        216
0x3e8f0360      \Program Files (x86)\KeePass Password Safe 2\KeePass.XmlSerializers.dll 216
0x3eaf7880      \Program Files (x86)\KeePass Password Safe 2\KeePass.XmlSerializers.dll 216
0x3fb0abc0      \Program Files (x86)\KeePass Password Safe 2\KeePassLibC64.dll  216
0x3fce1c70      \Users\Alissa Simpson\Pictures\Password.png     216
0x3fd62f20      \Program Files (x86)\KeePass Password Safe 2\KeePass.config.xml 216
0x3fecf820      \Program Files (x86)\KeePass Password Safe 2\unins000.exe       216
```
The Password.png looks interesting, let's dump it out, and we got the password for KeePass file `P4SSw0rd_123`. Open it up and search for the flag, and it was in the Recycle Bin
>flag{w0w_th1s_1s_Th3_SeC0nD_ST4g3_!!}

Back to Chrome, let's dump the History out to inspect
```
>python3 vol.py -f ~/Lab2.raw windows.filescan | grep -i "Chrome" | grep -i "History"
0x3fa3e430 100.0\Users\SmartNet\AppData\Local\Google\Chrome\User Data\Default\History-journal   216
0x3fcfb1d0(This one)\Users\SmartNet\AppData\Local\Google\Chrome\User Data\Default\History   216
0x3fd4a670      \Users\SmartNet\AppData\Local\Google\Chrome\User Data\Default\History-journal   216
```
There's a Mega link, downloaded the Important.zip file, the password is the SHA1 of stage3 flag in lab1 in lowercase, open it up and we got the flag
>flag{oK_So_Now_St4g3_3_is_DoNE!!}
# Lab 3
Using windows.cmdline I've found 2 interesting files named "evilscript.py" and "vip.txt" on the Desktop, then used windows.filescan to find the offset to dump out these files
```
>python3 vol.py -f ~/Lab3.raw windows.filescan | grep "Desktop"
0x4f34148  100.0\Users\hello\Desktop\suspision1.jpeg    128
0xbe20b10       \Users\hello\Desktop    128
0x24d2f530      \ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Remote Desktop Connection.lnk    128
0x2dbda760      \ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\System Tools\Desktop.ini 128
0x385d3958      \Users\hello\Desktop\OSForensics.lnk    128
0x3d095ae8      \Users\Public\Desktop\desktop.ini       128
0x3d0a7f80      \ProgramData\Microsoft\Windows\Start Menu\Programs\Games\Desktop.ini    128
0x3d0a8038      \Users\hello\Links\Desktop.lnk  128
0x3d0f2b30      \Users\hello\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Maintenance\Desktop.ini      128
0x3d3c0f80      \Users\hello\Desktop\DumpIt\HELLO-PC-20180930-094543.raw        128
0x3d445650      \Users\hello\AppData\Roaming\Microsoft\Windows\SendTo\Desktop.ini       128
0x3d46c3c8      \Users\hello\Desktop    128
0x3d481788      \Users\hello\Desktop\DumpIt     128
0x3d489c90      \Users\hello\Desktop\DumpIt\DumpIt.exe  128
0x3d4c0138      \Users\hello\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessories\Desktop.ini      128
0x3d7d9dd0      \ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Desktop.ini      128
0x3da48f80      \Users\hello\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessories\System Tools\Desktop.ini 128
0x3da7f038      \Users\hello\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessories\Accessibility\Desktop.ini        128
0x3dad65a8      \Users\Public\Desktop   128
0x3dcf3f18      \Users\hello\Desktop\DumpIt\DumpIt.exe  128
0x3de1b5f0      \Users\hello\Desktop\evilscript.py.py   128
0x3de41d00      \Users\hello\Desktop\desktop.ini        128
0x3de646e0      \Users\hello\Desktop    128
0x3deffef0      \ProgramData\Microsoft\Windows\Start Menu\Programs\Maintenance\Desktop.ini      128
0x3df96eb0      \Users\Public\Desktop   128
0x3dfaa828      \ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Accessibility\Desktop.ini        128
0x3e1e9360      \Users\hello\Desktop    128
0x3e727e50      \Users\hello\Desktop\vip.txt    128
```
I even found another sussy file named "suspision1.jpeg" :D
Let's dump all those file out to investigate
First is the "evilscript.py"
```
import sys
import string

def xor(s):

	a = ''.join(chr(ord(i)^3) for i in s)
	return a


def encoder(x):
	
	return x.encode("base64")


if __name__ == "__main__":

	f = open("C:\\Users\\hello\\Desktop\\vip.txt", "w")

	arr = sys.argv[1]

	arr = encoder(xor(arr))

	f.write(arr)

	f.close()
```
The script is quite easy to read, it takes the content, xor it with 3, and encode it to base64 and write it to "vip.txt", so to decode it we just need to reverse the process. Here I used CyberChef to cook it a lil' bit and got the first half of the flag
>inctf{0n3_h4lf

Back to the suspision1.jpeg, as the description said we need steghide, and need first half to solve the other, so I assumed that the first half is the passphrase, to extract the content from the jpeg file. And we got the other half
>_1s_n0t_3n0ugh}

And the full flag
>inctf{0n3_h4lf_1s_n0t_3n0ugh}
# Lab 4
Spent quite much time on this one to read some documents and tried to install Volatility2 with python2 and pyenv (I'm more familiar with Volatility3 but seems like Volatility2 has more useful plugins)
The key is to find the deleted content on Windows, the OS that installs on NTFS formatted drive, we need the 'mftparser' plugin on Volatility2.
>python2 vol.py -f ~/Lab4.raw --profile=Win7SP1x64 mftparser > mft_output.txt
```
MFT entry found at offset 0x3bd8ac00
Attribute: In Use & File
Record Number: 60583
Link count: 2


$STANDARD_INFORMATION
Creation                       Modified                       MFT Altered                    Access Date                    Type
------------------------------ ------------------------------ ------------------------------ ------------------------------ ----
2019-06-27 13:14:13 UTC+0000 2019-06-27 13:26:12 UTC+0000   2019-06-27 13:26:12 UTC+0000   2019-06-27 13:14:13 UTC+0000   Archive

$FILE_NAME
Creation                       Modified                       MFT Altered                    Access Date                    Name/Path
------------------------------ ------------------------------ ------------------------------ ------------------------------ ---------
2019-06-27 13:14:13 UTC+0000 2019-06-27 13:14:13 UTC+0000   2019-06-27 13:14:13 UTC+0000   2019-06-27 13:14:13 UTC+0000   Users\SlimShady\Desktop\IMPORT~1.TXT

$FILE_NAME
Creation                       Modified                       MFT Altered                    Access Date                    Name/Path
------------------------------ ------------------------------ ------------------------------ ------------------------------ ---------
2019-06-27 13:14:13 UTC+0000 2019-06-27 13:14:13 UTC+0000   2019-06-27 13:14:13 UTC+0000   2019-06-27 13:14:13 UTC+0000   Users\SlimShady\Desktop\Important.txt

$OBJECT_ID
Object ID: 7726a550-d498-e911-9cc1-0800275e72bc
Birth Volume ID: 80000000-b800-0000-0000-180000000100
Birth Object ID: 99000000-1800-0000-690d-0a0d0a0d0a6e
Birth Domain ID: 0d0a0d0a-0d0a-6374-0d0a-0d0a0d0a0d0a

$DATA
0000000000: 69 0d 0a 0d 0a 0d 0a 6e 0d 0a 0d 0a 0d 0a 63 74   i......n......ct
0000000010: 0d 0a 0d 0a 0d 0a 0d 0a 66 7b 31 0d 0a 0d 0a 0d   ........f{1.....
0000000020: 0a 5f 69 73 0d 0a 0d 0a 0d 0a 5f 6e 30 74 0d 0a   ._is......_n0t..
0000000030: 0d 0a 0d 0a 0d 0a 5f 45 51 75 34 6c 0d 0a 0d 0a   ......_EQu4l....
0000000040: 0d 0a 0d 0a 5f 37 6f 5f 32 5f 62 55 74 0d 0a 0d   ...._7o_2_bUt...
0000000050: 0a 0d 0a 0d 0a 0d 0a 0d 0a 0d 0a 5f 74 68 31 73   ..........._th1s
0000000060: 5f 64 30 73 33 6e 74 0d 0a 0d 0a 0d 0a 0d 0a 5f   _d0s3nt........_
0000000070: 6d 34 6b 65 0d 0a 0d 0a 0d 0a 5f 73 33 6e 0d 0a   m4ke......_s3n..
0000000080: 0d 0a 0d 0a 0d 0a 73 33 7d 0d 0a 0d 0a 47 6f 6f   ......s3}....Goo
0000000090: 64 20 77 6f 72 6b 20 3a 50                        d.work.:P
```
>inctf{1_is_n0t_EQu4l_7o_2_bUt_th1s_d0s3nt_m4ke_s3ns3}
# Lab 5
Notes:
 - "strange files being accessed"
 - "The names were not readable. They were composed of alphabets and numbers but I wasn't able to make out what exactly it was."
 - 3 flags
 - "There was a small mistake when making this challenge. If you find any string which has the string "L4B_3_D0n3!!" in it, please change it to "L4B_5_D0n3!!" and then proceed."
 - "You'll get the stage 2 flag only when you have the stage 1 flag."

Solution:
I've used both volatility2 and volatility3 for this lab. Profile for the memdump was the same as previous labs "Win7SP1x64".
As always, I started with windows.pslist and windows.cmdline (vol3). Serveral NOTEPADS.EXE processes was running made me suspect but I will leave it for later.
What looks interesting for me now is the "SW1wb3J0YW50.rar" appeared when i used windows.cmdline. So I used windows.filescan to find the offset and  windows.dumpfiles dump the file out
```
>python3 vol.py -f ~/Lab5.raw windows.filescan | grep "SW1wb3J0YW50"
0x3eed56f0 100.0\Users\SmartNet\Documents\SW1wb3J0YW50.rar      216
>python3 vol.py -f ~/Lab5.raw windows.dumpfiles --physaddr 0x3eed56f0
Volatility 3 Framework 2.5.2
Progress:  100.00               PDB scanning finished                        
Cache   FileObject      FileName        Result

DataSectionObject       0x3eed56f0      SW1wb3J0YW50.rar        file.0x3eed56f0.0xfa80010b44f0.DataSectionObject.SW1wb3J0YW50.rar.dat
```
The file contains "Stage2.png", and... the file is password protected. I guess we gotta find the Stage1 flag and use it as the password.
After wandering around the documents, i went for iehistory plugin in vol2 and found a weird looking string "ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfM19EMG4zXyEhfQ"
```
Process: 1396 explorer.exe
Cache type "URL " at 0x28c5900
Record length: 0x100
Location: Visited: Alissa Simpson@file:///C:/Users/Alissa%20Simpson/Pictures/ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfM19EMG4zXyEhfQ.bmp
Last modified: 2019-12-19 08:35:18 UTC+0000
Last accessed: 2019-12-19 08:35:18 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xec
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x28c5a00
Record length: 0x100
Location: Visited: Alissa Simpson@file:///C:/Users/Alissa%20Simpson/Pictures/ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfNV9EMG4zXyEhfQ.bmp
Last modified: 2019-12-20 03:46:09 UTC+0000
Last accessed: 2019-12-20 03:46:09 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xec
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x28c5b00
Record length: 0x100
Location: Visited: Alissa Simpson@file:///C:/Users/SmartNet/SW1wb3J0YW50.rar
Last modified: 2019-12-19 08:36:16 UTC+0000
Last accessed: 2019-12-19 08:36:16 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xac
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x28c5c00
Record length: 0x100
Location: Visited: Alissa Simpson@file:///C:/Windows/AppPatch/ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfNV9EMG4zXyEhfQ.bmp
Last modified: 2019-12-20 03:46:37 UTC+0000
Last accessed: 2019-12-20 03:46:37 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xdc
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x2955000
Record length: 0x100
Location: :2019122020191221: Alissa Simpson@file:///C:/Windows/AppPatch/ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfNV9EMG4zXyEhfQ.bmp
Last modified: 2019-12-20 09:16:37 UTC+0000
Last accessed: 2019-12-20 03:46:37 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0x0
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x2955100
Record length: 0x100
Location: :2019122020191221: Alissa Simpson@:Host: Computer
Last modified: 2019-12-20 09:14:56 UTC+0000
Last accessed: 2019-12-20 03:44:56 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0x0
**************************************************
Process: 1396 explorer.exe
Cache type "URL " at 0x2955200
Record length: 0x100
Location: :2019122020191221: Alissa Simpson@file:///C:/Users/Alissa%20Simpson/Pictures/ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfNV9EMG4zXyEhfQ.bmp
Last modified: 2019-12-20 09:16:09 UTC+0000
Last accessed: 2019-12-20 03:46:09 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0x0
**************************************************
Process: 1396 explorer.exe
Cache type "DEST" at 0x635910f
Last modified: 2019-12-20 09:16:37 UTC+0000
Last accessed: 2019-12-20 03:46:38 UTC+0000
URL: Alissa Simpson@file:///C:/Windows/AppPatch/ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfNV9EMG4zXyEhfQ.bmp
```
It does looks like a base64 string so i decoded it and got the flag
> flag{!!_w3LL_d0n3_St4g3-1_0f_L4B_3_D0n3_!!} //author mistake
> flag{!!_w3LL_d0n3_St4g3-1_0f_L4B_5_D0n3_!!} //fixed

and used that flag to open Stage2.png and got the 2nd flag
> flag{W1th_th1s_$taGe_2_1s_c0mPL3T3_!!}

Now back to the NOTEPAD.EXE, in the windows.cmdline console, that process doesn't looks like a normal notepad.exe of windows but rather an other "kind" of application
```
2744    notepad.exe     "C:\Windows\system32\notepad.exe" //normal one
2724    NOTEPAD.EXE     "C:\Users\SmartNet\Videos\NOTEPAD.EXE" 
2632    svchost.exe     C:\Windows\System32\svchost.exe -k WerSvcGroup
2716    WerFault.exe    C:\Windows\SysWOW64\WerFault.exe -u -p 2724 -s 156
1388    NOTEPAD.EXE     Required memory at 0x7efdf020 is not valid (process exited?)
780     WerFault.exe    C:\Windows\SysWOW64\WerFault.exe -u -p 1388 -s 156
2056    NOTEPAD.EXE     Required memory at 0x7efdf020 is inaccessible (swapped)
2168    WerFault.exe    Required memory at 0x7efdf020 is not valid (process exited?)
```
So I used windows.filescan to find the location and windows.dumpfile to dump that file out to analyse.
```
>python3 vol.py -f ~/Lab5.raw windows.filescan | grep "NOTEPAD"      
0x3ee9d070 100.0\Users\SmartNet\Videos\NOTEPAD.EXE      216
0x3fca5250      \Users\SmartNet\Videos\NOTEPAD.EXE      216

>python3 vol.py -f ~/Lab5.raw windows.dumpfiles --physaddr 0x3ee9d070
Volatility 3 Framework 2.5.2
Progress:  100.00               PDB scanning finished                        
Cache   FileObject      FileName        Result

DataSectionObject       0x3ee9d070      NOTEPAD.EXE     file.0x3ee9d070.0xfa8000f886e0.DataSectionObject.NOTEPAD.EXE.dat
ImageSectionObject      0x3ee9d070      NOTEPAD.EXE     file.0x3ee9d070.0xfa80021a1600.ImageSectionObject.NOTEPAD.EXE.img
SharedCacheMap  0x3ee9d070      NOTEPAD.EXE     file.0x3ee9d070.0xfa8001086b20.SharedCacheMap.NOTEPAD.EXE.vacb

>python3 vol.py -f ~/Lab5.raw windows.dumpfiles --physaddr 0x3fca5250
Volatility 3 Framework 2.5.2
Progress:  100.00               PDB scanning finished                        
Cache   FileObject      FileName        Result

DataSectionObject       0x3fca5250      NOTEPAD.EXE     file.0x3fca5250.0xfa8000f886e0.DataSectionObject.NOTEPAD.EXE.dat
ImageSectionObject      0x3fca5250      NOTEPAD.EXE     file.0x3fca5250.0xfa80021a1600.ImageSectionObject.NOTEPAD.EXE.img
SharedCacheMap  0x3fca5250      NOTEPAD.EXE     file.0x3fca5250.0xfa8001086b20.SharedCacheMap.NOTEPAD.EXE.vacb
```
*I dumped both NOTEPAD.EXE found but only inspect the first one and found the flag, maybe both are the same*
Using IDA to analyse the NOTEPAD.EXE, I've found the 3rd flag
```
loc_1007461:
call    sub_10075DD
push    offset Last     ; Last
push    offset First    ; First
call    _initterm
mov     eax, dword_1009AB0
mov     [ebp+var_24], eax
lea     eax, [ebp+var_24]
push    eax
push    dword_1009AAC
lea     eax, [ebp+var_2C]
push    eax
lea     eax, [ebp+var_30]
push    eax
lea     eax, [ebp+var_34]
push    eax
call    ds:__getmainargs
mov     [ebp+var_38], eax
push    offset dword_1009008 ; Last
push    offset dword_1009000 ; First
call    _initterm
add     esp, 24h
mov     eax, ds:_acmdln
mov     esi, [eax]
mov     [ebp+var_20], esi
cmp     byte ptr [esi], 22h ; '"'
mov     eax, 62h ; 'b'
push    eax
mov     eax, 69h ; 'i'
push    eax
mov     eax, 30h ; '0'
push    eax
mov     eax, 73h ; 's'
push    eax
mov     ebx, 7Bh ; '{'
push    ebx
mov     ecx, 4Dh ; 'M'
push    ecx
mov     ebx, 33h ; '3'
push    ebx
mov     eax, 6Dh ; 'm'
push    eax
mov     eax, 5Fh ; '_'
push    eax
mov     eax, 6Ch ; 'l'
push    eax
mov     eax, 34h ; '4'
push    eax
mov     eax, 42h ; 'B'
push    eax
mov     eax, 35h ; '5'
push    eax
mov     eax, 5Fh ; '_'
push    eax
mov     eax, 4Fh ; 'O'
push    eax
mov     eax, 56h ; 'V'
push    eax
mov     eax, 65h ; 'e'
push    eax
mov     ebx, 52h ; 'R'
push    ebx

loc_1007527:
mov     eax, 5Fh ; '_'
push    eax
mov     eax, 21h ; '!'
push    eax
mov     eax, 7Dh ; '}'
push    eax
jnz     short near ptr loc_1007574+1
```
> bi0s{M3m_l4B5_OVeR}
# Lab 6
Start off with windows.pslist and windows.cmdline, I found 3 interesting proccesses: Chrome, Firefox and Winrar with the file named "flag.rar"
Dumped the flag.rar file out, inside is a flag2.png but it is password protected, I will leave it for later
Back to chrome, i went straight for Chrome history and found an sussy pastebin link https://pastebin.com/RSGSi1hk
```
https://www.google.com/url?q=https://docs.google.com/document/d/1lptcksPt1l_w7Y29V4o6vkEnHToAPqiCkgNNZfS9rCk/edit?usp%3Dsharing&sa=D&source=hangouts&ust=1566208765722000&usg=AFQjCNHXd6Ck6F22MNQEsxdZo21JayPKug
 
 
But David sent the key in mail.
 
The key is... :(
```
The link given leads to a Google Docs page, mostly demo text, and a mega drive link on page 4, opened it up and... it is locked (of course)
Went back to Firefox to find any infomation related, but found nothing. I have no idea what to look at, so I went for the ultimate spell: strings and grep
> strings ~/Lab6.raw | grep -i "david" | grep -i "key"

And I did find what I need :D
> "THE KEY IS zyWxCjCYYSEMA-hZe552qWVXiPwa5TecODbjnsscMIU"

Went back to unlock the mega drive, downloaded the file named "flag_
.png" and... it was corrupted. Using this [tool](https://www.nayuki.io/page/png-file-chunk-inspector) I found that the IHDR was iHDR, opened the hex editor and change the byte from 69 to 49 and we got the first half of the flag.
>inctf{thi5_cH4LL3Ng3_!s_g0nn4_b3_?_

Now back to the rar file, I used vol2 with the consoles plugin to find what commands he has typed in
> python2 vol.py -f ~/Lab6.raw --profile=Win7SP1x64 consoles

Ok so he typed in "env", so I inspect the memdump again with vol3 and the windows.envars plugin, and found the rar files password
> 2940    chrome.exe      0x371f90        RAR password    easypeasyvirus

Open the flag2.png file and we got the 2nd half of the flag
>aN_Am4zINg_!_i_gU3Ss???_}

And the full flag is
> inctf{thi5_cH4LL3Ng3_!s_g0nn4_b3_?_aN_Am4zINg_!_i_gU3Ss???_}
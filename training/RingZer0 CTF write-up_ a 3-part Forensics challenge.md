Start up finding the right profile to use in Volatility2. The Win7SP1x86 profile worked for me throughout the challenge. I also renamed the file to 'ringo' to make it easier to work with.

# 1 / 3 Do not waste the environment
From the title of the challenge, I believe it's a hint so I tried using the *envars* plugin to find the flag.
```
python2 vol.py -f ~/ringo --profile=Win7SP1x86 envars
```
![image](https://hackmd.io/_uploads/S1cUvkTo6.png)

And we got the flag
> Flag-66d7724d872da91af56907aea0f6bfb8

# 2 / 3 Did you see my desktop?
Here I used the *screenshot* plugin to check if there was anything interesting there and I found the flag on the screen.
```
python2 vol.py -f ringo --profile=Win7SP1x86 screenshot --dump-dir= ~/
```
![session_1.WinSta0.Default](https://hackmd.io/_uploads/HyClD1aoT.png)
> FLAG-5bd2510a83e82d271b7bf7fa4e0970d1

# 3 / 3 Suspicious account password?
Talking about user account passwords, the thing that popup in my head was the NTLM hashes. Therefore I went for the *hashdump* plugin to easily dump out all user password hashes, and one of the users was named *flag*. Got the hash, tried to crack it and got the flag, quite surprised as the flag wasn't in the same format as first 2 challenges.

![image](https://hackmd.io/_uploads/S1UyPJaia.png)
>admin123
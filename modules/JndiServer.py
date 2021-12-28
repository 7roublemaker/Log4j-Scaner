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
warnings.filterwarnings("ignore")

from modules.log import logErr
# opts, args = getopt.getopt(argv,"hl:k:",["local=", "help", "keyword="])
helper = '''
Jndi Options:
    -h, --hlep
    \tshow JNDI Server options
    -l <port>, local <port>
    \tUsed local port to start the JNDI
    -k <keyword>, --key <keyword>
    \tThe keyword will be match in the flow of JNDI.
'''

exit_flag = 0

class interrupt(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        while True:
            a = input()
            print(a)
            if a == 'q':
                global exit_flag
                print(exit_flag)
                exit_flag = 1


def LocalLdapServer(port, keyword):
    print("[###] Monitoring the RMI&LDAP Server [###]")
    data_log = b""
    result_log = []
    ldap_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ldap_sock.bind(('0.0.0.0', int(port)))
    ldap_sock.listen(10)
    ldap_sock.settimeout(500)
    #outfilename = time.strftime('result/local-result-%Y%m%d-%H%M.txt')
    #time.sleep(0.5)
    tmp_data2 = []
    while True:
        try:
            #print(" [*] Checking RMI&LDAP Server")
            ldap_data = b'\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00'
            rmi_data = b'\x4e\x00\x0e\x32\x30\x32\x2e\x31\x30\x34\x2e\x31\x33\x36\x2e\x36\x36\x00\x00\x4d\xab'
            client_sock,remote = ldap_sock.accept()
            client_sock.settimeout(1)
            data1 = client_sock.recv(1024)
            if keyword == b'':
                print(" [+] Receive connect from %s:%s." % (remote[0], remote[1]))
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
            if keyword in data2:
                print(" [+] recv from " + str(remote[0]) + ":" + str(remote[1]))
                print(re.findall(b"[\d\w-]*" + keyword + b"[\d\w-]*", data2)[0])
            data_log = data_log + data2
            tmp_data2.append(data2)
            if data2 in tmp_data2:
                # client_sock.close()
                continue
            else:
                if keyword in data2:
                    print(" [+] recv from " + str(remote[0]) + ":" + str(remote[1]))
                    print(re.findall(b"[\d\w-]*" + keyword + b"[\d\w-]*", data2)[0])
                data_log = data_log + data2
                tmp_data2.append(data2)

            # print(b">> " + data_log)
        except Exception as e:
            print(e)
            logErr("[LocalLdapServerError] " + str(e))
            break
    ldap_sock.close()


def server(argv):
    try:
        opts, args = getopt.getopt(argv,"hl:k:",["local=", "help", "keyword="])
        keyword = b""
        if len(opts) < 1:
            raise Exception("No options")
        for opt, arg in opts:
            if opt == "-k" or opt == "--keyword":
                keyword = arg.encode()
            elif opt == "-l" or opt == "--local":
                local = 1
                ldap_port = arg
                if re.findall("[^\d]", ldap_port):
                    raise Exception("Error format of ldap server.")
            elif opt == "-h" or opt == "--help":
                print(helper)
    except Exception as e:
        print(e)
        logErr(" [GetArgsError] " + str(e))
        exit()
    print("[+] LDAP Server run in 0.0.0.0:%s"%( ldap_port))
    LocalLdapServer(int(ldap_port), keyword)
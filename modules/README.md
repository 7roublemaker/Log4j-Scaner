# log.py
## def logErr(msg)
`The method to record the error information of the running process. And it will be write to the log folder. `
**Input**
|Parameter|Type|Necessary|Declaration|
|:--:|:--:|:--:|--|
|msg|\<string\>|Y|The error message of very method of class. |

**Output**
|Type|Declaration|
|:--:|:--:|
|None|None |

# scan.py
##  def scan(argv)
`The main method of scan module. It containers some thread and multiprocessing method.`
**Input**
|Parameter|Type|Necessary|Declaration|
|:--:|:--:|:--:|------|
|argv|\<list\>|Y|The args which was filtering by `run.py`. |

**Output**
|Type|Declaration|
|:--:|:--:|
|None|None |

## GeneratePayloadId(url)
`The function is to generate the unique id of very url.`

**Input**
|Parameter|Type|Necessary|Declaration|
|:--:|:--:|:--:|:--|
|url|string|Y|Generate the id by very url. |

**Output**
|Type|Declaration|
|:--:|:--:|
|\<string\>|The id of input url. |

##  def CheckDnslog()
`The funtion is to check the DNSLog record. And it will return the record message when the monitoring id was found in the DNSLog record.`

**Input**
|Parameter|Type|Necessary|Declaration|
|:--:|:--:|:--:|:--|
|None|None|None|None|

**Output**
|Type|Declaration|
|:--:|:--:|
|\<string\>/None|The result of DNSLog record.|

##  def CheckDnsLogWithTenSecond(payload_ids)
`The funtion is to handle the result of `**`CheckDnslog()`**`.`

**Input**
|Parameter|Type|Necessary|Declaration|
|:--:|:--:|:--:|------|
|payload_ids|\<string\>|Y|The payload url id to monitor. |

**Output**
|Type|Declaration|
|:--:|:--:|
|None|None|

##  def LocalJndiServer(ip, port, payload_ids)
`The method will set up a socket listener to receive the jndi request.And it will print the result on console while record the url and payload_ids to result files.`

**Input**
|Parameter|Type|Necessary|Declaration|
|:--:|:--:|:--:|------|
|ip|\<string\>|Y|The public ip of local host. |
|port|\<int\>|Y|The listener port of local host. |
|payload_ids|\<string\>|Y|The payload_url_id to monitor. |

**Output**
|Type|Declaration|
|:--:|:--:|
|None|None|

##  def MatchWaf(response_text)
`Matching the waf keyword from response.`

**Input**
|Parameter|Type|Necessary|Declaration|
|:--:|:--:|:--:|------|
|response_text|\<string\>|Y|The reponse of http request. |

**Output**
|Type|Declaration|
|:--:|:--:|
|BOOL|The result of keyword matching|

##  def VerifyWaf(target)
`The method will send all payloads in the tools to verify the effectiveness of WAF.And it will print the result of each payload.`

**Input**
|Parameter|Type|Necessary|Declaration|
|:--:|:--:|:--:|------|
|target|\<string\>|Y|The target to verify with the fromat of domain or url. |

**Output**
|Type|Declaration|
|:--:|:--:|
|None|None|

##  class Log4j
`The class of scanner realize some methods to send the payload to target with different site in http like header, uri and so on.`

***def CheckCookie(url, payload, showWAF)***
`Check the vulnerability in http header with cookie parameter.`
**Input**
|Parameter|Type|Necessary|Declaration|
|:--:|:--:|:--:|------|
|url|\<string\>|Y|The target to send http request. |
|payload|\<string\>|Y|The payload to send. |
|showWAF|\<int\>|Y|The optional to show waf rejecting information. |

**Output**
|Type|Declaration|
|:--:|:--:|
|\<int\>|The result of running the method.|

***def CheckUserAgent(url, payload, showWAF)***
`Check the vulnerability in http header with User--Agent parameter.`
**Input**
|Parameter|Type|Necessary|Declaration|
|:--:|:--:|:--:|------|
|url|\<string\>|Y|The target to send http request. |
|payload|\<string\>|Y|The payload to send. |
|showWAF|\<int\>|Y|The optional to show waf rejecting information. |

**Output**
|Type|Declaration|
|:--:|:--:|
|\<int\>|The result of running the method.|

***CheckHeader(url, payload_id, basePayload, showWAF, encode_mode=0)***
`Check the vulnerability with the rest of http header parameters.`
**Input**
|Parameter|Type|Necessary|Declaration|
|:--:|:--:|:--:|------|
|url|\<string\>|Y|The target to send http request. |
|payload_id|\<string\>|Y|The url id . |
|basePayload|\<string\>|Y|The bease payload which will be inserted with some payload and url tag in the mehtod. |
|showWAF|\<int\>|Y|The optional to show waf rejecting information. |
|encode_mode|\<string\>|N|The optional mode of url encode. |

**Output**
|Type|Declaration|
|:--:|:--:|
|\<int\>|The result of running the method.|

***def CheckUri(url, payload, showWAF)***
`Check the vulnerability with http uri.`
**Input**
|Parameter|Type|Necessary|Declaration|
|:--:|:--:|:--:|------|
|url|\<string\>|Y|The target to send http request. |
|payload|\<string\>|Y|The payload to send. |
|showWAF|\<int\>|Y|The optional to show waf rejecting information. |

**Output**
|Type|Declaration|
|:--:|:--:|
|\<int\>|The result of running the method.|

***def CheckPOST(url, payload, showWAF, encode_mode=0)***
`Check the vulnerability with http post data.`
**Input**
|Parameter|Type|Necessary|Declaration|
|:--:|:--:|:--:|------|
|url|\<string\>|Y|The target to send http request. |
|payload|\<string\>|Y|The payload to send. |
|showWAF|\<int\>|Y|The optional to show waf rejecting information. |
|encode_mode|\<string\>|N|The optional mode of url encode. |

**Output**
|Type|Declaration|
|:--:|:--:|
|\<int\>|The result of running the method.|

***def CheckPOST(url, payload, showWAF, encode_mode=0)***
`Check the vulnerability with parameter data of the http get method.`
**Input**
|Parameter|Type|Necessary|Declaration|
|:--:|:--:|:--:|------|
|url|\<string\>|Y|The target to send http request. |
|payload|\<string\>|Y|The payload to send. |
|showWAF|\<int\>|Y|The optional to show waf rejecting information. |

**Output**
|Type|Declaration|
|:--:|:--:|
|\<int\>|The result of running the method.|

***def checkVul(self, url, showWAF=0)***
`Run all check method of the class.`
**Input**
|Parameter|Type|Necessary|Declaration|
|:--:|:--:|:--:|------|
|url|\<string\>|Y|The target to send http request. |
|showWAF|\<int\>|Y|The optional to show waf rejecting information. |

**Output**
|Type|Declaration|
|:--:|:--:|
|\<int\>|The result of running the method.|

##  class Log4jThread(threading.Thread)
`The class of thread realization.`

***def __init__(self, tmp_queue, id_queue)***
`The thread class init method.`
**Input**
|Parameter|Type|Necessary|Declaration|
|:--:|:--:|:--:|------|
|tmp_queue|\<string\>|Y|The target queue. |
|id_queue|\<string\>|Y|The useless parameter. |

**Output**
|Type|Declaration|
|:--:|:--:|
|None|None|

***def run(self)***
`Run the threading process.`
**Input**
|Parameter|Type|Necessary|Declaration|
|:--:|:--:|:--:|--|
|None|None|None|None |

**Output**
|Type|Declaration|
|:--:|:--:|
|None|None|

##  def t_join(m_count, timeout, tmp_queue)
`The method to monitor and operator the status of thread.`
**Input**
|Parameter|Type|Necessary|Declaration|
|:--:|:--:|:--:|--|
|m_count|\<int>|Y|The num of runing thread, defined with default 20 but it was related with the count of targets. |
|timeout|\<int>|Y|The interval of check the thread status. |
|tmp_queue|\<Queue>|Y|The target queue to monitoring it's size. |

**Output**
|Type|Declaration|
|:--:|:--:|
|None|None|

# JndiServer.py
##  def server(argv)
`The main method of JndiServer module. It containers some the realization of local Jndi server.`
**Input**
|Parameter|Type|Necessary|Declaration|
|:--:|:--:|:--:|------|
|argv|\<list\>|Y|The args which was filtering by `run.py`. |

**Output**
|Type|Declaration|
|:--:|:--:|
|None|None |

##  def LocalJndiServer(port, keyword)
`The method to set up a listener port to receive the jndi request.`
**Input**
|Parameter|Type|Necessary|Declaration|
|:--:|:--:|:--:|----------|
|port|\<int\>|Y|The listener port of local host. |
|keyword|\<string\>|N|The optional parameter. If keyword is None, the method will match all request and print it's ip:port on console. |

**Output**
|Type|Declaration|
|:--:|:--:|
|None|None|

# exploit.py

# proxy.py


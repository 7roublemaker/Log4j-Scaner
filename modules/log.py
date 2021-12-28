import time
import codecs

# error log printer
def logErr(msg):
    LogFilename = time.strftime('log/day%Y_%m_%d.txt')
    logTime = time.strftime('[%Y%m%d-%H:%M:%S] ')
    f = codecs.open(LogFilename, "a+", "utf-8")
    f.write(logTime + msg + '\n')
    f.close()


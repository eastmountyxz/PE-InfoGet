import pefile
import time
import warnings
import datetime
import os,string,shutil,re

#忽略警告
warnings.filterwarnings("ignore")

PEfile_Path = "hello-2.5.exe"

#----------------------------------第一步 解析PE文件-------------------------------
pe = pefile.PE(PEfile_Path, fast_load=True)
print(type(pe))
print(pe)
print(pe.get_imphash())

#显示DOS_HEADER
dh = pe.DOS_HEADER

#显示NT_HEADERS
nh = pe.NT_HEADERS

#显示FILE_HEADER
fh = pe.FILE_HEADER

#显示OPTIONAL_HEADER
oh = pe.OPTIONAL_HEADER

print(type(fh)) #<class 'pefile.Structure'>
print(str(fh))

#----------------------------------第二步 获取UTC时间-------------------------------
#通过正则表达式获取时间
p = re.compile(r'[[](.*?)[]]', re.I|re.S|re.M)   #最小匹配
res = re.findall(p, str(fh))
print(res[1])                                    #第一个值是IMAGE_FILE_HEADER
res_time = res[1].replace(" UTC","")
# Fri Jun 19 10:46:21 2020 UTC

#获取当前时间
t = time.ctime()
print(t,"\n")                                    # Thu Jul 16 20:42:18 2020
utc_time = datetime.datetime.strptime(res_time, '%a %b %d %H:%M:%S %Y')
print("UTC Time:", utc_time)
# 2020-06-19 10:46:21

#----------------------------------第三步 全球时区转换-------------------------------
#http://zh.thetimenow.com/india
#UTC时间比北京时间晚八个小时 故用timedelta方法加上八个小时
china_time = datetime.datetime.strptime(res_time, '%a %b %d %H:%M:%S %Y') + datetime.timedelta(hours=8)
print("China Time:",china_time)

#美国 UTC-5
america_time = datetime.datetime.strptime(res_time, '%a %b %d %H:%M:%S %Y') - datetime.timedelta(hours=5)
print("America Time:",america_time)

#印度 UTC+5
india_time = datetime.datetime.strptime(res_time, '%a %b %d %H:%M:%S %Y') + datetime.timedelta(hours=5)
print("India Time:",india_time)

#澳大利亚 UTC+10
australia_time = datetime.datetime.strptime(res_time, '%a %b %d %H:%M:%S %Y') + datetime.timedelta(hours=10)
print("Australia Time",australia_time)

#俄罗斯 UTC+3
russia_time = datetime.datetime.strptime(res_time, '%a %b %d %H:%M:%S %Y') + datetime.timedelta(hours=3)
print("Russia Time",russia_time)

#英国 UTC+0
england_time = datetime.datetime.strptime(res_time, '%a %b %d %H:%M:%S %Y')
print("England Time",england_time)

#日本 UTC+9
japan_time = datetime.datetime.strptime(res_time, '%a %b %d %H:%M:%S %Y') + datetime.timedelta(hours=9)
print("Japan Time",england_time)

#德国 UTC+1
germany_time = datetime.datetime.strptime(res_time, '%a %b %d %H:%M:%S %Y') + datetime.timedelta(hours=1)
print("Germany Time",germany_time)

#法国 UTC+1
france_time = datetime.datetime.strptime(res_time, '%a %b %d %H:%M:%S %Y') + datetime.timedelta(hours=1)
print("France Time",france_time)

#加拿大 UTC-5
canada_time = datetime.datetime.strptime(res_time, '%a %b %d %H:%M:%S %Y') - datetime.timedelta(hours=5)
print("Canada Time:",canada_time)

#越南 UTC+7 
vietnam_time = datetime.datetime.strptime(res_time, '%a %b %d %H:%M:%S %Y') + datetime.timedelta(hours=7)
print("Vietnam Time:",vietnam_time)

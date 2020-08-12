import os
import binascii

#-----------------------------------定义转换函数-----------------------------------
def str_to_hex(s):
    return r"\x"+r'\x'.join([hex(ord(c)).replace('0x', '') for c in s])

def hex_to_str(s):
    return ''.join([chr(i) for i in [int(b, 16) for b in s.split(r'\x')[1:]]])
    
def str_to_bin(s):
    return ' '.join([bin(ord(c)).replace('0b', '') for c in s])
    
def bin_to_str(s):
    return ''.join([chr(i) for i in [int(b, 2) for b in s.split(' ')]])


#--------------------------------二进制转字节码---------------------------------
fileIn = 'hello-2.5.exe'
fileOut = 'hex-hello'
inp = open(fileIn,'rb')
outp = open(fileOut,'w')

i = 0
for c in inp.read():
    outp.write('\\%#04x' %(c))
    i += 1
    if i >= 16:
        outp.write('\n')
        i = 0
inp.close()
outp.close()
print('二进制换十六进制成功\n')

    
"""
a="abcdefg"
x=str_to_hex(a)
print(x)
print(hex_to_str(x))
"""

#--------------------------------字节码转换字符串--------------------------------
#decode():bytes编码转为str
#encode():str编码转为bytes
f = open('hex-hello', 'r')
outp = open("result-hello.txt",'w', encoding="utf-8")
for n in f.readlines():
    n = n.strip()
    txt = n.replace('\\0x','\\x')
    res = hex_to_str(txt)
    outp.write(res + '\n')
outp.close()
print('十六进制转字符串成功\n')

---
title: 阴阳师：一个非酋的逆向旅程
date: 2017-01-14 12:15:11
tags:
---


## 0x00 前言
为了验证这个游戏到底有没有 SSR

<!-- more -->

## 0x01 前期工作

直接将 `onmyoji_netease_1.0.14.apk` 解压出来观察各个文件，便可以知道阴阳师是使用 `NeoX + Python`。
其中 `lib/armeabi-v7a/libclient.so` 和 `assets/script.npk` 这两个文件，
一个是带着 Python 虚拟机以及加解密相关的 so 文件，一个是加密之后的 Python 文件，
所以我们后期的工作中心也主要放在这两个文件上。

为了能够在后面调试阴阳师，我们需要对阴阳师重打包：

1. 使用 `apktool` 解包
```
apktool d onmyoji_netease_1.0.14.apk
```
2. 修改 `debuggable`      
将 `AndroidManifest.xml` 中的 `debuggable` 修改为 `true`

3. 重打包
```
apktool b onmyoji_netease_1.0.14
```
4. 签名
```
java -jar signapk.jar platform.x509.pem platform.pk8 onmyoji_netease_1.0.14.apk onmyoji_netease_1.0.14_fix.apk
```

## 0x02 Android 调试初试

由于我是第一次进行 Android 调试，所以这里我写得稍微啰嗦一点儿。

1. 关闭SELinux
```
setenforce 0
```

2. 运行 android_server
```
/data/android_server
```

3. 将 android_server 的端口转发到本地
```
adb forward tcp:23946 tcp:23946
```

4. 启动阴阳师
```
am start -D -n  com.netease.onmyoji/com.netease.onmyoji.Launcher
```

5. IDA 远程 Attach
{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/ida_remote_attach.png %}

6. IDA 设置调试选项
{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/ida_debug_option.png %}

7. 将阴阳师的调试端口转发到本地
```
ps | grep netease.onmyoji
adb forward tcp:17178 jdwp:process_pid
```

8. jdb 附加
```
jdb -connect com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=17178
```

由于种种原因，我需要重开很多次阴阳师，所以我就将步骤 7，8 合并成一个 `copy & paste` 的命令
```
for /f "delims=" %i in ('adb shell "set `ps |grep netease.onmyoji`; echo -n $2"') do adb forward tcp:17178 jdwp:%i && jdb -connect com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=17178
```

## 0x03 格式分析

在动态调试前，我们还是先看一下 `assets/script.npk` 的格式。虽然之前逆过网易其他游戏，也知道这文件是什么格式，
不过还是说一下我第一次分析的步骤，我们使用 C32 将其打开：

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/script-format-1.png %}

除了一个 `NXPK` 的 header，也看不出其他信息，我们再看看文件的尾部：

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/script-format-2.png %}

好像也没有什么特别的信息，不过等等，我们把窗口调整一下：

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/script-format-3.png %}

现在就可以很清楚的看到数据中间有一排 `00000000`。我们可以大胆猜测有效数据是由 `00000000` 进行分割，
我们拿一小段数据出来分析：

```
00000000 4C71C6FD ECD60A00 69040000 69040000 3057F779 3057F779
00000000 A9B3CEFD 5CB91F00 AC000000 AC000000 80C1D70C 80C1D70C
00000000 950CD6FD FC7E3500 C4050000 C4050000 21433D9E 21433D9E
00000000 CA1EF8FD D88F2700 FE100000 FE100000 6BB047E4 6BB047E4
00000000 73A33EFE 50614200 A71B0000 A71B0000 4A32F72E 4A32F72E
00000000 A5E959FE C40B0300 0A090000 0A090000 9B7A1F45 9B7A1F45
```
我们会发现：

* 第四排和第五排数据重复，第六排和第七排数据重复，所以有效数据只有四排
* 第二排数据的尾部是由上至下递增的，但是第二排的数据已经大过了文件大小，暂时意义不明
* 第三排数据，存在和 `assets/script.npk` 文件大小相近的数据，但是不存在大于文件大小的数据，猜测第三排的数据和 `assets/script.npk` 文件的 `offset` 相关
* 再看看第四排的数据，第四排的数据都偏小，猜测第四排的数据和文件的 `大小` 相关
* 最后看第五排数据，暂时意义不明

所以到这里我们可以猜测 `assets/script.npk` 的尾部数据是一个索引表，
阴阳师通过 Python 文件名计算出索引表的偏移量，然后再通过表格里面的文件偏移和大小，
获取到对应加密后的 Python 代码。

如果索引表真的存在，那么程序如何确定这个表的起始地址呢，我们找到这个索引表的前部：

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/script-format-4.png %}

可以看到这个表格的起始地址为 `0x00522DE8`，我们在 C32 里面搜索这个地址：

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/script-format-5.png %}

会发现文件起始地址偏移 0x14 处记录了索引表的地址。

总结: 
* `assets/script.npk` 在偏移量 0x14 处记录了索引表的地址
* 索引表每个索引由 `0x00000000` 进行分割
* 索引中的第三排数据是某个 Python 文件在 `assets/script.npk` 的偏移量
* 索引中的第四排数据是某个 Python 文件的大小


## 0x03 动态调试

#### read & open

在文章前面提过，`lib/armeabi-v7a/libclient.so` 和 `assets/script.npk` 这两个是重点文件，
在 `libclient.so` 加载之后，自然要关注一下 `script.npk`。

要想解密 `script.npk`，基本思路还是挺简单的：关注 `script.npk` 读取的数据经过了怎么样的处理。

为了更好的将 `read` 函数中的 fd 与文件名对应，我在 `open` 处下条件断点，并加上下面的判断：

``` python
import idc

if not hasattr(idc, "fd_map"):
    idc.fd_map = {}

filename = GetString(cpu.r0)

if filename and "script.npk" in filename:
    StepUntilRet()
    GetDebuggerEvent(WFNE_SUSP, -1)
    fd = cpu.r0
    continue_process()
    if fd != idaapi.BADADDR:
        print("open: %s fd: %s" % (filename, fd))
        idc.fd_map[fd] = filename
        return True
else:
    print("open: %s" % filename)
    
return False
```

上面的代码主要是将和 `script.npk` 相关的 fd 和文件名关联起来，
方便于在 `read` 调用时区分和 `script.npk` 相关的读取操作。

`read` 函数条件断点代码：

``` python
import idc

if not hasattr(idc, 'fd_map'):
    return

fd = cpu.r0

if fd in idc.fd_map:
    print("reading: %s" % idc.fd_map[fd])
    return True
    
return False
```

下了断点之后，你会发现这并没有什么用，因为调用次数过多，而且是由 Python 代码来负责读取解密，
如果要完整的跟完一次解密过程会特别累，既然是 Python 代码来负责读取解密，
那我们就在 `PyEval_EvalFrameEx` 处下断点来查看是什么文件在进行读取解密，添加如下代码：

``` python
import idc
import idautils

f_code_addr =  idc.Dword(idautils.cpu.r0 + 16)
strobj_addr = (idc.Dword(f_code_addr + 48))

print('eval: ' + idc.GetString(strobj_addr + 20))
```

跑起来：

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/redirect-show.png %}

这个时候我们就发现了一个可疑文件 `redirect.py`，这个 `redirect.py` 是什么时候加载的呢？
如果是从磁盘里读取的话，前面在 `open` 处的 log 会记录下来，
可是 `open` 处的 log 并没有和 `redirect.py` 相关的信息，
所以阴阳师要么用了一种比较奇怪的方式在磁盘内读取了这个文件，导致我们没有记录到，
要么就是在内部直接创建了这个 `redirect` 模块，我们先不要把情况想得太复杂，
还是先查看一下这个 `redirect.py` 模块。

#### Appcall

想要查看 `redirect.py` 模块，我们就需要 [IDA Appcall](https://www.hex-rays.com/products/ida/support/tutorials/debugging_appcall.pdf)
，`Appcall` 可以在调试的过程中，在当前程序执行环境下执行程序内、某个我们指定的函数，
所以使用 `Appcall` 调用 `PyRun_SimpleString` 我们就可以查看 Python 程序当前运行时的内部信息。

在这里，我们查看一下所有已经加载的 Python 模块信息：

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/appcall-command-line.png %}

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/appcall-get-sysmodules-1.png %}

信息太多了，我们只看 `redirect` 模块信息：

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/appcall-get-sysmodules-2.png %}

发现这个 `redirect` 既不是内置模块，也不是 frozen 模块，是一个纯 Python 模块，所以我们要找到什么时候创建了这个模块。

#### 寻找 redirect 的创建点

我们在 `PyImport_ImportModule`、`PyImport_ImportFrozenModule` 处下断点，继续打 log 重新跑一次：

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/import-log-result.png %}

然而并没有 `import redirect`，这个时候我们就只能用土方法，在 `Py_Initialize` 函数执行结束之后，
通过单步跟踪以及不断的使用 `Appcall` 查看 `redirect` 模块是否被创建，
最终确定了创建 `redirect` 模块的函数 `sub_AD109C`，这个函数正在 `Py_Intialize` 调用处的下方：

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/disassemble-1.png %}

我们再仔细看看 `sub_AD109C` 函数的实现：

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/disassemble-2.png %}

到这里我们可以很清楚的看到创建 `redirect` 模块的过程：

* `PyMarshal_ReadObjectFromString` 从程序某处读取 marshal 格式的字符串
* `PyImport_ExecCodeModule` 创建 `redirect` 模块

原来阴阳师是直接用 marshal 格式字符串直接创建一个模块，之前我们还没意识到有 `PyImport_ExecCodeModule` 这么一个函数，
现在我们直接给 `PyMarshal_ReadObjectFromString` 下断点：

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/dump-redirect-marshal-format.png %}

终于拿到了 `redirect.py` 的 marshal 格式字符串了。

## 0x04 查看 redirect 

拿到了 `redirect` 模块 marshal 格式的字符串之后，添加一个 py27 的 header: `\x03\xf3\x0d\x0a\x00\x00\x00\x00`，
然后直接使用 `uncompyle2` 反编译试试看：

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/redirect-uncompyle-error.png %}

oops，报错了，我们看一下这个 pyc 文件内部情况：

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/redirect-info.png %}

常量表，文件名都正常，再看一下 opcode：

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/redirect-dis-error.png %}

又报错了，我们仔细观察一下这些 opcode，会发现这些 opcode 并不是一个正常 Python 文件会产生的 opcode，
153 没有对应 opcode name，`EXTENDED_ARG` 这个 opcode 只有传递参数超过 65535 个的时候才会出现。
所以革命尚未成功，同志任需努力。

## 0x05 opcode 映射关系

看起来阴阳师好像是直接修改 Python opcode 映射关系，也就是原本 opcode 为 1 的时候代表的是 `POP_TOP`，
但是在这里被修改成 `ROT_THREE` 或者其他，想要解密 `redirect.pyc`，就必须拿到修改后的 opcode 映射关系。

想要拿到修改后的 opcode 映射关系，可以选择慢慢看 python 那个巨大的 switch，分析每个 opcode 对应的代码，
不过这样的方法太累人了，我们要换一种更简单的思路：

1. 使用阴阳师的 Python 来获取 一个 python script 的 pyc
2. 使用正常 Python 来获取 一个 python sctipt 的 pyc
3. 对比两个 pyc，拿到部分修改后的 opcode 映射关系，然后重复 1、2 两步直到 opcode 映射关系完整

#### 获取 pyc

想要使用阴阳师的 Python 来执行一段代码，我们就必须在 PC 上交叉编译一个程序来调用 `libclient.so` 中 Python。

代码如下：
``` c
/**
 * arm-linux-androideabi-gcc test.c -o test -ldl -pie
 * export LD_LIBRARY_PATH=./
 * cp test /path/to/libclient.so
 */

#include <stdio.h>
#include <dlfcn.h>

int main(int argc, char *argv[]){
    void (*Py_Initialize)();
    void (*PyRun_SimpleString)(char *);
    void (*Py_Finalize)();

    if (argc < 2) {
        printf("Usage: %s script.py\n", argv[0]);
        return;
    }

    FILE *fp = fopen(argv[1], "rb");

    fseek(fp, 0, SEEK_END);
    int file_len = ftell(fp);

    char *buf = (char *)malloc(file_len + 1);
    fseek(fp, 0, SEEK_SET);
    fread(buf, file_len, 1, fp);
    buf[file_len] = 0;

    void *libm_handle = dlopen("libclient.so", RTLD_LAZY );

    if (!libm_handle){
        printf("Open Error:%s.\n", dlerror());
        return 0;
    }

    Py_Initialize = dlsym(libm_handle, "Py_Initialize");
    Py_Initialize();

    PyRun_SimpleString = dlsym(libm_handle, "PyRun_SimpleString");
    PyRun_SimpleString(buf);

    Py_Finalize = dlsym(libm_handle, "Py_Finalize");
    Py_Finalize();

    dlclose(libm_handle);

    free((void *)buf);
    return 0;
}
```

将交叉编译后的程序 `test` 放到和 `libclient.so` 同一个目录下。

除了上面的方法外，我们还可以继续使用 [IDA Appcall](https://www.hex-rays.com/products/ida/support/tutorials/debugging_appcall.pdf)，
但是经常时灵时不灵：

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/appcall-error.png %}

遇到这种情况，差不多只能重新开始了，所以最好还是直接使用之前交叉编译的程序。

现在为了更快的拿到所有 opcode 的映射关系，我直接写了一份使用了所有 `Python 2.7 opcode` 的文件：
[py27opcode.py](https://gist.github.com/fate0/3e1d23bce9d4d2cfa93848dd92aba3d4)

因为 `from __future__ import division` 会影响 `division`，
要么一个文件的 divide 全是 true divide，要么全是正常的 divide，不能共存。

所以要使用阴阳师的 Python dump 两份 pyc，普通 Python dump 两份 pyc。

获取 pyc 脚本代码如下：

``` python
import marshal

infile = 'py27opcode.py'
outfile = 'android_py27opcode.pyc'

content = open(infile).read()
out_fd = open(outfile, 'wb')
cobj = compile(content, '', 'exec')
marshal.dump(cobj, out_fd)
out_fd.close()
```

用我们在 Android 上使用之前交叉编译后的程序运行上面的代码，得到 `android_py27opcode.pyc`，
删除 division 的注释后再运行一次，得到 `android_py27opcode1.pyc`，在普通环境下，
使用没修改过的 `Python 2.7.3` 再执行相同操作，分别得到 `normal_py27opcode.pyc` 和 `normal_py27opcode1.pyc`

#### 对比 pyc 文件

直接写代码，对比两组 pyc 的 opcode，代码如下：

``` python
import sys
import marshal

opmap = {}

def compare(cobj1, cobj2):
    codestr1 = bytearray(cobj1.co_code)
    codestr2 = bytearray(cobj2.co_code)

    if len(codestr1) != len(codestr2):
        print("two cobj has different length, skipping")
        return

    i = 0
    while i < len(codestr1):
        if codestr1[i] not in opmap:
            opmap[codestr1[i]] = codestr2[i]
        else:
            if opmap[codestr1[i]] != codestr2[i]:
                print("error: has wrong opcode")
                break

        if codestr1[i] < 90 and codestr2[i] < 90:
            i += 1
        elif codestr1[i] >= 90 and codestr2[i] >= 90:
            i += 3
        else:
            print("wrong opcode")

    for const1, const2 in zip(cobj1.co_consts, cobj2.co_consts):
        if hasattr(const1, 'co_code') and hasattr(const2, 'co_code'):
            compare(const1, const2)


def usage():
    print("Usage: %s filename1.pyc filename2.pyc")


def main():
    if len(sys.argv) != 3:
        usage()
        return

    cobj1 = marshal.loads(open(sys.argv[1]).read())
    cobj2 = marshal.loads(open(sys.argv[2]).read())
    compare(cobj1, cobj2)
    print(opmap)


if __name__ == '__main__':
    main()
```

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/compare-opcode-result.png %}

将两组结果进行合并拿到最终的一个 opcode 映射关系。

#### 纠正 opcode

至此，我们已经有足够的信息去修正 `redirect.py` 中错位的 opcode，代码如下：

``` python
#! /usr/bin/env python
# -*- coding: utf-8 -*-

import os
import zlib
import rotor
import marshal
import binascii
import argparse
import pymarshal


class PYCEncryptor(object):
    def __init__(self):
        self.opcode_encrypt_map = {
            1: 38, 2: 46, 3: 37, 4: 66, 5: 12, 10: 35, 11: 67, 12: 81, 13: 32, 15: 9, 19: 63, 20: 70,
            21: 44, 22: 36, 23: 39, 24: 57, 25: 10, 26: 52, 28: 49, 30: 86, 31: 87, 32: 88, 33: 89,
            40: 24, 41: 25, 42: 26, 43: 27, 50: 14, 51: 15, 52: 16, 53: 17, 54: 8, 55: 21, 56: 55,
            57: 82, 58: 34, 59: 22, 60: 65, 61: 6, 62: 58, 63: 71, 64: 43, 65: 30, 66: 19, 67: 5,
            68: 60, 71: 53, 72: 42, 73: 3, 74: 48, 75: 84, 76: 77, 77: 78, 78: 85, 79: 47, 80: 51,
            81: 54, 82: 50, 83: 83, 84: 74, 85: 64, 86: 31, 87: 72, 88: 45, 89: 33, 90: 145, 91: 159,
            92: 125, 93: 149, 94: 157, 95: 132, 96: 95, 97: 113, 98: 111, 99: 138, 100: 153, 101: 101,
            102: 135, 103: 90, 104: 99, 105: 151, 106: 96, 107: 114, 108: 134, 109: 116, 110: 156,
            111: 105, 112: 130, 113: 137, 114: 148, 115: 172, 116: 155, 119: 103, 120: 158, 121: 128,
            122: 110, 124: 97, 125: 104, 126: 118, 130: 93, 131: 131, 132: 136, 133: 115, 134: 100, 135: 120,
            136: 129, 137: 102, 140: 140, 141: 141, 142: 142, 143: 94, 146: 109, 147: 123
        }
        self.opcode_decrypt_map = {self.opcode_encrypt_map[key]: key for key in self.opcode_encrypt_map}
        self.pyc27_header = "\x03\xf3\x0d\x0a\x00\x00\x00\x00"

    def _decrypt_file(self, filename):
        os.path.splitext(filename)
        content = open(filename).read()

        try:
            m = pymarshal.loads(content)
        except:
            try:
                m = marshal.loads(content)
            except Exception as e:
                print("[!] error: %s" % str(e))
                return None

        return m.co_filename.replace('\\', '/'), pymarshal.dumps(m, self.opcode_decrypt_map)

    def decrypt_file(self, input_file, output_file=None):
        result = self._decrypt_file(input_file)
        if not result:
            return

        pyc_filename, pyc_content = result
        if not output_file:
            output_file = os.path.basename(pyc_filename) + '.pyc'

        with open(output_file, 'wb') as fd:
            fd.write(self.pyc27_header + pyc_content)


def main():
    parser = argparse.ArgumentParser(description='onmyoji py decrypt tool')

    parser.add_argument("INPUT_NAME", help='input file')
    parser.add_argument("OUTPUT_NAME", help='output file')

    args = parser.parse_args()

    encryptor = PYCEncryptor()
    encryptor.decrypt_file(args.INPUT_NAME, args.OUTPUT_NAME)


if __name__ == '__main__':
    main()
```

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/redirect-opcode-unmapping.png %}

#### 最终结果

这次我们直接用 `uncompyle2` 反编译：

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/redirect-uncompyle-success.png %}

终于成功解出 `redirect.py` 文件了，根据这个 `redirect.py` 给出的信息，我们就可以拿到解密 `script.npk` 的方法：

1. 按照之前分析 `script.npk` 的方法，事先将每个加密后的 python 文件分割出来
2. 按照 `redirect.py` 里面的加密方法，写出解密过程
3. 按照之前方法，再修正每个 python 脚本的 opcode 映射关系

至此逆向代码的工作终于完成了。

## 0x05 IDAPython

记录一下在分析过程中使用的 script：

#### 1. 尝试自动化

因为要经常重开阴阳师，但是每次重新调试都需要我手动重复暂停继续等待加载 `libclient.so`，所以我写了这么一个 IDAPython Script:

``` python
from idc import *
from idaapi import *
from idautils import *

bt_cond = """
filename = GetString(cpu.r0)
print("loading: %s" % filename)

if not filename:
    return True

if filename == "libclient.so":
    return True
"""
add_bpt(LocByName('__dl__ZL17soinfo_link_imageP6soinfoPK17android_dlextinfo'), 0, BPT_SOFT)
enable_bpt(LocByName('__dl__ZL17soinfo_link_imageP6soinfoPK17android_dlextinfo'), True)
SetBptCnd(LocByName('__dl__ZL17soinfo_link_imageP6soinfoPK17android_dlextinfo'), bt_cond)
```

看着是没什么问题，但是有时候 `GetString(cpu.r0)` 返回一个 `idaapi.BADADDR`，所以 IDA 暂停了，
但是暂停的时候去查看这个地址的内容却发现是正常数据，并不是 `idaapi.BADADDR`，这个情况我并没有去解决，后面还是老老实实手动。

#### 2. 尝试分析函数

当一些断点断下来的时候，在动态调试的窗口只能看到运行指令以及之后的几条指令，虽然说也可以一直按 `C` 键，
但是总这样也挺不方便的，所以我将静态调试的 IDA 中`text` 段的函数地址全部导出到 `d:\\ida.txt` 中：

``` python
import json

funclist = []
for seg_ea in Segments():
    if SegName(seg_ea) != '.text':
        continue

    for function_ea in Functions(SegStart(seg_ea), SegEnd(seg_ea)):
        funclist.append(function_ea)

py_init = LocByName('Py_Initialize')
funclist.insert(0, py_init)

open('d:\\ida.txt', 'w').write(json.dumps(funclist))
print('done')
```

然后再将 `d:\\ida.txt` 的内容再导入到动态调试的 IDA 中：

``` python
import json

funclist = json.loads(open('d:\\ida.txt').read())

daynamic_py_init = LocByName('Py_Initialize')
static_py_init = funclist.pop(0)

offset = daynamic_py_init - static_py_init

for function_ea in funclist:
    MakeFunction(function_ea + offset)

print('done')
```

然而因为 `libclient.so` 中的 `text` 段有 1w 多个函数，导入的时候 `MakeFunction` 实在太慢了，
大概要等五分钟才好，用了几次之后我就放弃了这样的方法。

#### 3. 显示调用堆栈

不知道为什么我的 `Call Stack` 一直显示任何东西，不确定是手机的问题还是 IDA 的问题，还是这个 App 的问题，折腾这问题感觉很麻烦。
因为 fp 寄存器还保存着程序的返回地址，所以还是直接写个 IDAPython Script 打印出调用堆栈比较方便的(如果 fp 不能用，
可以参考 [An attempt to reconstruct the call stack](http://www.hexblog.com/?p=104))：

``` python
import idaapi, idautils

static_py_init = 0x1285398
dynamic_py_init = LocByName('Py_Initialize')
offset = dynamic_py_init - static_py_init

f_fp = idautils.cpu.fp
f_pc = 0

i = 0
while i < 100:
    i += 1
    f_pc = Dword(f_fp)
    f_fp = Dword(f_fp-4)

    if f_fp == idaapi.BADADDR:
        break

    print("%s %s" % (hex(f_pc), hex(f_pc - offset)))

print('===============================')
```


## 0x06 简单写个挂

看了代码之后，发现抽卡的爆率不在本地，但是百鬼夜行的碎片掉率是在本地计算的，简单看一下相关代码片段：

``` python
# scenemembers/GhostWalkScene.py

class GhostWalkScene(GameScene):
    # 省略 ...
    def CheckFairGhostIsHit(self, ghostID, model):
        return True  # modify by fate0
        modelIndex = self.FairModelIndexDict[model]
        
        # 省略 ...

        data = random.randint(1, 100)
        if data <= int(hitRate * 100):
            return True
        else:
            return False

    def CheckEffectGhostIsHit(self, id):
        return True  # modify by fate0
        rate = float(GhostWalkFairData.data[int(id)]['rate'])
        
        # 省略 ...

        if randInt <= int(rate * 100.0):
            return True
        else:
            return False
            
    def FireBean(self, offsetX, offsetY):
        helpers.createModelAsync('model/douzi/douzi.gim', self.FireBeanCallback, (0.3,
         offsetX,
         offsetY,
         self.PlayerModel))
        self.TotalBeanNum = self.TotalBeanNum + 1  # modify by fate0
        
        # 省略 ...

```

* `CheckFairGhostIsHit`: 用来检查走过的式神是否被击中
* `CheckEffectGhostIsHit`: 用来检查飞过的状态是否被击中
* `FireBean`: 开火

所以让 `CheckFairGhostIsHit` 和 `CheckEffectGhostIsHit` 这两个方法返回 `True` 就可以实现百分百命中，
将 `self.TotalBeanNum = self.TotalBeanNum - 1` 修改成 `self.TotalBeanNum = self.TotalBeanNum + 1` 就可以实现无限福豆。

视频演示：

<video src='http://static.fatezero.org/blog/video/decrypt-onmyoji/demo.mp4' type='video/mp4' controls='controls'  width='100%' height='100%'>
</video>

## 0x07 总结

第一次逆 Android 程序，感悟就是手机竟然还会有广告？

## 0x08 更新

找到一个对任意用户或者对任意频道用户拒绝服务的漏洞，奖励:

{% img http://static.fatezero.org/blog/img/decrypt-onmyoji/reward.png %}


{% iframe //music.163.com/outchain/player?type=2&id=588640&auto=0&height=66 500 86%}

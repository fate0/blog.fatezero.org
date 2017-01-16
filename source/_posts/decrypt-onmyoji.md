---
title: 阴阳师：一个非酋的逆向旅程(TODO)
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
{% img /img/decrypt-onmyoji/ida_remote_attach.png %}

6. IDA 设置调试选项
{% img /img/decrypt-onmyoji/ida_debug_option.png %}

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


## 0x03 open & read

之前我也说过了，`lib/armeabi-v7a/libclient.so` 和 `assets/script.npk` 这两个是重点文件，在 `libclient.so` 加载之后，自然要关注一下 `script.npk`。

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

上面的代码主要是将和 `script.npk` 相关的 fd 和文件名关联起来，方便于在 `read` 调用时区分和 `script.npk` 相关的读取操作。

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

## 0x??

TODO

## 0x?? 迷一般的 opcode

为了计算出正确的 `opcode`，我写了一份使用了所有 `Python 2.7 opcode` 的文件： [pyopcode.py](https://gist.github.com/fate0/3e1d23bce9d4d2cfa93848dd92aba3d4)

TODO

除了上面的方法外，我们还可以使用 [IDA Appcall](https://www.hex-rays.com/products/ida/support/tutorials/debugging_appcall.pdf)
``` python
test = Appcall.proto('PyRun_SimpleString', 'int PyRun_SimpleString(char *);')
# test.options = Appcall.APPCALL_MANUAL
print test("open('/sdcard/test123.txt', 'w+').write(str(sys.path))")
```
`Appcall` 比上面的方法更好的是它处于程序的运行状态，程序运行中的数据，使用 `Appcall` 都可以接触到。

但是这招实在没法不吐槽：优点非常好用，缺点时灵时不灵。

## 0x?? 花样使用 IDAPython

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
但是暂停的时候去查看这个地址的内容却发现是正常数据，并不是 `idaapi.BADADDR`。这个谜一般的情况我并没有去解决，后面我还是老老实实手动。

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
因为 fp 寄存器还保存着程序的返回地址，所以还是直接写个 IDAPython Script 打印出调用堆栈比较方便的(如果 fp 不能用，可以参考 [An attempt to reconstruct the call stack](http://www.hexblog.com/?p=104))：

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


## 0x?? 简单写个挂

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

## 0x?? 总结

第一次逆 Android 程序，感悟就是手机竟然还会有广告？


{% iframe //music.163.com/outchain/player?type=2&id=588640&auto=0&height=66 500 86%}
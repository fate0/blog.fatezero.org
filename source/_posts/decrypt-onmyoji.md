---
title: 阴阳师：一个非酋的逆向旅程
date: 2017-01-14 12:15:11
tags:
---


## 0x00 前言
为了验证这个游戏到底有没有 SSR

<!-- more -->

## 0x01 前期工作

#### 工具准备
* Android 5.0.2
* windows
* ubuntu

```
apktool d onmyoji_netease_1.0.14.apk
```
将 `AndroidManifest.xml` 中的 `debuggable` 修改为 `true`

```
apktool b onmyoji_netease_1.0.14
```

```
java -jar signapk.jar platform.x509.pem platform.pk8 onmyoji_netease_1.0.14.apk onmyoji_netease_1.0.14_fix.apk
```




## 0x02 Android 调试初试

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

8. xxx
```
jdb -connect com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=17178
```

由于种种原因，我需要重开很多次阴阳师，所以我就将步骤 7，8 合并成一个 `copy & paste` 的命令
```
for /f "delims=" %i in ('adb shell "set `ps |grep netease.onmyoji`; echo -n $2"') do adb forward tcp:17178 jdwp:%i && jdb -connect com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=17178
```


## 0x03 IDAPython 

#### 1. 更加自动化
虽然说能够对阴阳师进行调试了，但是每次重新调试都需要我手动重复暂停继续等待加载 `libclient.so`，所以我写了这么一个 IDAPython script:

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

但是问题来了，有时候 `GetString(cpu.r0)` 返回一个 `idaapi.BADADDR`，所以 IDA 暂停了，
但是暂停的时候去查看这个地址的内容却发现是正常数据，后面我还是老老实实改成自己手动。

#### 1. 动态调试代码分析存在问题

为了能够在调试的时候能够正常显示函数，我将静态调试的 IDA 中 `text` 段的函数地址全部导出到 `d:\\ida.txt` 中

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

然后再将 `d:\\ida.txt` 的内容再导入到动态调试的 IDA 中

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

然而因为 `text` 段有 1w 多个函数，导入的时候 `MakeFunction` 实在太慢了，大概要等五分钟才好，所以我就放弃了这样的方法。

#### 2. Call Stack
不知道为什么我的 `Call Stack` 一直显示任何东西，不确定是手机的问题还是 IDA 的问题，还是这个 App 的问题，
所以我还是从 fp 直接推出整个 Call Stack

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

## 0x??

TODO

## 0x??

为了计算出正确的 `opcode`，我写了一份使用了所有 `Python 2.7 opcode` 的文件： [pyopcode.py](https://gist.github.com/fate0/3e1d23bce9d4d2cfa93848dd92aba3d4)


## 0x??

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

撒一次豆子的成果：

{% img /img/decrypt-onmyoji/result1.png %}
{% img /img/decrypt-onmyoji/result2.png %}

## 0x?? 总结


{% iframe //music.163.com/outchain/player?type=2&id=588640&auto=0&height=66 500 86%}
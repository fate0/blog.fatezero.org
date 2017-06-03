---
title: Package 钓鱼
date: 2017-06-01 20:47:24
tags:
---


## 0x00 前言

前几天 `Samba` 公开了一个远程代码执行的漏洞，然后各种 POC 也随之出现，
`exploit-db` 上也有这样一个 Python 版本的 [POC:  Samba 3.5.0 - Remote Code Execution](https://www.exploit-db.com/exploits/42060/).

<!-- more -->

直接执行 POC，报错误信息：

{% img http://static.fatezero.org/blog/img/package-fishing/run-poc-at-the-first-time.png %}

这种情况非常简单，直接 `pip install smb` 就行，但是：

{% img http://static.fatezero.org/blog/img/package-fishing/install-smb-package.png %}

好吧，我们还是需要 Google 一下这个 `smb` 的 package 名字，最后发现原来是 `pysmb`：

{% img http://static.fatezero.org/blog/img/package-fishing/install-pysmb-and-run-poc.png %}

最后 POC 终于跑了起来.

我们再回过头来看看整个流程，似乎并没有什么地方不对劲。

直接说问题所在吧，如果你在 `2017-05-24` 到 `2017-05-31` 这段时间内执行过 `pip install smb` 或者 `pip download smb`，
那么恭喜你，你的名字可能出现在我的绵羊墙上。


### 0x01 试水 (2017-05-23 19:00)

第一天，我在 PyPI 上投放了 4 个 evil package: `python-dev`、`mongodb`、`proxy`、`shadowsock` 
测试一下不检查 package、随意安装 package 的人有多少。

其中所有的内容都是用 `cookiecutter` 根据模版 [cookiecutter-evilpy-package](https://github.com/fate0/cookiecutter-evilpy-package/tree/cf812e1f44ca052b5e7055a8ff8cf5c4d81dcf98) 生成。

每个 package 都会收集用户的

* username
* hostname
* ip
* hostinfo

我选择了 GitHub Issues + webtask.io 的方式，将安装 evil package 的用户信息通过 webtask.io 中转到 GitHub Issues 上对外公开。

所以我就在 Github 上注册了个小马甲 [evilpackage](https://github.com/evilpackage) 专门提交 Issue。

因为 webtask.io 获取客户端 ip 的时候，其实获取到的是 webtask.io 前面 nginx 的 ip 地址，并不是用户的 ip，所以就只能在代码里面获取客户端的外网 ip.
使用 webtask.io 和 GitHub Issues 的主要原因是这两都是免费的。

## 0x02 增加投放 package (2017-05-24 19:00)

查看了一天的 Issues 数量，大概有 700+，效果非常不错，决定继续投放 evil package。
与此同时，@[ztz](http://weibo.com/u/1260091985) 同学也加入了游戏，也在 RubyGems 上投放 Gems。

继续投放 evil package，就必须想一些比较好的名字，我主要使用下面两种方法:

1. Google 搜索提示框            
直接根据 Google 的搜索框提示:
{% img http://static.fatezero.org/blog/img/package-fishing/google-search-input-list.png %}
便收集到了没有在 PyPI 上注册，而且比较流行的 Package 名字:

    * caffe
    * ffmpeg
    * git
    * mkl
    * opencl
    * opencv
    * openssl
    * pygpu
    * tkinter
    * vtk
    * proxy

2. 想象力             
依据平时写代码的经验总结出下面可能觉得会常用，但并没有在 PyPI 上注册的 Package 名字:

    * ftp
    * smb
    * hbase
    * samba
    * rabbitmq
    * zookeeper
    * phantomjs
    * memcached
    * requirement.txt
    * requirements.txt

其中 `requirements.txt` 并没有注册成功，稍后再说。

## 0x03 暂停服务 (2017-05-25 23:00)

晚上回家的时候又统计了一下安装量，一天安装量达到了 2000+，效果已经很显著，不必再增加新的 package 了，但是到了晚上 23:00 的时候，
我的 GitHub Issues 被恶意插入脏数据，所以只能暂停服务：

{% img http://static.fatezero.org/blog/img/package-fishing/insert-useless-data.png %}

之所以只能暂停服务，那是因为 webtask.io 没法获取客户端 ip，我也没法 ban 掉对应的 ip，作出任何相对的处理，只能停服务。

话说到底谁才是攻击者。

## 0x04 evilpackage 被封 (2017-05-26 2:00)

我专门提交 Issue 的小马甲 [evilpackage](https://github.com/evilpackage) 因为触发了 GitHub 对 Spam 的检测，所以被封号了。
早上起床看到消息后，立马写邮件申诉，直到 2017-05-26 13:00 终于回复我的邮件了：

{% img http://static.fatezero.org/blog/img/package-fishing/unlock-evilpackage.png %}

## 0x05 放弃 webtask.io (2017-05-26 19:00)

为了避免和之前一样被恶意插入脏数据，决定要放弃 webtask.io，每月花费 $10 巨款购入一台 vps。

使用 nginx + flask 的配置，继续将 user data 提交到 GitHub Issues 上。

nginx 的 `ngx_http_limit_req_module` 模块最大能够支持 `1s/m`，也就是最多可以限制每个 ip 在每分钟内最多请求一次，
所以我们必须修改 `ngx_http_limit_req_module` 模块代码

``` c
// src/http/modules/ngx_http_limit_req_module.c

        if (ngx_strncmp(value[i].data, "rate=", 5) == 0) {

            len = value[i].len;
            p = value[i].data + len - 3;

            if (ngx_strncmp(p, "r/s", 3) == 0) {
                scale = 1;
                len -= 3;

            } else if (ngx_strncmp(p, "r/m", 3) == 0) {
                scale = 60;
                len -= 3;

            } else if (ngx_strncmp(p, "wtf", 3) == 0) {
                scale = 1000;
                len -= 3;
            }
```

增加一个 `else if` block，直接将 scale 增加到 1000，这样就能限制每个 ip 在 16 min 内只能访问一次我们的接口，
除非使用大量代理，不然很难在短时间内插入大量脏数据。

## 0x06 repo 被封 (2017-05-27 3:00)

早上起床刷新一下 GitHub Issues 页面，结果发现：

{% img http://static.fatezero.org/blog/img/package-fishing/lock-repo.png %}

邮件：

{% img http://static.fatezero.org/blog/img/package-fishing/lock-repo-email.png %}

赶紧先上服务器加上一行代码，将用户上传的数据先暂时存在本地（之前太懒）。
然后马上回邮件，问情况，两天后：

{% img http://static.fatezero.org/blog/img/package-fishing/lock-repo-response-email.png %}

解封无望，之前的数据大概就是没了。

目前还能通过 GitHub Search 找到以前的部分数据 [GitHub Issue](https://github.com/search?l=&q=repo%3Afate0%2Fcookiecutter-evil-pypackage&ref=advsearch&type=Issues&utf8=%E2%9C%93)


## 0x07 写 web 界面 (2017-05-30 19:00):

由于之前一直在忙，最后拖到了30号才开始写 web 展示界面 [http://evilpackage.fatezero.org/](http://evilpackage.fatezero.org/)

也准备好新的 cookiecutter 模版 [cookiecutter-evilpy-package](https://github.com/fate0/cookiecutter-evilpy-package/commit/b1a968407b1a94b17298af969727848ad1325cae)

新的 cookiecutter 模版会提示用户安装了 evilpackage，并打开用户的浏览器去访问 [http://evilpackage.fatezero.org/](http://evilpackage.fatezero.org/)，让用户知道，自己已经是绵羊墙上的一员了。

计划打算第二天再往 PyPI 上提交新版本的 Package。

## 0x08 清空 (2017-05-31):

早上查找资料的时候发现，原来已经有好几批人干过和我一样类似的事情了

* 2013-06-06: [requestes 0.0.1](https://pypi.python.org/pypi/requestes)
* 2016-01-25: [requirements-dev 1.0.0](https://pypi.python.org/pypi/requirements-dev/1.0.0)
* 2016-03-17: [Typosquatting in Programming Language Package Managers](http://incolumitas.com/data/thesis.pdf) 

前两批都只是上传一个 package 用来提示安装用户，也防止恶意用户使用这些 package 名字，
后面一个小哥和我一样收集了用户不太敏感的信息，只不过他的数据一直没有公开。

过了一会 @[ztz](http://weibo.com/u/1260091985) 同学告诉我他的 RubyGems 被清空了。

再过了一会我这边也被 PyPI 管理员警告要删除账号了，所以我就把所有的 Package 给删除了，账号也给删除了。

目前为止所有的 package 又回到了 unregister 的状态, 任何人都可以继续注册使用我之前注册的 package.


## 0x09 数据统计

目前我只能对在 [http://evilpackage.fatezero.org/](http://evilpackage.fatezero.org/) 上那 10685 条数据进行统计

从 2017-05-27 10:38:03 到 2017-05-31 18:24:07，总计 106 个小时内，
有 9726 不重复的 ip 安装了 evil package，平均每个小时有 91 个 ip 安装了 evil package。

1. 每个 package 命中排名:
```
2862 opencv
2834 tkinter
810 mkl
789 python-dev
713 git
683 openssl
535 caffe
328 ffmpeg
224 phantomjs
200 smb
191 vtk
179 pygpu
113 mongodb
70 requirement.txt
56 memcached
31 rabbitmq
15 ftp
14 shadowsock
12 samba
10 proxy
10 hbase
5 zookeeper
```

2. 前 50 个国家命中排名
```
2507 United States
1667 China
772 India
481 Germany
448 Japan
331 France
319 Republic of Korea
306 United Kingdom
305 Russia
297 Canada
225 Brazil
183 Australia
179 Netherlands
167 Poland
147 Taiwan
129 Italy
127 Israel
126 Spain
106 Singapore
103 Ukraine
89 Hong Kong
87 Switzerland
76 Sweden
74 Turkey
60 Ireland
57 Vietnam
57 Iran
54 Belgium
53 Finland
52 Austria
49 Pakistan
49 Indonesia
47 Argentina
43 New Zealand
42 Mexico
41 Romania
40 Thailand
37 Norway
37 Czechia
31 South Africa
31 Denmark
31 Colombia
29 Portugal
29 Greece
29 Chile
24 Philippines
23 Malaysia
20 Hungary
20 Belarus
19 Nepal
```

3. 每个访问排名 
```
28 114.255.40.3
25 46.105.249.70
16 54.84.16.79
16 54.237.234.187
16 54.157.41.7
16 54.145.106.255
16 52.90.178.211
13 34.198.151.69
12 52.221.7.193
11 54.235.37.25
10 34.224.47.129
9 172.56.26.43
7 94.153.230.50
7 80.239.169.204
7 73.78.62.6
7 54.87.185.66
7 52.207.13.234
7 113.140.11.125
6 52.55.104.10
6 24.108.0.220
```

光从这几天来看，在 PyPI 上投放 evilpackage 的效果还是非常不错的，
每天都会有大概 2200+ 个独立 ip 进行访问，数据量稍微比之前那位小哥好一点，
也就是说，即便是类似的文章发出来，过了一年之后，随意安装 package 的这种情况完全没有改善，可能更严重了。

那位小哥释放掉所有的 package 之后，我作为一个 "恶意者" 再次使用他之前使用的 `git`、`openssl` 名字来统计数据，
我作为一个 "恶意者"，被官方勒令删除所有的 package，这些 package 名字再次被释放，我比较好奇下一位 "恶意者" 会是谁，
会在 package 里放什么？会是和我一样收集数据，还是直接 `rm -rf /`，还是勒索。拭目以待。

## 0x10 requirements.txt

一般经常使用 Python 的人都知道 `requirements.txt` 是整个项目的依赖文件，一般这样使用：

```
pip install -r requirements.txt
```

不过也有可能一时手速过快，敲打成

```
pip install requirements.txt
```

所以 `requirements.txt` 也是一个比较好的 evil package 的名字

#### 诡异的 `requirements.txt` 

在 2017-05-24 19:00 晚上，我尝试在 PyPI 注册上传 `requirements.txt` 的时候：

{% img http://static.fatezero.org/blog/img/package-fishing/upload-requirements-failed.png %}

嗯，都失败了，但是 [GitHub Issues](https://github.com/search?utf8=%E2%9C%93&q=repo%3Afate0%2Fcookiecutter-evil-pypackage+requirements.txt&type=Issues) 上竟然会有 153 个和 `requirements.txt` 相关的 Issues：

{% img http://static.fatezero.org/blog/img/package-fishing/requirements-txt-show-in-issues.png %}

我并不怀疑这些 `requirements.txt` 数据的真实性，因为就没有人知道我尝试上传过 `requirements.txt`，所以这些数据肯定是真实的。

PyPI 上也并不存在 `requirements.txt` 信息，本地尝试安装也失败了，至今仍未明白这种情况为何发生。

#### 绕过 PyPI `requirements.txt` 的限制

在 PyPI 账号被删除之后，我还是对 `requirements.txt` 很好奇，为什么之前 GitHub 上会有记录？
能不能绕过 PyPI 的限制？下面简单讲一下如何绕过 PyPI 的限制。

我们直接查看提交 Package 时，PyPI 对 Package 名字限制的地方：
```python
# from: https://github.com/pypa/pypi-legacy/blob/master/webui.py#L2429
@must_tls
def submit_pkg_info(self):
    # ...
    # ...
    name = data['name']
    version = data['version']

    if name.lower() in ('requirements.txt', 'rrequirements.txt',
            'requirements-txt', 'rrequirements-txt'):
        raise Forbidden, "Package name '%s' invalid" % name
```

通过上面的代码，我们可以看到 PyPI 直接硬编码 `'requirements.txt', 'rrequirements.txt', 
'requirements-txt', 'rrequirements-txt'` 禁止用户上传这些文件。


我们再看看 `pip install xxx` 的时候，PyPI 是怎么查找 Package 的：
```python
# from: https://github.com/pypa/pypi-legacy/blob/master/store.py#L611
def find_package(self, name):
    '''Return names of packages that differ from name only in case.'''
    cursor = self.get_cursor()
    sql = 'select name from packages where normalize_pep426_name(name)=normalize_pep426_name(%s)'
    safe_execute(cursor, sql, (name, ))
    return [r[0] for r in cursor.fetchall()]
```

好吧，直接查找数据库，我们再跟下来看 `normalize_pep426_name`：
``` python
# from: https://github.com/pypa/warehouse/blob/master/warehouse/migrations/versions/3af8d0006ba_normalize_runs_of_characters_to_a_.py#L27
def upgrade():
    op.execute(
        """ CREATE OR REPLACE FUNCTION normalize_pep426_name(text)
            RETURNS text AS
            $$
                SELECT lower(regexp_replace($1, '(\.|_|-)+', '-', 'ig'))
            $$
            LANGUAGE SQL
            IMMUTABLE
            RETURNS NULL ON NULL INPUT;
        """
    )
    op.execute("REINDEX INDEX project_name_pep426_normalized")
```

看到中间那个正则了吧，这也就意味着 
```
pip install youtube-dl
pip install youtube_dl
pip install youtube.dl
pip install youtube-_-dl
pip install youtube.-.dl
```

这几条命令其实都是等价的，都是在安装 `youtube_dl`, 那么我们就可以很容易的就绕过 PyPI 的限制，
直接上传一个 `requiremnets--txt`：


```
twine register dist/requirements--txt-0.1.0.tar.gz
twine upload dist/requirements--txt-0.1.0.tar.gz
```

来来来，我们直接尝试 `pip install requirements.txt`：

{% img http://static.fatezero.org/blog/img/package-fishing/install-requirements--txt.png %}

通过上面的图，我们可以看到 PyPI 已经返回我们的 package url，
到了 pip 准备安装这个 package 的时候报错了，所以直接看 pip 代码：


``` python
# https://github.com/pypa/pip/blob/master/pip/index.py#L650
if not version:
    version = egg_info_matches(egg_info, search.supplied, link)
if version is None:
    self._log_skipped_link(
        link, 'wrong project name (not %s)' % search.supplied)
    return
```

看了代码，也就是没法在 url 中获取 package 的版本号，
因为 package 的名字(`requirements--txt`)和搜索名字(`requirements.txt`)对不上，我们得找找其他方法：

``` python
# https://github.com/pypa/pip/blob/master/pip/index.py#L626
if ext == wheel_ext:
    try:
        wheel = Wheel(link.filename)
    except InvalidWheelFilename:
        self._log_skipped_link(link, 'invalid wheel filename')
        return
    if canonicalize_name(wheel.name) != search.canonical:
        self._log_skipped_link(
            link, 'wrong project name (not %s)' % search.supplied)
        return

    if not wheel.supported(self.valid_tags):
        self._log_skipped_link(
            link, 'it is not compatible with this Python')
        return

    version = wheel.version
```

看到这里，大家应该也知道了，之前我们一直都是使用 source 的方式提交 package，如果我们直接打包成 wheel，
根据上面的代码，就不会再报错了，我们重新打包，再次上传：

{% img http://static.fatezero.org/blog/img/package-fishing/upload-requirements-success.png %}

终于成功了，当然 wheel 安装方式并不能直接执行命令，
不过我们可以通过给 `requirements.txt` 添加一个恶意依赖达到执行任意代码的效果。

在这里，我就添加了一个名为 `ztz` 的 source package，用于提醒安装 `requirements.txt` 的用户

{% img http://static.fatezero.org/blog/img/package-fishing/ztz.png %}


## 0x11 总结

最后还是提一下我是怎么被 PyPI 官方发现的，原因非常简单，
我之前每个 evil package 都是用同一个 cookiecutter 模版生成，
而每个模版的 short desc 都是 `just for fun : )`，所以在 [PyPI 首页](https://pypi.python.org/pypi) 刷了一排 `just for fun : )`。
就是因为这样简单的理由被发现。

但是如果，我为每个 evil package 准备不同模版，为每个 evil package 准备文档， 
为每个 evil package 准备不同的 PyPI account 上传，每次上传使用不同 ip，在 PyPI 没有审核机制的情况下，
是很难将所有的 evil package 一网打尽，只能靠别人 report。

所以防御方案就完全不可能期待 PyPI 会做什么，只能提升自我对信息安全意识，对 PyPI 上不熟悉的项目一律采取不可信的态度，
意识到随意 `pip install` 就和随意的执行 `exe` 一样危险。

想做一件坏事情真不容易，快去看看 [http://evilpackage.fatezero.org/](http://evilpackage.fatezero.org/) 上面有没有你的名字。

{% iframe //music.163.com/outchain/player?type=2&id=478731355&auto=0&height=66 500 86%}

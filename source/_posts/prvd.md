---
title: PHP 运行时漏洞检测
date: 2018-11-11 10:00:24
---

## 0x00 前言

这片博文将简单的介绍我编写的 PHP 运行时漏洞检测系统 [prvd](https://github.com/fate0/prvd) 的检测逻辑，
以及该系统在实际测试中的效果。

<!-- more -->

## 0x01 基本知识

在这里我们先介绍几个常用的词语：

1. source

    数据来源点，可以是：
    * 网络，例如常规的 Web 参数等
    * 文件系统
    * 数据库
    * 等等其他用户可控或者间接可控的地方

2. filter

    数据过滤处理点，可以是：
    * 编码解码，例如 `base64_decode` 等
    * 常规字符串操作，例如 `strtolower` 等
    * 安全过滤，例如 `mysqli_escape_string` 等
    * 等等其他会更改字符串内容的地方

3. sink

    漏洞触发点，可以是：
    * 操作文件相关行为，例如 `file_put_content` 等
    * 操作网络相关函数，例如 `curl` 等
    * 操作命令相关行为，例如 `system` 等
    * 等等其他危险行为

有些地方既可以是 source 点，也可以是 sink 点，比如说 `file_put_content` 在参数可控的时候是 sink 点，因为返回的数据也是我们可控的，这里返回的数据也是 source 点。

## 0x02 xmark

我们先简单地介绍一下 [xmark](https://github.com/fate0/xmark)，这是一个 PHP7 扩展，能够直接使用 PHP 代码做到：

* 对字符串变量进行打标记
* Hook 绝大多数函数/类
* Hook 部分 opcode

基于 [xmark](https://github.com/fate0/xmark) 所提供的功能，即便是我们不熟悉 PHP 内部实现，我们也能够很简单的去实现：

* PHP RASP
* PHP 解密工具，例如 [phpdecoder](http://ddecode.com/phpdecoder/)
* PHP 运行时漏洞检测
* ...

因为 PHP 并不像 Python、Ruby 等其他语言可以很方便的 Hook 函数、类，所以我们开发了这么一个扩展来完成类似的功能。

实际上 [xmark](https://github.com/fate0/xmark) 这个项目有不少代码是直接拷贝 [taint](https://github.com/laruence/taint) 的，
那为什么要改这样一个轮子呢？

* taint 的 source 点覆盖不全面，只对 GPC 进行标记
* taint 处理和漏洞相关的逻辑需要在 PHP 扩展中实现

这里我不打算花太多篇幅介绍 xmark 的实现，直接看代码更方便，更多关于 xmark 的信息可以点[这里](https://github.com/fate0/xmark)

## 0x03 prvd

前面说了基于 [xmark](https://github.com/fate0/xmark) 我们可以实现挺多好玩的事情，
这里我选择去完成一个 PHP 运行时漏洞检测系统，也就是 [prvd](https://github.com/fate0/prvd) 这个项目，
项目名也就是 PHP Runtime Vulnerability Detection 的缩写。

prvd 有两种模式，一种是 taint 模式, 另外一种是 payload 模式。taint 模式可以选择开启，payload 模式是一直都开启的。
这两种模式都依赖外部来解决执行路径的问题。

#### taint 模式

这种模式下 prvd 和 taint 一样，都是 source 打上一个标记，在某些 filter 中传递这个标记，然后在 sink 点检查对应的参数是否被打上标记。

比方说：
``` php
$cmd = $_POST['cmd'];
$cmd1 .= "fate0";
$cmd2 = strtolower($cmd1);
system($cmd2);
```

`$_POST['cmd']` 一开始就被我们打上了标记，在自赋值的时候将标记传递给了 `$cmd1`，
在经历 `strtolower` 这个 filter 的时候继续将标记传递给了 `$cmd2`，
`$cmd2` 最后进入 sink 点 `system` 函数的时候被检测被打上了标记，从而确定是否可能存在问题。

taint 模式可以不需要输入特定的 payload 进行攻击就可能发现一些漏洞点，也不会污染数据，但是在 filter 中判断是否应该继续传递标记比较难处理，
有可能数据已经经过了很好的过滤，但是我们还是继续传递了标记，最终导致误报。也有可能数据处理不当，但我们已经去除了标记，最终导致漏报。

我们举个漏报的例子：
``` php
$id = $_POST[ 'id' ];

$id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $id);

$query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
// $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' );
```

可控变量 `$id` 经过 `mysqli_real_escape_string` 的时候需不需清除其标记呢？

为了解决这种情况，我编写了另外一种 payload 模式。

#### payload 模式

有时候追踪执行流并没有什么用，整那么多玩意，还不如直接一把梭哈，直接把 payload 打过去，然后在 sink 点观测，
这就是我们的 payload 模式，这个模式的 prvd 可以归类为 IAST 的一种。

payload 模式相比 taint 模式，优点为：

* 误报率比 taint 模式低，使用 payload 模式，从技术上完全把误报率降低到 1% 一下
* 可以不关注 source 点和 filter 点，这样即使数据经历多次中转，最后经过 sink 点的漏洞，也有能力去检测，比如说多阶 SQL 注入的情况

缺点为：

* 漏报率可能会比 taint 模式下高，因为可能经过各种 filter 的时候就被 payload 就会拦截下来，也可能需要特定 payload 才能触发漏洞
* 需要特别关注 sink 点，在 sink 点中根据各种条件判断是否为漏洞
* 会污染数据

下面简单的介绍一下在 payload 模式下，各种漏洞的检测方法：

| 漏洞类型 | 检测方法 |
| ------ | ------ | 
| SQL 注入 | 在 `prvd_check_sqli` 中检测待 SQL 的完整性是否被破坏，是否逃逸了单双引号 |
| 任意文件操作 | 在 `prvd_check_path` 中检测文件操作的路径中是否包含 `../xtanzi` 字符串 | 
| 远程命令执行 | 在 `prvd_check_rce` 中检测待执行命令的完整性是否破坏，是否逃逸了单双引号 |
| SSRF | 在 `prvd_check_ssrf` 中检测输入的链接 domain 是否包含 `xtanzi` 字符串 |
| XSS | 在 `prvd_check_xss` 中判断输入是否被 taint 标记 |
| 调用任意 callback | 在 `prvd_check_callback` 中检测 callback 是否包含 `xtanzi` 字符串 |

我知道上面的各种检测方式并不完美，每个漏洞的检测方法都有误报和漏报的情况，不过现阶段还是够用的，可以以后继续完善。

#### fuzzer

这里我使用 Python 写了一个比较简单的 fuzzer 放在项目 tools 目录下，目前也只是对每个 source 点增加一个 `'"><xtanzi>./../xtanzi` 这样的 payload

这里也可以根据自己的情况，重新编写 fuzzer。

#### Sentry 漏洞展示

至此，我们还缺少一个漏洞上报的平台，我们希望这个平台能够：

* 良好的权限管理，拥有的 group、project 等功能
* 收集到漏洞触发时的请求信息
* 收集到漏洞触发时的堆栈信息
* 能够对多个同堆栈下的重复漏洞进行去重
* 能够一键提交 jira 以及 git issue
* 各种统计功能
* ...

天啊，需求越来越多，我们的精力更多的被分配到了这个平台上了，请不要忘了我们本意是要做一个 PHP 运行时漏洞检测系统。
上报平台虽然重要，但不应该成为整套系统花费精力最多的部分，我们需要把时间放在漏洞检测这块。

这个时候我想起了 [Sentry](https://github.com/getsentry/sentry)
> Sentry is cross-platform application monitoring, with a focus on error reporting. 

{% img http://static.fatezero.org/blog/img/prvd/sentry.png %}

Sentry 本来是一个跨平台应用的异常报告系统，但在我们这套 PHP 运行时漏洞检测系统中被使用为漏洞上报平台了，理由是：

* 支持上面提到的需求
* 界面美观
* DRY

我们的 prvd 可以说是 Sentry 的一个检测漏洞的 Client，只不过 prvd 的功能不是报告异常，而是报告漏洞，
由于 Sentry 支持多种语言，所以我们不仅可以给 PHP 写这样一个 Client，还可以给 Python, Ruby 等其他语言写这样检测漏洞的 Client

## 0x04 实际例子

最后，我们拿 [DedeCMS](http://updatenew.dedecms.com/base-v57/package/DedeCMS-V5.7-UTF8-SP2.tar.gz) 作为测试例子，看看 prvd 的效果如何。


#### 安装环境

首先在 `dede/config.php` 修改 `csrf_check` 函数让其直接返回 true，其次执行下面命令启动 fuzzer：

```sh
python prvd/tootls/fuzzer.py
```

然后前往 [Sentry](https://sentry.io) 注册一个账号，或者自建一套 Sentry 服务

剩下的可以直接使用 docker

```sh
docker pull mysql
docker pull fate0/prvd
docker run -d --name dede_mysql -e MYSQL_ALLOW_EMPTY_PASSWORD=1 -e MYSQL_ROOT_PASSWORD='' -p 3306:3306 mysql --default-authentication-plugin=mysql_native_password
docker run -d --name dede_prvd -e "PRVD_SENTRY_DSN={SENTRY_DSN}" -e "PRVD_FUZZER_DSN={FUZZER_DSN}" -e "PRVD_TAINT_ENABLE=false" -v "/local_path_to_web_root/:/var/www/html" -p 8080:80 --link dede_mysql fate0/prvd
```

因为 taint 模式误报会比较多(taint 模式出来的漏洞在 Sentry 上会以蓝色标注)，我也并不打算花时间去 review 详情，所以这里我只启用了 payload 模式。

#### 检测过程

每个功能点都乱点一下，每个输入框都随便写写，尽量每个功能都能够瞎点瞎填覆盖到。

#### DedeCMS 相关漏洞

最后得出下面这些可疑的漏洞：

* [dede_archives_do.php SQL 注入](http://static.fatezero.org/blog/other/prvd/dedecms_archives_do.php_sqli.html)
* [dede_article_add.php SQL 注入](http://static.fatezero.org/blog/other/prvd/dedecms_article_add.php_body_sqli.html)
* [dede_article_keywords_make.php SQL 注入](http://static.fatezero.org/blog/other/prvd/dedecms_article_keywords_make.php_sqli.html)
* [dede_article_test_same.php SQL 注入](http://static.fatezero.org/blog/other/prvd/dedecms_article_test_same.php_sqli.html)
* [dede_pm.php SQL 注入](http://static.fatezero.org/blog/other/prvd/dedecms_pm.php_sqli.html)
* [dede_makehtml_rss_action.php SQL 注入](http://static.fatezero.org/blog/other/prvd/dedecms_makehtml_rss_action.php_sqli.html)
* [dede_co_gather_start_action.php SQL 注入](http://static.fatezero.org/blog/other/prvd/dedecms_co_gather_start_action.php_sqli.html)
* [dede_co_export.php SQL 注入](http://static.fatezero.org/blog/other/prvd/dedecms_co_export.php_sqli.html)
* [dede_co_do.php SQL 注入](http://static.fatezero.org/blog/other/prvd/dedecms_co_do.php_sqli.html)
* [dede_content_batchup_action.php SQL 注入](http://static.fatezero.org/blog/other/prvd/dedecms_content_batchup_action.php_sqli.html)
* [dede_makehtml_all.php SQL 注入](http://static.fatezero.org/blog/other/prvd/dedecms_makehtml_all.php_sqli.html)
* [dede_makehtml_archives_action.php SQL 注入](http://static.fatezero.org/blog/other/prvd/dedecms_makehtml_archives_action.php_sqli_1.html)
* [dede_article_add.php 服务器端请求伪造](http://static.fatezero.org/blog/other/prvd/dedecms_article_add.php_ssrf.html)
* [dede_co_add.php 服务器端请求伪造](http://static.fatezero.org/blog/other/prvd/dedecms_co_add.php_ssrf.html)
* ...

虽然都只是后台的漏洞，但拿来做演示是最好不过了 ：）

## 0x05 总结

上面简单的介绍了 prvd 的检测原理和使用过程。简单的说，prvd 就是一个半自动的 PHP 运行时漏洞检测系统，
在 taint 模式下，会尽可能显示可疑漏洞，方便熟悉安全的人员或者开发人员去 review 代码，
在 payload 模式下，即使不太了解安全的测试人员也能够检测出漏洞，

## 0x06 引用

* [prvd](https://github.com/fate0/prvd)
* [taint](https://github.com/laruence/taint)
* [xmark](https://github.com/fate0/xmark)
* [Sentry](https://github.com/getsentry/sentry)

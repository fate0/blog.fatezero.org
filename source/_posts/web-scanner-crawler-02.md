---
title: 爬虫 JavaScript 篇[Web 漏洞扫描器]
date: 2018-04-09 10:00:24
---


## 0x00 前言

[上一篇](http://blog.fatezero.org/2018/03/05/web-scanner-crawler-01/)主要讲了如何通过修改 Chromium 代码为 Web 漏洞扫描器的爬虫打造一个稳定可靠的 headless 浏览器。这一篇我们从浏览器底层走到上层，从 C++ 切换到 JavaScript，讲一下如何通过向浏览器页面注入 JavaScript 代码来尽可能地获取页面上的链接信息。

<!-- more -->

## 0x01 注入 JavaScript 的时间点

首先我们要解决的第一个问题是：在什么时间点向浏览器页面注入 JavaScript 代码？

答案非常简单，
在页面加载前，我们希望能够注入一段 JavaScript 代码以便于能够 Hook、备份各种未被污染的函数，
在页面加载后，我们希望能够注入一段 JavaScript 代码以便于能够进行遍历各个元素、触发各种事件、获取链接信息等操作。

那么下一个问题又来了：怎么定义页面加载前、页面加载后？

页面加载前的定义非常简单，只要能在用户代码执行前执行我们注入的 JavaScript 代码即可，也就是在页面创建之后、用户代码执行之前的时间段对于我们来说都算是页面加载前，CDP 刚好提供了这么一个 API 
[`Page.addScriptToEvaluateOnNewDocument`](https://chromedevtools.github.io/devtools-protocol/tot/Page#method-addScriptToEvaluateOnNewDocument) 能够让我们在页面加载前注入 JavaScript 代码。

接下来考虑一下该如何定义页面加载后。最简单的方法就是不管三七二一，每个页面都加载 30s (即便是空白的页面)，随后再注入我们的代码，但很明显这会浪费很多资源，我们需要根据每个页面的复杂度来控制加载时间。可能会有同学说我们可以监听 `load` 事件，等待页面加载结束之后再注入代码，那我们考虑一个比较常见的场景，在某个页面上刚好有那么一两个图片字体资源加载速度特别慢，导致 `load` 迟迟未被触发(甚至不触发)，但这些资源其实我们并不在乎，完全可以直接注入我们代码，所以只等待 `load` 事件也并不是一个特别好的选择。

我们先看一下加载一个页面的过程，除了会触发 `load` 事件之外还会触发什么事件:

``` html 
<html>
<!-- 在外部 script 之前的 css 会阻塞 DOM 的构建 -->
<link rel="stylesheet" href="http://httpbin.org/delay/3?id=1">
<script src="http://httpbin.org/delay/1?id=2"></script>
<!-- 后面两个 css 并不会阻塞 DOM 的构建 -->
<link rel="stylesheet" href="http://httpbin.org/delay/6?id=3">
<link rel="stylesheet" href="http://httpbin.org/delay/6?id=4">
</html>
```

``` python
import pychrome
import pychrome.exceptions

def lifecycleEvent(**kwargs):
    print("{}: {}".format(kwargs['timestamp'], kwargs['name']))

browser = pychrome.Browser()
tab = browser.new_tab()

tab.Page.lifecycleEvent = lifecycleEvent

tab.start()
tab.Page.enable()

try:
    tab.Page.setLifecycleEventsEnabled(enabled=True)
except pychrome.exceptions.CallMethodException:
    pass

tab.Page.navigate(url="http://localhost/load_event.html")
tab.wait(60)
```

{% img http://static.fatezero.org/blog/img/web-scanner-crawler-02/carbon.png 350  %}


下面我们简单地介绍一下上面几个我们会用到的事件

| 事件 | 解释 |
| --- | --- |
| DOMContentLoaded | 一般表示 DOM 和 CSSOM 均准备就绪的时间点 |
| networkAlmostIdle | 当前网络连接数少于 2 后触发 |
| networkIdle | 当前没有网络连接后触发 |
| load | 网页所有资源载入后触发，浏览器上加载转环停止旋转 |

之前解释过 `load` 事件可能对我们来说太晚了，但是现在 `DOMContentLoaded` 事件对我们来说又太早了，因为用户代码也可能会绑定这个事件然后操作 DOM，我们肯定是希望能够在页面稳定之后再注入我们的代码，所以在 `load` 和 `DOMContentLoaded` 之间某个时间点对我们来说比较合适，可惜并没有这样一个特别的事件存在，所以我个人觉得比较好的方案是将上面各个事件结合一起使用。

我们先说一下这几个事件的触发顺序，首先这几个事件触发顺序不一定，例如触发时间 `load` 事件不一定比 `DOMContentLoaded` 晚，`load` 也不一定比 `networkAlmostIdle` 晚。唯一能确定的就是 `networkAlmostIdle` 一定比 `networkIdle` 晚。在一般的情况下时间顺序是 `DOMContentLoaded` -> `networkAlmostIdle` -> `networkIdle` -> `load`。

所以一般的解决方案：
1. 等待 `load`，同时设定等待超时时间，`load` 超时直接注入代码，同时等待 `DOMContentLoaded` 事件
2. `DOMContentLoaded` 事件触发，接着等待 `networkAlmostIdle`，同时设定等待超时时间，超时直接注入代码
3. `networkAlmostIdle` 事件触发，接着等待 `networkIdle` 同时设定等待超时时间，超时直接注入代码

如果 `load` 事件在其他事件前触发，那就直接注入代码。

## 0x02 DOM 构建前

解决了在什么时候注入 JavaScript 代码的问题，接下来我们该开始考虑第一阶段该注入什么代码了。

由于在第一阶段的时间点，DOM 树还未构建，所以我们所注入的代码均不能操作 DOM，能干的事情也就只有 Hook、备份 BOM 中的函数。

#### basic

我们先把一些会导致页面阻塞、关闭的函数给 Hook 了，例如:

```js
window.alert = function () { return false; };
window.prompt = function (msg, input) { return input; };
window.confirm = function () { return true; };
window.close = function () { return false; };
```

同时也需要在 CDP 中处理 `Page.javascriptDialogOpening` 事件，因为还有类似 `onbeforeunload` 这样的弹窗。

#### location
还记得我们上一篇通过修改 Chromium 代码将 `location` 变成可伪造的事情了吗？就是为了能够在这里对 `location` 直接 Hook，直接看代码：

```js
var oldLocation = window.location;
var fakeLocation = Object();
fakeLocation.replace = fakeLocation.assign = function (value) {
    console.log("new link: " + value);
};
fakeLocation.reload = function () {};
fakeLocation.toString = function () {
    return oldLocation.toString();
};
Object.defineProperties(fakeLocation, {
    'href': {
        'get': function () { return oldLocation.href; },
        'set': function (value) { console.log("new link: " + value); }
    },
    // hash, host, hostname ...
});
var replaceLocation = function (obj) {
    Object.defineProperty(obj, 'location', {
        'get': function () { return fakeLocation; },
        'set': function (value) { console.log("new link: " + value); }
    });
};

replaceLocation(window);
addEventListener('DOMContentLoaded', function () {
    replaceLocation(document);
})
```

这里还需要注意的是 `doucment.location` 需要等待 DOM 构建结束之后才能 hook, 所以需要注册 `DOMContentLoaded` 事件来 hook `document.location`。

#### 网络

因为之前我们修改了 `Chromium` 代码使得 `window.open` 无法新建窗口，这样在 CDP 中也没法获取 `window.open` 想打开的链接信息，所以我们还需要在代码中 Hook `window.open` 函数：
```js
window.open = function(url) { console.log("new link: " + url); };
```

还有我们比较常用的 AJAX：

``` js
window.XMLHttpRequest.prototype.send = function (data) {
    // 记录发送的数据，注意 data 可能是 raw data 
};
window.XMLHttpRequest.prototype.open = function (method, url, async, user, password) {
    // 记录 method, url 等信息
};
window.XMLHttpRequest.prototype.setRequestHeader = function (header, value) {
    // 记录 header
};
window.XMLHttpRequest.prototype.abort = function () {};
```

hook XHR 时要考虑的问题就是在 XHR 正在发送请求的时候，需不需要暂停我们的其他操作（如触发事件）？ 
我们注入的代码的下一个操作可能会中断正在发送的 XHR 请求，导致更多链接的丢失，
比较典型的例子就是：[AJAX Demo](http://testphp.vulnweb.com/AJAX/index.php)，这个问题没有标准答案。

`WebSocket`、`EventSource`、`fetch` 和 XHR 差不多：

``` js
var oldWebSocket = window.WebSocket;
window.WebSocket = function(url, arg) {
    console.log("new link: " + url);
    return new oldWebSocket(url, arg);
}

var oldEventSource = window.EventSource;
window.EventSource = function(url) {
    console.log("new link: " + url);
    return new oldEventSource(url);
}

var oldFetch = window.fetch;
window.fetch = function(url) {
    console.log("new link: " + url);
    return oldFetch(url);
}
```
#### 时间

我们还需要 hook 两个定时器函数：

* `setTimeout`
* `setInterval`

因为可能用户代码会延迟或者定期做一些操作，我们可能等不来那么长的时间，所以我们要给这些定时器做一个加速，
也就是 Hook 之后修改相对应的 delay 为更小的值，同时加速之后也要 hook `Date` 类来同步时间。

#### 锁定

我们可以 hook 这些函数，那么其他人也可以继续 hook 这些函数，但一般对这些函数进行 hook 的人都不是什么好人，
被别人继续 hook 之后可能会影响到我们的代码，所以我们还需要锁定这些基础函数。

例子：
```js
window.open = function(url) { console.log('hook before defineProperty'); }
Object.defineProperty(window, 'open', {
    value: window.open,
    writable: false,
    configurable: false,
    enumerable: true
});
window.open = function(url) { console.log('hook after defineProperty'); }

window.open('http://www.fatezero.org')
```

结果：
```sh
hook before defineProperty
```

第一阶段我们能做的事情也做得差不多了，剩下的事情就交给第二阶段的代码干了。

## 0x03 遍历节点

第二阶段，也就是页面稳定后，我们肯定是要先遍历 DOM 中的各个节点，
然后才能获取节点上的链接信息，以及触发节点上绑定的事件，所以这里我们看一下获取 DOM 中所有的节点，有哪些方法：

* CDP 的 `DOM.querySelectorAll`
* document.all
* document.querySelectorAll
* TreeWalker

我们一个一个的排除，
首先排除 CDP，因为如果使用 CDP 遍历各个节点，那就意味着后续的对节点的操作也要继续使用 CDP 才能进行，其速度远没有在一个 Context 内的代码操作 DOM 快。
接着排除 `document.all`(`HTMLAllCollection`，动态元素集合) 和 `document.querySelectorAll`(`NodeList`, 静态元素集合)，因为这两个都只是元素集合，而不是节点集合，
并不包含 text, comment 节点。最后就剩下 TreeWalker 了。

TreeWalker 也有两种玩法，一种是先获取所有的节点，然后在触发各个节点上的事件，另外一种是边遍历节点，边触发事件。

可能会有同学觉得第二种方法比较优雅，我们看一下使用第二种方法的一种情况：
```html
<div id="container">
<a id="a1">hello a1</a><br>
<a id="a2" onclick="removeA2()">hello a2</a><br>
<a id="a3">hello a3</a><br>
</div>

<script>
function removeA2() {
    var c = document.getElementById('container');
    c.removeChild(document.getElementById('a2'));
}

function treeWalkerFilter(element) {
    if (element.nodeType === Node.ELEMENT_NODE) {
        return NodeFilter.FILTER_ACCEPT;
    }
}

treeWalker = document.createTreeWalker(
    document,
    NodeFilter.SHOW_ELEMENT,
    treeWalkerFilter,
    false
);

while (treeWalker.nextNode()) {
    console.log("[*] processing node " + treeWalker.currentNode.tagName + ' ' + treeWalker.currentNode.id);
    if (treeWalker.currentNode.click) {
        treeWalker.currentNode.click();
    }
}
console.log(treeWalker.currentNode);
</script>
```

结果：

{% img http://static.fatezero.org/blog/img/web-scanner-crawler-02/treewalker.png 400  %}


是的，如果 TreeWalker 刚好走到一个节点，触发了事件使得该节点离开了 DOM 树，那 TreeWalker 就走不下去了，
所以比较保险的方法就是在页面稳定后收集一份静态的节点列表，再触发事件，也就是使用 `TreeWalker` 的第一种玩法。

## 0x04 事件触发

在收集到一份静态节点列表，获取静态节点列表的链接信息之后，我们就该考虑一下如何触发各个节点上的事件了。

首先，我们来谈一下如何触发鼠标、键盘相关的事件，主要方法有两：

* `dispatchEvent`
* CDP 的 `Input.dispatchMouseEvent`

我们使用一个简单的例子看一下两者最大的差别：

```html
<button id="test" onclick="testEventTrusted(event)">click</button>
<script>
function testEventTrusted(event) {
    if ("isTrusted" in event) {
        if (event.isTrusted) {
            console.log("trusted");
        } else {
            console.log("not trusted");
        }
    } else {
        console.log("not support");
    }
}
</script>
```

使用 CDP 测试两者区别：

``` python
import pychrome

browser = pychrome.Browser()

tab = browser.new_tab()

tab.start()
tab.Page.navigate(url="http://localhost/test.html")

tab.Runtime.enable()
tab.Runtime.evaluate(expression="console.log('js click: ')")
tab.Runtime.evaluate(expression="var e = new MouseEvent('click');test.dispatchEvent(e);", _timeout=5)

result = tab.Runtime.evaluate(expression='test', _timeout=5)

btn_object_id = result['result']['objectId']
result = tab.DOM.getBoxModel(objectId=btn_object_id)

border = result['model']['border']

odd = [value for i, value in enumerate(border) if i % 2 == 1]
even = [value for i, value in enumerate(border) if i % 2 == 0]

x = min(even)
y = min(odd)
width = max(even) - x
height = max(odd) - y

x += width / 2
y += height / 2

tab.Runtime.evaluate(expression="console.log('cdp click: ')")
tab.Input.dispatchMouseEvent(type="mousePressed", x=x, y=y, button='left', clickCount=1)
tab.Input.dispatchMouseEvent(type="mouseReleased", x=x, y=y, button='left', clickCount=1)
```

结果：

{% img http://static.fatezero.org/blog/img/web-scanner-crawler-02/event_js_and_cdp_result.png 280  %}

`dispatchEvent` 和 `Input.dispatchMouseEvent` 这两者最大的区别就是事件来源是否是真实的用户点击，
虽说 `isTrusted` 也就是一个改 Chromium 代码就能解决的问题，但我们也没法保证还有没有其他黑科技来检测是否事件是否来自真实用户。
然而我还是觉得 CDP 实在太慢，所以还是继续选择使用 `dispatchEvent` 来触发各种事件。

接下来我们要考虑一下如何使用 `dispatchEvent` 触发事件，
可能有些同学觉得，我们可以扫描所有元素节点，收集内联事件，对于动态添加的事件，可以 Hook `addEventListener` 获取到，
最后再挨个触发元素相对应的事件，其实这样做是有问题的。

我们还是先看看一个例子：
```html
<div id="container" onclick="btnClick(event)">
    <button id="btn1">click1</button>
    <button id="btn2">click2</button>
</div>

<script>
    function btnClick(e) {
        console.log('click: ' + e.target.id);
    }
</script>
```
例子将事件绑定在 container 内，等事件冒泡到 container，再通过 event.target 区分元素。
如果按照之前的思路，我们的代码将会在 container 中触发一个点击事件，而忽略了 container 下的两个按钮，所以之前的思路并不合理。

我个人的想法是，每个元素都只触发常用的事件，比如说 `click`、`dbclick`、`mouseover` 等事件，忽略一些非主流事件。
只触发常见的键盘、鼠标事件让我们的行为更像是一个正常人类的行为，这样也减少了被反爬虫机制带入坑的可能性。
另外，说到爬虫行为做到和正常人类类似，还有一个小细节，那就是元素是否在可见区域，
以前都是直接将浏览器的 viewpoint 设置最大，现在我们使用 `element.scrollIntoViewIfNeeded` 将滚动条滚动到元素的位置，然后再触发事件。

## 0x05 新节点

那么问题又来了，由于我们各种点击、敲击键盘、尝试触发各种操作而产生新的节点，我们该怎么办？
肯定还是要继续处理这些新节点，但是怎么找到这些新节点，难道还要重新再扫一遍 DOM 查找新节点？
有没有一个方法可以获取到变化的属性和节点？

在 HTML5 中就刚好有这么一个类 `MutationObserver`，我们看看例子：

```html

<button id="btn1" onclick="createE()">create element</button>
<button id="btn2" onclick="changeA()">change attr</button>

<div id="container">
<form id="form1" action="/">
</form>
</div>

<script>
    btn1.onclick = function() {
        var container = document.getElementById('container');
        var eA = document.createElement('a');
        eA.href = "http://www.fatezero.org";
        container.appendChild(eA);
    };

    btn2.onclick = function () {
        form1.action = "http://www.fatezero.org/form";
    };

    var observer = new MutationObserver(function(mutations ){
        mutations.forEach(function (mutation) {
            if (mutation.type === 'childList') {
                // 在创建新的 element 时调用
                console.log("child list: ");
                console.log(mutation);
            } else if (mutation.type === 'attributes') {
                // 在属性发生变化时调用
                console.log("attributes: ");
                console.log(mutation);
            }
        });
    });

    observer.observe(window.document, {
        subtree: true,
        childList: true,
        attributes: true,
        attributeFilter: ['src', 'href', 'action']
    });
</script>
```

按顺序点击 btn1 和 btn2 的结果：

{% img http://static.fatezero.org/blog/img/web-scanner-crawler-02/mutation_observer_result.png 600  %}

所以我们完全可以利用 `MutationObserver` 作深度优先的扫描，如果弹出新的节点，那就优先处理新的节点。每次都是先静态扫描新的节点列表，然后再尝试触发新增节点列表的事件。

但是值得注意的是 `MutationObserver` 并不会实时将变更元素传回来，而是收集一个时间段的元素再传回来，所以未能及时切换到新的节点继续触发事件也是正常的事情。

## 0x06 自动填写表单

OK，事件我们触发了，新节点我们也处理了，这里我们还需要对一些元素进行特殊处理，比如说自动填写表单内的输入元素。

这一小节没什么难度，主要是判定哪些地方该填名字，哪些地方该填邮箱，哪些地方该填号码，
需要根据不同情况输入对应的数据。另外还要注意的是在填写数据的时候还要触发对应的事件，例如填写 `<input type="text">` 的时候，
我们需要把鼠标移动到 `input` 元素上，对应触发 `mouseover`、`mouseenter`、`mousemove` 消息，
接着要鼠标点击一下输入点，对应 `mousedown`、`mouseup`、`click` 消息，
然后鼠标移开转到其他元素去，对应 `mousemove`、`mouseout`、`mouseleave` 消息。

这里还有个小建议，所有的用户输入都带上一个可识别的词，
例如我们自定义词为 CasterJS，email 处就填写 `casterjs @gmail.com`， addr 处就写 `casterjs road`， 至于为什么下一篇再说。 

## 0x07 CDP

这一个小结主要和 CDP 相关的 TIP ，使用什么语言操控 CDP 都行，在这里我选择我比较熟悉的 Python 作为解释。

#### 自定义 request

CDP 在 navigate 的时候并不能直接自定义 request，通俗的讲就是在 navigate 的时候并不能设置 method 和 headers 等信息，
但很明显这个功能对我们的扫描器来说非常重要。幸运的是，虽然 CDP 没有直接支持这样的功能，但可以通过 `Network.requestIntercepted` 
变向实现这样的功能。

代码如下:

``` python
import time
import pychrome

def request_intercepted(interceptionId, request, **kwargs):
    headers = request.get('headers', {})
    headers['Test-key'] = 'test-value'

    tab.Network.continueInterceptedRequest(
        interceptionId=interceptionId,
        headers=headers,
        method='POST',
        postData="hello post data: %s" % time.time()
    )

browser = pychrome.Browser()
tab = browser.new_tab()

tab.Network.requestIntercepted = request_intercepted

tab.start()
try:
    tab.Network.setRequestInterception(patterns=[{'urlPattern': '*', 'resourceType': 'Document'}])
except pychrome.exceptions.CallMethodException:
    tab.Network.setRequestInterceptionEnabled(enabled=True)

tab.Page.navigate(url="http://httpbin.org/post")

tab.wait(3)

result = tab.Runtime.evaluate(expression="document.documentElement.outerText")
html_content = result.get('result', {}).get('value', "")
print(html_content)
```

结果：

``` json
{
  "args": {}, 
  "data": "hello post data: 1521343371.056448", 
  "files": {}, 
  "form": {}, 
  "headers": {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", 
    "Accept-Encoding": "gzip, deflate", 
    "Connection": "close", 
    "Content-Length": "34", 
    "Host": "httpbin.org", 
    "Test-Key": "test-value", 
    "Upgrade-Insecure-Requests": "1", 
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/63.0.3239.150 Safari/537.36"
  }, 
  "json": null, 
  "origin": "1.1.1.1", 
  "url": "http://httpbin.org/post"
}
```

#### 网络优化

我们的浏览器是肯定需要加载 css 和 js 的，那其他网络资源如图片、视频等媒体资源是不是可以直接禁止加载？
其实这样做并不合理，直接禁用图片等资源可能会影响到用户代码执行逻辑，例如我们常见的 `<img src=1 onerror=alert(1)>`，
所以比较好的解决方法就是返回假的媒体资源。

代码如下：

``` python
import pychrome
import pychrome.exceptions

image_raw_response = ('SFRUUC8xLjEgMjAwIE9LCkNvbnRlbnQtVHlwZTogaW1hZ2UvcG5nCgqJUE5HDQoaCgAAAA1JSERSAAAAAQ'
                      'AAAAEBAwAAACXbVsoAAAAGUExURczMzP///9ONFXYAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAAKSURBVAiZY'
                      '2AAAAACAAH0cWSmAAAAAElFTkSuQmCC')


def requestIntercepted(**kwargs):
    global image_raw_response
    resource_type = kwargs.get('resourceType', 'other').lower()
    interception_id = kwargs.get('interceptionId')

    if resource_type == 'image':
        tab.Network.continueInterceptedRequest(
            interceptionId=interception_id,
            rawResponse=image_raw_response,
            _timeout=5,
        )
    else:
        tab.Network.continueInterceptedRequest(
            interceptionId=interception_id,
            _timeout=5,
        )


browser = pychrome.Browser()
tab = browser.new_tab()

tab.Network.requestIntercepted = requestIntercepted

tab.start()
tab.Page.enable()

try:
    tab.Network.setRequestInterception(patterns=[{'urlPattern': '*', 'resourceType': 'Image'}])
except pychrome.exceptions.CallMethodException:
    tab.Network.setRequestInterceptionEnabled(enabled=True)

tab.Page.navigate(url="https://weibo.com/fatez3r0")
tab.wait(60)
```

{% img http://static.fatezero.org/blog/img/web-scanner-crawler-02/replace_images.png 700  %}


#### session isolate

我们的扫描器可能会有使用不同用户信息扫描同一个域名的情况，
我们肯定不希望在同一个 browser 下，不同 tab 的 Cookie 信息等串在一起，
我们希望每个 tab 都有一个隐身模式，每个 tab 都资源互不影响，
比较走运的是 Headless Chrome 刚好有这么一个功能，叫 session isolate ，也是 Headless 模式下独有的功能。

我们看一下 Headless 模式的 session isolate 功能的简单例子:

``` python
import pychrome

browser = pychrome.Browser()
version_info = browser.version()

target = pychrome.Tab(webSocketDebuggerUrl=version_info['webSocketDebuggerUrl'], id='1')

target.start()
tab0 = browser.new_tab(url="http://httpbin.org/cookies/set?browser=here_is_fate0")

# 1. 尝试注释下面这行
browser_context_id1 = target.Target.createBrowserContext()['browserContextId']
target_id1 = target.Target.createTarget(
    url="http://httpbin.org/cookies",
    # 2. 以及这行
    browserContextId=browser_context_id1
)['targetId']


tab1 = pychrome.Tab(
    id=target_id1,
    webSocketDebuggerUrl='ws://127.0.0.1:9222/devtools/page/{}'.format(target_id1)
)
tab1.start()
tab1.Runtime.enable()
print(tab1.Runtime.evaluate(expression='document.documentElement.outerText'))
```

运行结果：
``` sh
{'result': {'type': 'string', 'value': '{\n  "cookies": {}\n}\n'}}
```

如果注释 1、2 两行，运行结果：
```sh
{'result': {'type': 'string', 'value': '{\n  "cookies": {\n    "browser": "here_is_fate0"\n  }\n}\n'}}
```

所以只要每个 tab 都新建一个 `BrowserContext` 就可以做到互不干扰了，
这也就相当于每个 tab 都是一个独立的隐身模式，能够做到每个 tab 互不影响，
也可以共用一个 `BrowserContext` 达到共享 cache、cookie 之类信息的功能。

#### 安全问题

从 chromium 62 开始存在一个安全问题，在使用 `remote-debugging-port` 参数的时候可以系统上任意写文件，
我已经提交安全 [issue](https://bugs.chromium.org/p/chromium/issues/detail?id=824816) 给 chromium，
可惜撞洞了，有人比我早了一个月提交了[相关漏洞](https://bugs.chromium.org/p/chromium/issues/detail?id=813540)，
所以在选定 chromium 版本的时候要注意跳过这些版本或者自行修复这些问题。

## 0x08 结合

讲了那么多，是时候该把所有的东西结合在一起，我们先简单捋一下执行过程：

1. 注入 Hook 相关的 JavaScript 代码
2. 使用 TreeWalker 遍历节点，收集节点链接信息，获取静态的节点列表
3. 触发各个节点的相关操作，自动填写表单
4. MutationObserver 监控动态节点创建，优先处理新节点

我们以 `http://testphp.vulnweb.com/AJAX/index.php` 作为例子跑一遍，看一下我们代码的执行状况，
为了更方便的展示，我将每个节点（触发事件）的处理时间都额外增加了 0.1s，同时也给所有节点都加上了边框，蓝色边框表示正在处理的节点。

测试视频如下：
<video src='http://static.fatezero.org/blog/video/web-scanner-crawler-02/vulnweb_test.mov' type='video/mov' controls='controls'  width='100%' height='100%'>
</video>

通过加边框和打 log 的方式，我们完全可以一步一步的看着爬虫的操作是否符合我们的预期。这个例子的结果证明了:
* xhr 的 hook（不被其他 xhr 中断）
* 事件的触发（新节点的产生）
* `MutationObserver` 的监控（正确处理新节点）
* 图片资源的处理（原始图片被替换）
* 窗口的处理（没有弹 alert 窗）

上面的行为是符合我们的预期的。

目前第一篇和第二篇的内容总算是组合在了一起，成为了一个能够独立运行、测试的组件，该组件所提供的功能就是输入一个 request 相关的信息，返回 response 中所有的链接信息，
如果我们的爬虫存在链接信息漏抓，那很可能就是这部分出问题，所以也只需要调试这部分代码即可，非常方便。

该组件可以通过stdin/stdout、RPC、消息队列等方式传递任务和结果。
可以通过在单台机器上多开 tab 达到纵向扩展，也可以在多台机器上启多个 browser 达到横向扩展，这部分各自有自个的想法，不会就这个方向继续写下去了。

## 0x09 总结

至此，Web 漏洞扫描器爬虫中的 `Downloader` 这部分我已经简单地介绍了一遍，
对照一下我自己的代码，也深知这部分我并没有讲全，因为这部分坑多，内容也乱且多，但是再写下去就真的没完没了，看着累，写着更累，得赶紧切到下一个话题。

[下一篇](#)，我将会继续介绍爬虫的调度部分以及整体架构。

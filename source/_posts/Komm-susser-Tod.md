---
title: 'Komm, süsser Tod'
date: 2016-12-21 22:53:27
mathjax: true
---


这篇文章的意义在于测试这个主题所支持的功能

<!--more-->


## 测试 MarkDown 功能

#### 0x1. 表格

| 靠左表头 | 居中表头 | 靠右表头 | 
|:---- | :----: |-----:|
| `content`| 内容 | $a=1$|
| *内容* | $a^3$ | **内容** |


#### 0x2. 代码

这里是代码块

``` python
import sys

print("hello world")
```

这里是行内代码 `print("hello world")`

#### 0x3. 引用

> 这里是引用
> 第二行引用


#### 0x4. 链接

[我的博客](http://blog.fatezero.org)
[我的wiki](http://wiki.fatezero.org)


#### 0x5. 图片

![privateinvestocat](https://octodex.github.com/images/privateinvestocat.jpg)


## 测试 mathjax

这里是数学公式块

{% raw %}
$$
        \begin{matrix}
        1 & x & x^2 \\
        1 & y & y^2 \\
        1 & z & z^2 \\
        \end{matrix}
$$
{% endraw %}

这个是行内数学公式 $\sqrt[4]{\frac xy}$


## 测试 Hexo 功能

#### 0x1 iframe

{% iframe //music.163.com/outchain/player?type=2&id=31365696&auto=0&height=66 500 86%}

#### 0x2 img

{% img https://octodex.github.com/images/privateinvestocat.jpg 200 200 %}
一般使用 Hexo 内的图片 tag, 因为可以调整图片大小

#### 0x3 raw

```
{% raw %}
content
{% endraw %}
```

#### 0x4 主题 tip
<div class="tip">
    这个是主题带的 tip
</div>



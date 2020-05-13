# XSS_Cheat_Sheet_2020_Edition

## 简介
xss漏洞模糊测试有效载荷的最佳集合 2020版 <br>
该备忘清单可用于，漏洞猎人，安全分析，渗透测试人员，查找web应用的跨站点脚本漏洞 <br>
本备忘录翻译自国外的XSS_Cheat_Sheet_2020_Edition.pdf议题，源文件可在本项目内直接下载 <br>

## 摘要
1.基本 <br>
2.高级 <br>
3.绕过 <br>
4.利用 <br>
5.额外 <br>
6.枚举 <br>

## 内容
**1.HTML Injection （代码注入）**
当输入的payload，被插入到HTML标签或外部标签的属性值内时，则使用
下面的方法进行测试，如果输入的内容被插入到了HTML注释，则在payload之前添加"->"
```
<svg onload=alert(1)>
"><svg onload=alert(1)>
```




# 介绍

gokart二开项目，其实原项目是做了一半的半成品，上次更新已经是在两三年前了，然后在24年4月10日关闭了。

之前看了南大的软件分析课程，感觉很有趣，但java的SAST例子和工具有不少了，好奇go的SAST该怎么写，所以做此项目。

做了以下改进：

1. 优化CallGraph的初始化 ✅
2. 修改生成污点的算法（不支持多路污点），且会出现长路径覆盖短路径的情况。✅
3. 解决不支持跨包调用 ✅
4. 增加多态的分析（接口类型）✅
5. 修复结构体嵌套检测不到的bug ✅
6. 支持闭包分析的部分情况 (普通闭包测试✅ 嵌套闭包测试✅ 使用外部变量的闭包✅)  ✅
7. \*ssa.parameter 修复 ✅
8. 优化source和sink，特别是web的source ✅
9. 支持嵌入式字段的分析 ✅
10. 结果输出优化 ✅
11. 引用传递问题, （测试了当前热度最高的go SAST工具gosec，看起来也没有解决得很好，所以我就放心的写自己的逻辑了）✅
12. 多路算法bug修复（如BinOP等分路的污点分析）✅
13. 添加对MakeMap的支持 ✅
14. 修复go高版本无法运行的bug ✅
15. 修复处理Slice的算法 ✅ 
16. 一些性能优化 ✅
17. 高阶函数为参数的情况。（不是很会）



添加了-w（WebMode参数），支持web项目的扫描。

由于go web框架众多，这里只测试了go gin和beego两框架，未来会看着添加。（主要懒得写测试靶场）



-v参数会显示详细路径，如果出现一个sink，多path的情况，请添加-v参数查看具体的path。（默认只显示一条）



使用例：

`./gokart scan /path/to/project/ -v `

详细使用方法参考原项目：

https://github.com/praetorian-inc/gokart



参考：

https://github.com/JackOfMostTrades/gadgetinspector

https://github.com/Eugeny/tabby

https://www.bilibili.com/video/BV1b7411K7P4/



测试通过的靶场：

https://github.com/godzeo/go-gin-vul/

https://github.com/cokeBeer/go-sec-code



本项目处于测试阶段，欢迎提交各种bug，漏报误报的issue




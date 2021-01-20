1、说明

该工具主要用于指纹识别后，进行漏洞精准扫描。

2、命令使用

    poc.exe	-h	//查看帮助
    poc.exe -l	//列举可用的检测列表
    poc.exe -m smart -f url.txt	//通过智能模式识别相应的指纹（目前只针对web指纹识别），进行精准poc插件调用
    poc.exe -m all -f url.txt	//通过遍历所有的PoC插件进行漏洞扫描

3、参数详解

    -f string	//URL请求链接文件。
    -l			//获取poc检测能力列表。
    -m string	//选择扫描模式，smart为智能模式；all为暴力扫描模式；'DSO-00001'、'DSO-00001|DSO-00002'，指定一个或多个poc进行扫描 。 (default "smart")
    -o string	//保存的扫描结果文件。 (default "Result.json")
    -t int		//并发线程数。 (default 20)
    -u string	//URL请求链接。



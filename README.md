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

4、检测列表

```
DSO-00010:Apache Tomcat 管理后台弱口令
DSO-00011:JBoss 管理后台弱口令
DSO-00012:Weblogic 管理后台弱口令
DSO-00013:Resin 管理后台弱口令
DSO-00014:IBM WebSphere 管理后台弱口令
DSO-00019:Apache Axis2 管理后台弱口令
DSO-00020:Apache Tomcat 测试页面泄露
DSO-00021:Apache Axis2 敏感信息泄露
DSO-00022:IIS WebDav存在任意文件上传
DSO-00023:GlassFish 任意文件读取
DSO-00024:网站.git目录代码泄露
DSO-00025:网站.svn目录代码泄露
DSO-00026:Apache Solr 未授权访问
DSO-00027:HTTP Proxy Check
DSO-00029:Apache Zookeeper 未授权访问
DSO-00030:Redis 未授权访问
DSO-00031:Memcached 信息泄露漏洞
DSO-00032:JBoss 敏感信息泄露
DSO-00033:MongoDB 未授权访问
DSO-00034:JBoss Head认证绕过上传任意文件漏洞
DSO-00035:Apache Struts2 DevMode远程代码执行漏洞(S2-008)
DSO-00036:Resin 任意文件读取
DSO-00037:JBoss invoker代码执行漏洞
DSO-00038:ManageEngine Applications Manager 管理后台默认口令
DSO-00039:Jenkins Script 未授权访问
DSO-00040:Apache Struts2 多个旧版本远程代码执行漏洞[8]
DSO-00041:Weblogic T3协议未限制访问漏洞
DSO-00042:Elasticsearch 未授权访问
DSO-00043:Zabbix jsrpc SQL注入漏洞
DSO-00044:Zabbix latest SQL注入漏洞
DSO-00045:Java Debugger 远程命令执行漏洞
DSO-00046:OpenSSL 1.0.1 内存读取信息泄露漏洞
DSO-00047:Elasticsearch 远程任意代码执行漏洞
DSO-00048:Weblogic 服务端请求伪造攻击漏洞
DSO-00049:Bash 4.3 远程命令执行漏洞
DSO-00050:Elasticsearch Groovy Scripting Engine Sandbox 安全绕过漏洞
DSO-00051:HTTP.sys 远程代码执行漏洞
DSO-00052:Apache ActiveMQ 未认证存在任意文件上传
DSO-00053:Jetty 信息泄露
DSO-00054:Elasticsearch 路径遍历漏洞
DSO-00055:IBM WebSphere Java反序列化漏洞
DSO-00056:Elasticsearch 目录穿越漏洞
DSO-00057:Atlassian Confluence 任意文件读取漏洞
DSO-00058:Apache Shiro <=1.2.4 远程代码执行
DSO-00059:Windows SMB 远程命令执行漏洞(MS17-010)
DSO-00060:Jenkins Java反序列化漏洞
DSO-00061:Weblogic wls-wsat代码执行漏洞
DSO-00062:Apache Tomcat PUT任意写文件漏洞
DSO-00063:Java RMI 反序列化代码执行漏洞
DSO-00064:Apache Struts2 远程代码执行漏洞(S2-045/046)
DSO-00065:IIS 6.0 远程命令执行漏洞
DSO-00066:Apache Struts2 远程代码执行漏洞(S2-052)
DSO-00068:Weblogic RMI接口类型验证绕过反序列化漏洞
DSO-00069:ThinkPHP 5.0.23/5.1.31 远程代码执行
DSO-00070:Docker Remote API 未授权访问
DSO-00071:DNS 域传送漏洞
DSO-00072:Adobe ColdFusion enter.cfm 任意文件读取漏洞
DSO-00075:Apache Roller 外部实体注入漏洞
DSO-00078:Supervisord 远程命令执行漏洞
DSO-00079:Apache CouchDB 未认证远程命令执行
DSO-00080:node.js 路径遍历漏洞
DSO-00082:HP智能管理平台 远程代码执行漏洞
DSO-00083:Cisco ASA 目录遍历漏洞
DSO-00085:Apache Struts2 远程代码执行漏洞(S2-057)
DSO-00086:Apache Pluto 远程代码执行漏洞
DSO-00088:Weblogic WLS核心组件（T3协议）反序列化漏洞
DSO-00089:Weblogic 内置应用ws_utc任意文件上传漏洞
DSO-00090:uWSGI 目录穿越漏洞
DSO-00093:Apache Hadoop Map/Reduce 未授权访问
DSO-00094:Apache HBase 未授权访问
DSO-00095:Apache Hadoop 未授权访问
DSO-00096:Apache Hadoop Yarn 资源管理系统RESTAPI未授权访问
DSO-00097:Apache Spark 未授权访问
DSO-00098:Gitlist <=0.4.0 远程命令执行漏洞
DSO-00099:InfluxDB 未授权访问
DSO-00100:星网锐捷 SVG 6000 管理后台默认口令
DSO-00101:Apache Syncope console 默认口令
DSO-00102:Dell iDRAC 系统管理默认口令
DSO-00103:H2 DataBase 任意代码执行漏洞
DSO-00104:H3C ER3108G 系统管理默认口令
DSO-00105:Harbor 管理后台弱口令
DSO-00106:HP智能管理平台 默认口令
DSO-00107:Jenkins 任意文件读取漏洞
DSO-00108:Jupyter Notebook 未授权访问
DSO-00109:OrientDB 管理后台弱口令
DSO-00110:RabbitMQ 管理后台弱口令
DSO-00113:Smartbi Insight 大数据分析平台默认口令
DSO-00114:Smartbi Insight 大数据分析平台SQL注入漏洞
DSO-00116:安财软件 GetFile 任意文件读取漏洞
DSO-00123:phpMyAdmin 反序列化漏洞
DSO-00124:PhpStorm XDebug 远程调试代码执行漏洞
DSO-00127:SoftNAS Cloud OS命令注入漏洞
DSO-00128:SonarQube 管理后台弱口令
DSO-00129:天融信防火墙 默认口令
DSO-00132:Nexus 仓库管理用户弱口令
DSO-00133:HUAWEI 防火墙 & VPN 网关 Web 管理后台弱口令
DSO-00134:GlassFish 管理后台弱口令
DSO-00136:eWebEditor 弱口令
DSO-00137:Jupyter Notebook 弱口令
DSO-00147:ThinkPHP 5.0.23 method远程代码执行
DSO-00148:ThinkPHP 5.x filter远程代码执行
DSO-00150:JBoss jmx-console 未授权访问
DSO-00204:Zabbix 默认弱口令
DSO-00294:phpMoAdmin 任意代码执行漏洞
DSO-00297:FCKeditor 2.4.2 PHP版本任意文件上传漏洞
DSO-00374:phpStudy 弱密码漏洞
DSO-00389:PHPCMS V9 referer SQL注入漏洞
DSO-00470:Zabbix jsrpc.php SQL注入漏洞
DSO-00604:欧虎政务系统 custom_design.php 任意文件写入漏洞
DSO-00617:PHP PHP-CGI 远程代码执行漏洞
DSO-00632:璐华企业版 OA 系统多处 SQL注入漏洞
DSO-00657:HTTPOXY 远程代理感染漏洞
DSO-00667:IIS 短文件名泄露漏洞
DSO-00688:Apache Geronimo 默认管理密码
DSO-00689:Apache OPTIONS 存在内存泄漏漏洞
DSO-00700:KindEditor 存在目录遍历漏洞
DSO-00701:KindEditor 存在文件上传漏洞
DSO-00703:phpMyAdmin 管理后台弱口令
DSO-00704:CactiEZ WeatherMap 任意文件写入漏洞
DSO-00707:Apache Dubbo 未授权访问
DSO-00708:Apache Druid Console 未授权访问
DSO-00709:Nexus Repository Manager <=3.14.0 远程代码执行漏洞
DSO-00710:Nginx 整数溢出漏洞(CVE-2017-7529)
DSO-00728:FastCGI 文件读取漏洞
DSO-00799:Gitlab 多个版本导入项目功能目录遍历漏洞
DSO-00800:Spring Security OAuth2 <= 2.0.9 远程代码执行漏洞
DSO-00802:PHPUnit 远程代码执行漏洞
DSO-00803:Ruby On Rails 路径穿越漏洞(CVE-2018-3760)
DSO-00805:Flask Jinja2 服务端存在模板注入漏洞
DSO-00808:Apache Tika-server <1.18 存在命令执行漏洞
DSO-00820:Windows RDP 协议远程代码执行漏洞(MS12-020)
DSO-00827:通达OA /general/mytable/intel_view/video_file.php 存在任意文件下载漏洞
DSO-00848:通达OA /inc/finger/use_finger.php SQL注入漏洞
DSO-00880:金蝶OA comm_user.jsp SQL注入漏洞
DSO-00890:通达OA系统 upload.php SQL注入漏洞
DSO-00892:用友FE role_add_user.jsp SQL注入漏洞
DSO-00893:用友FE depReimburse.jsp SQL注入漏洞
DSO-00894:用友FE协同办公系统 file_publish_open.jsp SQL注入漏洞
DSO-00900:三才期刊系统 pdfdow.aspx 存在文件下载漏洞
DSO-00905:南京擎天政务系统 /inc/frame.htm 越权访问漏洞
DSO-00929:ThinkPHP 2.1/2.2/3.0 web框架代码执行漏洞
DSO-00931:安宁电子邮件系统 Mail login.php 存在文件包含漏洞
DSO-00959:金山防火墙 adsl_stat_dialog.php 远程命令执行漏洞
DSO-00961:中科网威防火墙 CommandsPolling.php 远程命令执行漏洞
DSO-00962:中科网威防火墙 CommandsPolling.php 文件读取漏洞
DSO-00966:正方协同办公系统 gwxxbviewhtml.do页面存在任意文件下载漏洞
DSO-00968:Atlassian Confluence Server 远程代码执行
DSO-00980:Apache Solr <= 7.0.1 XML实体注入漏洞
DSO-00983:Cisco RV320 信息泄露漏洞
DSO-00989:Apache Haus 默认页面信息泄露
DSO-00990:Apache Tomcat 默认页面信息泄露
DSO-01060:MikroTik RouterOS Winbox 任意文件读写漏洞
DSO-01072:用友FE协同办公系统 createprinttemplete.jsp SQL注入漏洞
DSO-01096:Weblogic wls9-async 组件反序列化漏洞
DSO-01097:KingdeeOA InstantMessage.jsp 存在SQL注入漏洞
DSO-01109:phpMyAdmin 4.8.1 存在本地文件包含漏洞
DSO-01110:Apache CouchDB 垂直权限绕过漏洞
DSO-01121:Apache Tomcat CGIServlet enableCmdLineArguments 远程代码执行漏洞
DSO-01128:万户OA download_netdisk.jsp 任意文件下载漏洞
DSO-01136:金蝶EAS /easoa/login/kingdee_sso_auth.jsp SQL注入漏洞
DSO-01138:泛微e-cology weaver.file.SignatureDownLoad SQL注入漏洞
DSO-01139:泛微e-cology weaver.file.SignatureDownLoad 文件下载漏洞
DSO-01144:万户ezOffice /defaultroot/Logon.do SQL注入漏洞
DSO-01145:用友FE codeMoreWidget.jsp 存在SQL注入漏洞
DSO-01156:网康NS-ASG安全网关 add_getlogin.php SQL注入漏洞
DSO-01159:万户ezOFFICE /defaultroot/extension/smartUpload.jsp 文件上传漏洞
DSO-01165:用友FE办公平台 ncsubjass.jsp 存在SQL注入漏洞
DSO-01166:金山防火墙 schedule.php 远程命令执行漏洞
DSO-01169:网康安全网关 NS-ASG Download.php 文件下载漏洞
DSO-01170:网康安全网关 show_logfile.php 命令执行漏洞
DSO-01177:用友e-HR ELTextFile.load.d 存在任意文件读取漏洞
DSO-01178:金山防火墙 viewauditmail.php SQL注入漏洞
DSO-01179:用友NC nc.itf.ses.inittool.SESInitToolService 信息泄露漏洞
DSO-01188:用友FE deptTreeXml.jsp 注入漏洞
DSO-01199:Jenkins 远程命令执行漏洞(CVE-2018-1000861)
DSO-01202:JBoss 5.x/6.x 反序列化漏洞(CVE-2017-12149)
DSO-01204:Gitea 1.4.0 目录穿越漏洞
DSO-01205:Coremail邮件系统 配置文件信息泄露漏洞
DSO-01206:Weblogic wls-async组件反序列化（补丁绕过）漏洞
DSO-01207:Apache Solr <= 7.0.1 远程命令执行漏洞
DSO-01208:Coremail邮件系统 服务未授权访问和服务接口参数注入漏洞
DSO-01210:ThinkPHP <5.1.23 SQL注入漏洞
DSO-01212:GoAhead 2.5.0~3.6.5 LD_PRELOAD 远程代码执行漏洞
DSO-01214:FineReport 敏感配置文件下载漏洞
DSO-01217:Apache Spark API 未授权访问
DSO-01220:Adobe ColdFusion amf 反序列化漏洞
DSO-01221:致远 OA A8 无需认证 Getshell 漏洞
DSO-01223:JC6 金和协同管理平台任意文件上传漏洞
DSO-01224:JBoss 4.x JBossMQ JMS反序列化漏洞(CVE-2017-7504)
DSO-01225:Apache JMeter RMI 反序列化命令执行漏洞(CVE-2018-1297)
DSO-01226:mini_httpd <1.30 任意文件读取漏洞
DSO-01230:Django <1.11.5 debug页面XSS漏洞
DSO-01231:Apache ActiveMQ Console存在默认口令
DSO-01232:Django <2.0.8 任意URL跳转漏洞
DSO-01249:LibreNMS 远程代码执行(CVE-2018-20434)
DSO-01256:Ruby on Rails 路径穿越与任意文件读取漏洞(CVE-2019-5418)
DSO-01257:LibreNMS SQL注入漏洞(CVE-2018-20678)
DSO-01258:Apache Axis 远程命令执行漏洞
DSO-01301:Elasticsearch <=1.5.1 备份功能任意文件写入漏洞
DSO-01302:PHP-FPM Fastcgi 未授权访问
DSO-01303:Apache Log4j Server (2.x)<=2.8.1 远程代码执行漏洞
DSO-01304:rsync 未授权访问
DSO-01305:Apache Struts2 远程代码执行漏洞(S2-048)
DSO-01306:uWSGI 未授权访问
DSO-01310:Apache Dubbo 用户弱口令
DSO-01311:Atlassian Jira 多个版本未授权服务端模板注入漏洞
DSO-01312:Weblogic DeploymentService接口任意文件上传漏洞
DSO-01314:Palo Alto GlobalProtect SSL VPN 远程代码执行漏洞
DSO-01316:ProFTPd mod_copy 远程命令执行漏洞
DSO-01321:Apache ActiveMQ 任意文件写入漏洞
DSO-01334:Apache Solr < 8.2.0 远程命令执行漏洞
DSO-01335:齐治运维堡垒机 服务端存在命令执行漏洞
DSO-01341:Pulse Connect Secure (PCS) SSL VPN 任意文件读取漏洞
DSO-01347:Atlassian Confluence 存在任意文件读取漏洞
DSO-01372:Adobe ColdFusion 任意文件上传漏洞
DSO-01374:Spring Cloud Config Server 路径穿越与任意文件读取漏洞
DSO-01397:Nexus Repository Manager 2.x 远程命令执行漏洞
DSO-01416:金山防火墙 editschedule.php 远程命令执行漏洞
DSO-01422:Harbor 存在任意管理员注册漏洞
DSO-01430:源天OA系统 com.velcro.base.GetDataAction 参数formid 存在SQL注入漏洞
DSO-01434:RuvarHRM 人力资源管理系统 file_download.aspx 存在SQL注入漏洞
DSO-01437:泛微e-cology 远程代码执行漏洞
DSO-01447:Fortigate SSL VPN 跨站脚本漏洞
DSO-01448:Fortigate SSL VPN 任意文件读取漏洞
DSO-01449:phpStudy 远程命令执行漏洞
DSO-01453:泛微e-cology WorkflowCenterTreeData接口 SQL注入漏洞(限oracle数据库)
DSO-01457:Apache Server Status 信息泄露漏洞
DSO-01458:Apache Axis2 任意文件读取漏洞
DSO-01466:Apache CouchDB 未授权访问
DSO-01473:FE协作办公系统 FILE 协议 ProxyServletUtil 接口文件读取漏洞
DSO-01497:Apache Struts2 方法调用远程代码执行漏洞(S2-037)
DSO-01514:Iceflow VPN 日志文件未授权访问漏洞
DSO-01517:Zabbix 未授权访问
DSO-01539:中兴网关设备 通用型任意文件包含漏洞
DSO-01559:亿邮 Email Defender 系统 SQL注入漏洞
DSO-01569:泛微e-cology validate.jsp SQL注入漏洞
DSO-01570:Kibana 远程命令执行漏洞
DSO-01574:Harbor 访问控制绕过漏洞
DSO-01615:PHP 远程代码执行漏洞
DSO-01619:ThinkCMF框架任意内容包含漏洞
DSO-01620:源天OA系统 com.velcro.base.DataAction SQL注入漏洞
DSO-01621:泛微e-cology 数据库配置信息泄漏漏洞
DSO-01622:安达通安全网关 admin_getLisence 信息泄露漏洞
DSO-01629:安达通安全网关 admin_getLisence 命令执行漏洞
DSO-01639:Zabbix httpmon.php SQL注入漏洞
DSO-01646:imo云办公室系统 read.php任意文件读取漏洞
DSO-01650:imo云办公室系统downnmsg.php 存在SQL注入漏洞
DSO-01659:Apache Solr Velocity模版注入远程命令执行漏洞
DSO-01666:爱琴思邮件系统 /login.php 任意文件读取漏洞
DSO-01669:用友致远A6协同系统 /isNotInTable.jsp SQL注入漏洞
DSO-01676:imo云办公室系统  get_file.php 存在命令执行漏洞
DSO-01677:imo云办公室系统  write.php 存在文件上传漏洞
DSO-01682:莱克斯企业易网通SMB2010 bottomframe.cgi SQL注入漏洞
DSO-01684:用友TurboCRM管理系统 smsstatusreport.php 注入漏洞
DSO-01685:用友e-HR attach.download.d SQL注入漏洞
DSO-01686:用友GRP-U8 userInfoWeb 注入漏洞
DSO-01688:天融信WEB应用安全网关 wafconfig.db 文件下载漏洞
DSO-01689:天融信WEB应用安全网关 /file_tamper_show.php 任意文件读取漏洞
DSO-01690:天融信WEB应用安全网关 file_ssh.php 命令执行漏洞
DSO-01693:天融信应用交付系统 download.php 下载漏洞
DSO-01694:天融信应用交付系统 登录绕过漏洞
DSO-01695:天融信应用交付系统 static_arp_setting_content.php SQL注入漏洞
DSO-01697:任天行网络安全管理系统 traceroute.php 命令执行漏洞
DSO-01699:任天行网络安全管理系统 info.php 信息泄漏漏洞
DSO-01701:网康NS-ASG安全网关 export_log.php 未授权日志下载漏洞
DSO-01703:网康NS-ASG安全网关 默认弱口令
DSO-01705:用友GRP-U8财务管理系统 UploadFile 文件上传漏洞
DSO-01706:网神SecFox安全审计系统 importhtml.php SQL注入漏洞
DSO-01707:网神SecFox安全审计系统 preview.php 任意文件写入漏洞
DSO-01708:网神SecFox安全审计系统 默认弱口令
DSO-01710:用友GRP-U8财务管理系统 login 参数UserNameText 存在SQL注入漏洞
DSO-01724:天融信应用交付系统 enable_tool_debug.php 命令执行漏洞
DSO-01725:金山防火墙 sysmanage.php 未授权访问漏洞
DSO-01728:正方教务管理系统 JSCheckPassword 注入漏洞
DSO-01729:网神SecFox安全审计系统 login.php SQL注入漏洞
DSO-01730:用友TurboCRM forgetpswd.php SQL注入漏洞
DSO-01731:用友e-HR PositionDetail.jsp 注入漏洞
DSO-01732:用友协同办公系统 addRole.jsp 注入漏洞
DSO-01734:Cacti 默认弱口令
DSO-01737:用友致远A6 initData.jsp 注入漏洞
DSO-01738:用友致远 A6 协同办公系统 DownExcelBeanServlet 信息泄露漏洞
DSO-01739:用友致远A6 getSessionList.jsp  session泄露漏洞
DSO-01740:用友致远A6 test.jsp  SQL注入漏洞
DSO-01741:Apache Flink 未授权上传jar包远程代码执行漏洞
DSO-01742:用友致远 A6 协同办公系统 createMysql.jsp 未授权访问漏洞
DSO-01743:用友NC nc.itf.ses.inittool.PortalSESInitToolService 信息泄露漏洞
DSO-01745:用友e-HR 人力资源管理系统 smartweb2.RPC.d XXE漏洞
DSO-01746:用友e-HR ref.show.d 注入漏洞
DSO-01751:HiNet GPON光猫 未授权访问漏洞
DSO-01752:HiNet GPON光猫 远程命令执行漏洞
DSO-01763:SMC Networks Web Interface交换机 管理系统默认口令
DSO-01771:Apache Solr 远程代码执行漏洞
DSO-01773:网御上网行为管理系统 autheditpwd.php SQL注入漏洞
DSO-01775:任天行网络安全管理系统 ping.php 命令执行漏洞
DSO-01778:瑞友天翼应用虚化系统 默认弱口令漏洞
DSO-01779:科达DVR接入网关 FileDownloadServlet 任意文件读取漏洞
DSO-01781:网域科技上网行为流量管理 download.php 设备日志信息下载漏洞
DSO-01785:用友 FE协作办公系统 addUser.jsp 越权访问漏洞
DSO-01787:AppEx LotApp应用交付系统 download.php 任意文件下载漏洞
DSO-01788:AppEx LotApp应用交付系统 static_arp_del.php SQL注入漏洞
DSO-01789:AppEx LotApp应用交付系统 static_arp_setting_content.php SQL注入漏洞
DSO-01790:AppEx LotApp应用交付系统 登录绕过漏洞
DSO-01791:AppEx LotApp应用交付系统 system.php代码执行漏洞
DSO-01793:金蝶OA resin 导致目录遍历漏洞
DSO-01799:泛微e-cology workflowid参数 SQL注入漏洞
DSO-01800:皓峰防火墙 login.php SQL注入漏洞
DSO-01801:皓峰防火墙 setdomain.php 越权访问漏洞
DSO-01802:博华网龙防火墙 cmd.php 命令执行漏洞
DSO-01803:博华网龙防火墙 /xml 目录遍历漏洞
DSO-01804:MagicFlow一体化防火墙网关 任意文件读取漏洞
DSO-01805:西默科技上网行为管理 远程命令执行漏洞
DSO-01806:深度上网行为管理设备接口 getcfgfile 备份文件任意下载漏洞
DSO-01807:浪潮ClusterEngine V4.0 远程命令执行漏洞
DSO-01808:企智通上网行为管理系统 downTcpdumpFile.jsp 任意文件下载漏洞
DSO-01809:企智通上网行为管理系统 user_eqp_batexport.jsp 信息泄漏漏洞
DSO-01810:企智通上网行为管理 recvpass.do SQL注入漏洞
DSO-01813:飞鱼星路由器 加密用户密码泄露漏洞
DSO-01814:汉塔科技上网行为流量管理系统 ping.php 命令执行漏洞
DSO-01816:惠尔顿上网行为管理平台 默认弱口令
DSO-01817:金航网上阅卷系统 /yjLogin SQL注入漏洞
DSO-01818:惠尔顿上网行为管理平台 download.php 任意文件下载漏洞
DSO-01820:惠尔顿e地通 Socks5 VPN登录系统 信息泄漏漏洞
DSO-01821:SECCN VPN 默认弱口令
DSO-01822:网康安全网关 singlelogin.php  SQL注入漏洞
DSO-01824:安宁VMX反垃圾网关系统 logins.php SQL注入漏洞
DSO-01825:D-Link 上网行为审计网关 importhtml.php SQL注入漏洞
DSO-01826:网神SecSSL安全接入网关3600 log_down.php 文件包含漏洞
DSO-01829:金蝶OA DocumentEdit.jsp SQL注入漏洞
DSO-01830:网御上网行为管理系统 importhtml.php 命令执行漏洞
DSO-01831:莱克斯NSG上网行为管理 recovery_passwd.cgi SQL注入漏洞
DSO-01832:用友CRM reservationcomplete.php SQL注入漏洞
DSO-01833:用友GRP U8 cm_function_save.jsp SQL注入漏洞
DSO-01834:网御上网行为管理系统 ques.php SQL注入漏洞
DSO-01835:锐捷RG-NBR路由器 默认弱口令
DSO-01836:莱克斯NSG上网行为管理 默认口令漏洞
DSO-01837:莱克斯NSG上网行为管理 nsg_pnpbasic.cgi 命令执行漏洞
DSO-01843:网域科技上网行为流量管理系统 info.php 信息泄漏漏洞
DSO-01845:用友致远A6协同办公系统 iSignatureHtmlServer.jsp  注入漏洞
DSO-01846:用友NC综合办公系统 LoginServerDo.jsp SQL注入漏洞
DSO-01847:惠尔顿上网行为管理平台 delectSSLL.php 命令执行漏洞
DSO-01848:惠尔顿e地通Socks5 VPN登录系统 pppoe1.conf 信息泄漏漏洞
DSO-01849:惠尔顿上网行为管理平台 getLoginIkey.php 注入漏洞
DSO-01850:惠尔顿e地通Socks5 VPN登录系统 默认弱口令漏洞
DSO-01851:D-Link上网行为审计网关 uploadfile.php 任意文件上传漏洞
DSO-01855:致远OA A8-V5 officeservlet 任意文件读取漏洞
DSO-01861:网神SecSSL安全接入网关3600 user_add_action.php 任意文件上传漏洞
DSO-01862:网神SecSSL安全接入网关3600 app_wrp.php URL重定向漏洞
DSO-01863:Harbor 多个漏洞
DSO-01868:AppEx LotApp应用交付系统 check_instance_state.php 命令执行漏洞
DSO-01872:锐捷统一上网行为管理与审计系统 默认弱口令
DSO-01873:企智通上网行为管理系统 rp_download.jsp 任意文件下载漏洞
DSO-01875:网神SecSSL安全接入网关3600 minica_down.php 任意命令执行漏洞
DSO-01876:网御上网行为管理系统 preview.php 任意文件写入漏洞
DSO-01878:神州数码防火墙 默认弱口令
DSO-01885:用友TurboCRM管理系统 updateactivityemailnum.php SQL注入漏洞
DSO-01886:用友FE selectUDR.jsp SQL注入漏洞
DSO-01887:网神SecSSL安全接入网关3600 minica_down.php 文件读取漏洞
DSO-01888:O2micro SSL VPN main.php 文件包含漏洞
DSO-01892:OLYM审计系统 默认弱口令
DSO-01894:用友GRP-U8财务管理系统 cm_notice_content.jsp  SQL注入漏洞
DSO-01895:网神SecSSL 3600安全接入网关 user_edit_action.php 任意文件上传漏洞
DSO-01899:网康安全网关 naccheck.php SQL注入漏洞
DSO-01900:O2micro SSL VPN minica_down.php 任意命令执行漏洞
DSO-01901:OLYM审计系统 info.php 信息泄漏漏洞
DSO-01902:OLYM审计系统 ping.php 命令执行漏洞
DSO-01906:天融信TopApp-AD应用交付系统 static_restart_arp_action.php 命令执行漏洞
DSO-01975:迈普安全网关 sys_dia_data_down 文件下载漏洞
DSO-01976:迈普安全网关 log_fw_operate_jsondata管理日志越权访问
DSO-01977:迈普 安全网关默认弱口令
DSO-02014:mongo-express 远程代码执行漏洞
DSO-02021:Citrix 路径遍历漏洞
DSO-02022:JetBrains IDE workspace.xml 文件泄露
DSO-02027:Struts2 S2-019 远程代码执行漏洞
DSO-02029:GitLab Explore敏感信息泄露
DSO-02053:FusionAuth 远程命令执行漏洞
DSO-02064:Apache Dubbo 反序列化漏洞
DSO-02074:Apache Tomcat Ajp协议文件包含漏洞
DSO-02082:Spring Boot Actuator未授权访问
DSO-02093:Weblogic IIOP 协议反序列化漏洞
DSO-02176:天融信防火墙存在通用弱口令漏洞
DSO-02178:Apache Druid websession.html 未授权访问
DSO-02191:通达OA未授权文件上传和文件包含漏洞
DSO-02205:Apache SkyWalking未授权访问
DSO-02228:安恒明御安全网关文件遍历下载
DSO-02275:Nexus Repository Manager 3.x远程代码执行漏洞
DSO-02297:Nagios XI Scheduled组件 远程命令执行漏洞
DSO-02303:Palo Alto 防火墙 未授权远程代码执行漏洞
DSO-02342:通达OA前台任意用户伪造登录漏洞
DSO-02344:PHP phpinfo信息泄露
DSO-02392:Apache Tomcat 集群会话同步远程代码执行漏洞
DSO-02412:Apache SkyWalking 默认口令
DSO-02415:Apache Dubbo 远程代码执行(CVE-2020-1948)
DSO-02423:F5 BIG-IP 远程代码执行漏洞
DSO-02424:F5 BIG-IP 远程代码执行漏洞httpd配置缓解方案绕过
DSO-02426:Citrix ADC 任意文件读取漏洞
DSO-02427:SAP NETWEAVER AS JAVA 严重漏洞
DSO-02428:Weblogic 多个远程代码执行漏洞
DSO-02430:Apache Kylin 系统管理默认口令
DSO-02431:Apache Kylin 远程命令执行漏洞
DSO-02432:深信服 SSLVPN设备远程命令执行漏洞
DSO-02433:Cisco ASA/FTD设备 任意文件读取漏洞
DSO-02438:OpenFire SSRF漏洞
DSO-02441:Apache SkyWalking SQL注入漏洞(CVE-2020-13921)
DSO-02442:Apache SkyWalking SQL注入漏洞(CVE-2020-9483)
DSO-02443:Spring Cloud Config 目录遍历漏洞(CVE-2020-5405)
DSO-02444:Spring Cloud Config 目录穿越漏洞(CVE-2020-5410)
DSO-02452:深信服 EDR终端检测响应平台 命令执行漏洞
DSO-02454:IIOP 协议未限制访问漏洞
DSO-02457:深信服 EDR 终端检测响应平台 任意用户登陆漏洞
DSO-02463:Apereo CAS 反序列化漏洞
DSO-02464:fastjson 反序列化漏洞
DSO-02469:用友NC 6.5 SQL注入漏洞
DSO-02470:泛微云桥e-Bridge 任意文件读取漏洞
DSO-02477:Coremail V5 任意文件上传漏洞
DSO-02479:ThinkAdminV6未授权列目录、任意文件读取漏洞
DSO-02480:天融信TopApp-LB负载均衡命令执行漏洞
DSO-02481:用友GRP-U8 xml注入漏洞
DSO-02483:泛微e-cology checkFolderCanDelete.jsp页面SQL注入漏洞
DSO-02484:联软UniNAC网络准入控制系统 任意文件上传漏洞
DSO-02486:Apache Solr ConfigSet 文件上传漏洞
DSO-02489:VMware vCenter任意文件读取漏洞
DSO-02501:Weblogic Console HTTP协议远程代码执行漏洞
DSO-02503:Weblogic Console HTTP协议远程代码执行漏洞CVE-2020-14882绕过
DSO-02509:ThinkPHP 3.2.3 日志文件配置不当漏洞
DSO-02997:绿盟UTS综合威胁探针密码泄露
DSO-02998:NexusDB目录遍历漏洞
DSO-02999:Codis未授权访问
DSO-03040:通用敏感及备份文件泄露
DSO-03230:Struts2 S2-061 远程命令执行漏洞
DSO-03438:SolarWinds Orion API 远程代码执行漏洞
DSO-03499:Apache Flink 任意文件读取漏洞
DSO-03502:泛微OA e-cology resource 存在任意文件读取漏洞
```


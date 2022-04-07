# jcSniffer

网络攻防基础作业一: 嗅探器的设计与实现

基础功能：
- [X] 选择网卡进行抓包
- [X] 图形化界面，多线程实现生产者与消费者模型
- [X] 对常见数据包进行分析与关键内容展示
- [X] 基础协议过滤的设计与实现
- [X] 数据包的存储与导入
- [ ] 重传包的识别
- [ ] 常见厂商 MAC 地址识别


扩展功能: 
- [X] 扩展协议过滤的设计与实现
- [X] 实现 TCP/HTTP 流的追踪以及传输数据的识别与导出
- [ ] 丢包率分析

# 主要环境

| Packet | Version | Description |
| - | - | - |
| Python | 3.8.12 | 逻辑实现 |
| WinPcap | 4.1.3 | scapy 依赖 |
| PyQt5 | 5.15.4 | 图形界面实现 |
| pyqt5-tools | 5.15.4.3.2 | 图形界面设计 |
| scapy | 2.4.5 | 逻辑实现 |

## 测试环境

系统: Win 10
需要安装 WinPcap 4.1.3

# 基础

## 选择网卡进行抓包

- 自动识别本机网卡信息并展示

![](https://gitee.com/Butterflier/pictures/raw/master/202204051120985.png)

- 双击选择网卡后进如抓包页面等待启动

![](https://gitee.com/Butterflier/pictures/raw/master/202204051122884.png)

- 点击启动按钮或快捷键即可一键开启嗅探

![](https://gitee.com/Butterflier/pictures/raw/master/202204051123559.png)

## 生产者与消费者模型

- 生产者为 `./sniff.py` 中的 `SniffThread` 线程: 其负责捕捉指定网卡的数据包, 每捕捉到一个后调用回调函数 `prn` 发送 `HandleSignal` 通知消费者处理

```python
class SniffThread(QThread):
    HandleSignal = pyqtSignal(scapy.layers.l2.Ether)

    def __init__(self, filter, if_name):
        super().__init__()
        self.filter = filter
        self.if_name = if_name

    def run(self):
        sniff(filter=self.filter, iface=self.if_name,
              prn=lambda packet: self.HandleSignal.emit(packet))
```

- 消费者为 `./main.py` 中的 `JCSnifferWindow` 收到信号后调用 `display` 存储并展示数据包

```python
class JCSnifferWindow(Ui_MainWindow, QMainWindow):

    def __init__(self):
        # ...

    def start_sniff(self):
        self.sniffThread = SniffThread("", self.if_name)
        self.sniffThread.HandleSignal.connect(self.display)
        self.sniffThread.start()

    def display(self, packet):
        # 消费者处理函数
        ...
```

## 数据报分析与展示

- IPv4 数据报

![](https://gitee.com/Butterflier/pictures/raw/master/202204051136244.png)

- IPv6 数据报

![](https://gitee.com/Butterflier/pictures/raw/master/202204051152487.png)

- ARP 数据报

![](https://gitee.com/Butterflier/pictures/raw/master/202204051151826.png)

- TCP 数据包

![](https://gitee.com/Butterflier/pictures/raw/master/202204051142046.png)

- UDP 数据包

![](https://gitee.com/Butterflier/pictures/raw/master/202204051143508.png)

- HTTP 数据包

![](https://gitee.com/Butterflier/pictures/raw/master/202204051154571.png)

- ICMP 数据包

![](https://gitee.com/Butterflier/pictures/raw/master/202204051154480.png)


## 基础数据包过滤

### 基于协议的过滤

- `pro=#1` 基于单个协议: `'HTTP', 'TCP', 'UDP', 'IPV6', 'ARP', 'ICMP'`

![](https://gitee.com/Butterflier/pictures/raw/master/202204051156336.png)

- `pro=#1,#2,...` 基于多个协议

![](https://gitee.com/Butterflier/pictures/raw/master/202204051157689.png)

### 基于端口的过滤

- `sport=#1`: 基于指定源端口

![](https://gitee.com/Butterflier/pictures/raw/master/202204051158367.png)

- `dport=#1-#2`: 基于指定目标端口范围

![](https://gitee.com/Butterflier/pictures/raw/master/202204051159711.png)

- `port=#1, #2..., #3-#4...`: 基于指定源/目的端口

![](https://gitee.com/Butterflier/pictures/raw/master/202204051201290.png)

### 基于IP地址的过滤

- `src=#1`: 基于指定源 IP

![](https://gitee.com/Butterflier/pictures/raw/master/202204051202984.png)

- `dst=#1/#2`: 基于指定目标 IP 网段

![](https://gitee.com/Butterflier/pictures/raw/master/202204051203240.png)

- `ip=#1`: 基于指定源/目标

![](https://gitee.com/Butterflier/pictures/raw/master/202204051237330.png)

### 逻辑或合并多个过滤条件

- `filter_1 OR filter_2`: 基于指定 IP 或 指定端口

![](https://gitee.com/Butterflier/pictures/raw/master/202204051239726.png)

> Tips: 指定 IP 与 指定端口等功能实现将在扩展过滤中介绍


## 数据包的存储与导入

- 存储数据包

![](https://gitee.com/Butterflier/pictures/raw/master/202204051241060.png)

- 导入数据包

![](https://gitee.com/Butterflier/pictures/raw/master/202204051242798.png)

Tips: 导入后不可继续嗅探

![](https://gitee.com/Butterflier/pictures/raw/master/202204051243501.png)

# 扩展功能

## 扩展数据包过滤

该过滤指令将数据包的传输方向, 协议类型, 源/目的 IP地址/网段, 源/目的端口合并, 并支持 `*` 通配符
下方为展示样例:

1. `10.203.158.136 > http > *`: 捕获 `10.203.158.136` 发出的所有 `http` 请求 

![](https://gitee.com/Butterflier/pictures/raw/master/202204051247246.png)

2. `10.203.158.136 < http < *`: 捕获 `10.203.158.136` 接收的所有 `http` 请求

![](https://gitee.com/Butterflier/pictures/raw/master/202204051250080.png)

3. `10.203.158.136 <> http <> *`: 捕获 `10.203.158.136` 发出或接收的所有 `http` 请求

![](https://gitee.com/Butterflier/pictures/raw/master/202204051248513.png)

4. `124.16.77.0/24 < * < *`: 捕获 `124.16.77.0/24` 子网收到的所有数据包

![](https://gitee.com/Butterflier/pictures/raw/master/202204051253705.png)

5. `10.203.158.136:80, 443, 7000-8000 <> * <> *` 捕获 `10.203.158.136` 80 或 443 或 7000 到 8000 端口所发出或接收的所有数据包

![](https://gitee.com/Butterflier/pictures/raw/master/202204051256179.png)

## 流的追踪以及传输数据的识别与导出

支持 HTTP 流的追踪与数据识别与导出

- 当我们定位到一个包时, 如果识别出有可以导出的文件, 会高亮下载按钮

![](https://gitee.com/Butterflier/pictures/raw/master/202204051347350.png)

![](https://gitee.com/Butterflier/pictures/raw/master/202204051347075.png)

- 这时点击下载按钮就会自动完成针对该文件的流的追踪以及数据的拼接, 提供下载

![](https://gitee.com/Butterflier/pictures/raw/master/202204051352118.png)

- 目前测试通过了 `jpeg` 图片数据流, `pdf` 数据流, `markdown` 文件数据流的追中与文件识别导出

![](https://gitee.com/Butterflier/pictures/raw/master/202204051352118.png)

![](https://gitee.com/Butterflier/pictures/raw/master/202204051352585.png)

![](https://gitee.com/Butterflier/pictures/raw/master/202204051351055.png)

![](https://gitee.com/Butterflier/pictures/raw/master/202204051719056.png)

- 理论上支持从 HTTP 流中导出传输的所有文件


# Reference

- 感谢: @d1nn34
> 初始设计参考了 `https://github.com/d1nn3r/sniffer`
# MPUDP Relay | 多路径 UDP 中继

This project is a UDP relay and monitoring service with client-server architecture. It allows for multiple link configurations on the client side, heartbeats for monitoring, and automated link switching based on performance metrics such as RTT, packet loss, and throughput.  
本项目是一个基于客户端-服务器架构的 UDP 中继与监控服务，支持客户端多线路配置，通过心跳包进行监控，并基于 RTT、丢包率和吞吐量等性能指标实现自动线路切换。

## Problem | 解决的问题

Sometimes, it is desired to connect to a terminal device with multiple UDP ports. For example, when using frp mapping for devices behind NAT, multiple frp servers are often used to avoid single point of failure, each with different addresses but corresponding to the same port of the terminal device.

有时期望连接的终端机的udp端口具有多个地址，（例如，对NAT后的设备使用frp映射，为了避免frp的单点故障，往往会使用多个frp服务器，他们具有不同的地址，但都对应终端设备的同一个端口）

Different links may have different performance, availability, and stability, so a relay service is needed to automatically select the best link for data transmission based on different performance metrics.

不同的链路可能具有不同的性能、可用性、稳定性，因此需要一个中继服务，能够根据不同的性能指标，自动选择最佳的链路进行数据传输。

```
Client -- MPUDP-client -----MultiPath----- MPUDP-server -- Server
                       |= Frp service 1 =|
                       |= Frp service 2 =|
                       |= Frp service 3 =|
```

## Solution | 解决方案

The MPUDP service allows applications that need to connect to servers to first connect to the MPUDP client through a UDP relay service. The client monitors multiple links and forwards the local application traffic to the MPUDP server. The server forwards the data to the upstream server and returns the data along the same path. The client automatically switches links based on performance metrics such as RTT, packet loss, and throughput.

通过一个 UDP 中继服务，将需要连接服务器的应用先连接到MPUDP客户端，客户端监控多条线路，将本地应用的流量转发至MPUDP服务端。服务端将数据转发至上游服务器，并将上游服务器返回的数据沿同一路径返回。客户端根据 RTT、丢包率和吞吐量等性能指标自动切换线路。


## Features | 功能特点

- **Client-Server Architecture | 客户端-服务器架构**
- **Multi-Link Configuration | 多线路配置**
- **Heartbeat Monitoring | 心跳监控**
- **Automatic Link Switching | 自动线路切换**
- **DNS Refreshing | DNS 刷新**
- **Debug Mode | 调试模式**

## Configuration | 配置

The service requires a JSON configuration file. The default configuration file is `config.json`. Below is an example configuration:  
服务需要一个 JSON 配置文件，默认文件为 `config.json`。以下是示例配置：

```json
{
    "mode": "client",
    "server": {
        "listen_addr": ":5000",
        "upstream_addr": "127.0.0.1:6000",
        "heartbeat_timeout_sec": 10
    },
    "client": {
        "listen_addr": "0.0.0.0:8999",
        "links": [
            {
                "remote_addr": "1.2.3.4:5000"
            },
            {
                "remote_addr": "[240c::1]:5000"
            }
        ],
        "heartbeat_interval_sec": 1,
        "loss_weight": 5.0,
        "rtt_weight": 1.0,
        "switch_threshold": 25.0,
        "throughput_threshold_kbps": 500,
        "max_consecutive_fail": 5,
        "dns_refresh_interval_sec": 600,
        "debug": false
    }
}
```

### Parameters | 配置参数

#### Common | 通用
- **`mode`**: Set to `"client"` or `"server"`.  
  设置为 `"client"` 或 `"server"`。

#### Server | 服务端
- **`listen_addr`**: Address and port to listen for incoming connections.  
  监听客户端连接的地址和端口。
- **`upstream_addr`**: Address of the upstream server.  
  上游服务器地址。
- **`heartbeat_timeout_sec`**: Timeout in seconds to consider a client disconnected.  
  判断客户端断开连接的超时时间（秒）。

#### Client | 客户端
- **`listen_addr`**: Address and port to listen for local application traffic.  
  监听本地应用流量的地址和端口。
- **`links`**: List of remote server addresses for UDP links.  
  UDP 线路的远程服务器地址列表。
- **`heartbeat_interval_sec`**: Interval in seconds to send heartbeat packets.  
  心跳包发送间隔（秒）。
- **`loss_weight`**: Weight for packet loss in link scoring.  
  丢包率在线路评分中的权重。
- **`rtt_weight`**: Weight for RTT in link scoring.  
  RTT 在线路评分中的权重。
- **`switch_threshold`**: Minimum score improvement required to switch links.  
  切换线路所需的最低分数改进值。
- **`throughput_threshold_kbps`**: Throughput threshold in kbps to avoid switching.  
  避免切换的吞吐量阈值（Kbps）。
- **`max_consecutive_fail`**: Maximum consecutive failures before marking a link as down.  
  判定线路不可用前的最大连续失败次数。
- **`dns_refresh_interval_sec`**: Interval in seconds to refresh DNS.  
  DNS 刷新的时间间隔（秒）。
- **`debug`**: Enable debug logs.  
  是否启用调试日志。

## Usage | 使用方法

1. Start the service with the appropriate mode:  
   使用对应模式启动服务：
   ```bash
   ./udp-relay -config=config.json
   ```

2. The server listens for client connections and relays data to the upstream server.  
   服务端监听客户端连接，并将数据转发至上游服务器。

3. The client monitors multiple links, forwards local application traffic to the server, and switches links based on performance.  
   客户端监控多条线路，将本地应用的流量转发至服务端，并根据性能切换线路。

## Notes | 注意事项

- The service is designed for UDP traffic only.  
  服务仅支持 UDP 流量。
- The service does not support encryption.  
  服务不支持加密。
- The service does not support multiple clients.  
  服务不支持多个客户端。
- I am not proficient in Go, and this project was written to solve a specific problem. Some code was contributed by the o1 model, and there may be some issues (especially in concurrency). Suggestions and improvements are welcome.  
  我并不熟练掌握 Go 语言，这个项目是我为了解决一个特定问题而编写的，部分代码由o1模型贡献，可能存在一些问题（特别是并发部分），欢迎提出建议和改进。
- This project is for learning and communication purposes only and may not be used for illegal purposes. You are responsible for any consequences.  
  该项目仅供学习交流使用，不得用于非法用途，由此产生的一切后果自行承担。
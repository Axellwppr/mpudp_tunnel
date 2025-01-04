package main

import (
    "context"
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "math"
    "net"
    "os"
    "sync"
    "sync/atomic"
    "time"
)

// ==================== 配置结构 ====================

type Config struct {
    Mode   string       `json:"mode"`   // "client" or "server"
    Server ServerConfig `json:"server"`
    Client ClientConfig `json:"client"`
}

type ServerConfig struct {
    ListenAddr          string `json:"listen_addr"`
    UpstreamAddr        string `json:"upstream_addr"`
    HeartbeatTimeoutSec int    `json:"heartbeat_timeout_sec"`
}

type ClientConfig struct {
    ListenAddr              string       `json:"listen_addr"`
    Links                   []LinkConfig `json:"links"`
    HeartbeatIntervalSec    int          `json:"heartbeat_interval_sec"`
    LossWeight              float64      `json:"loss_weight"`
    RttWeight               float64      `json:"rtt_weight"`
    SwitchThreshold         float64      `json:"switch_threshold"`
    ThroughputThresholdKbps float64      `json:"throughput_threshold_kbps"`
    MaxConsecutiveFail      int          `json:"max_consecutive_fail"`
    Debug                   bool
}

// 每条可用线路的配置
type LinkConfig struct {
    RemoteAddr string `json:"remote_addr"`
}

// ==================== 公共工具函数 ====================

var heartbeatMagic = []byte{0xFF, 0x00, 0xFF, 0x00}

func isHeartbeatPacket(data []byte) bool {
    if len(data) < 4 {
        return false
    }
    for i := 0; i < 4; i++ {
        if data[i] != heartbeatMagic[i] {
            return false
        }
    }
    return true
}

func int64ToBytes(n int64) []byte {
    b := make([]byte, 8)
    for i := 0; i < 8; i++ {
        b[i] = byte(n >> (56 - 8*i))
    }
    return b
}

func bytesToInt64(b []byte) int64 {
    var n int64
    for i := 0; i < 8; i++ {
        n = (n << 8) | int64(b[i])
    }
    return n
}

type ScoreData struct {
    RTT      time.Duration
    LossRate float64 // 0~1
}

// 假设: 分数越高越好。
// 在此我们定义: score = -(loss_weight*lossRate*100 + rtt_weight*rtt_ms)
// 丢包率和 RTT 越高, score 越低。
func CalcScore(sd ScoreData, lossWeight, rttWeight float64) float64 {
    rttMs := float64(sd.RTT.Milliseconds())
    lossPct := sd.LossRate * 100
    return -(lossWeight*lossPct + rttWeight*rttMs)
}

// ==================== 客户端部分 ====================

type ClientLink struct {
    RemoteAddr        *net.UDPAddr
    ScoreHistory      []float64
    HistoryIdx        int
    LastScore         float64
    ConsecutiveFail   int64  // 连续心跳收不到响应
    testSent          int64  // 心跳/测速包已发
    testReceived      int64  // 心跳/测速包已收到响应

    bytesSentInWindow int64  // 用于计算上行吞吐量
    bytesRecvInWindow int64  // 用于计算下行吞吐量
    windowStart       time.Time
    mu                sync.Mutex
}

type UdpClient struct {
    config      ClientConfig
    localConn   *net.UDPConn
    links       []*ClientLink
    activeIndex int64 // 原子操作，当前使用的链路下标

    stopChan chan struct{}
    wg       sync.WaitGroup
}

func NewUdpClient(cfg ClientConfig) (*UdpClient, error) {
    if len(cfg.Links) == 0 {
        return nil, fmt.Errorf("无可用线路")
    }

    links := make([]*ClientLink, 0, len(cfg.Links))
    for _, linkCfg := range cfg.Links {
        addr, err := net.ResolveUDPAddr("udp", linkCfg.RemoteAddr)
        if err != nil {
            return nil, fmt.Errorf("无法解析远程地址 [%s]: %v", linkCfg.RemoteAddr, err)
        }
        links = append(links, &ClientLink{
            RemoteAddr:   addr,
            ScoreHistory: make([]float64, 8),
        })
    }

    client := &UdpClient{
        config:    cfg,
        links:     links,
        stopChan:  make(chan struct{}),
    }

    // 默认激活第一条线路
    atomic.StoreInt64(&client.activeIndex, 0)
    return client, nil
}

func (c *UdpClient) Start(ctx context.Context) error {
    lAddr, err := net.ResolveUDPAddr("udp", c.config.ListenAddr)
    if err != nil {
        return fmt.Errorf("解析客户端监听地址失败: %w", err)
    }

    c.localConn, err = net.ListenUDP("udp", lAddr)
    if err != nil {
        return fmt.Errorf("监听UDP失败: %w", err)
    }
    log.Printf("[Client] 启动，监听: %s", c.config.ListenAddr)

    // 初始化各线路的 windowStart
    now := time.Now()
    for _, ln := range c.links {
        ln.windowStart = now
    }

    // 启动读本地应用数据 -> 转发到远端
    c.wg.Add(1)
    go c.handleLocalRead()

    // 启动读远端服务器 -> 写本地
    c.wg.Add(1)
    go c.handleServerRead()

    // 启动心跳/测速 例行任务
    c.wg.Add(1)
    go c.heartbeatRoutine()

    return nil
}

func (c *UdpClient) Stop() {
    close(c.stopChan)
    if c.localConn != nil {
        _ = c.localConn.Close()
    }
    c.wg.Wait()
}

func (c *UdpClient) handleLocalRead() {
    defer c.wg.Done()
    buf := make([]byte, 64*1024)

    for {
        n, _, err := c.localConn.ReadFromUDP(buf)
        if err != nil {
            select {
            case <-c.stopChan:
                return
            default:
                // 区分临时错误/永久错误
                if ne, ok := err.(net.Error); ok && ne.Temporary() {
                    log.Printf("[Client] 本地读取临时错误: %v", err)
                    continue
                }
                log.Printf("[Client] 本地读取严重错误, goroutine 退出: %v", err)
                return
            }
        }

        data := make([]byte, n)
        copy(data, buf[:n])

        idx := atomic.LoadInt64(&c.activeIndex)
        if idx < 0 || idx >= int64(len(c.links)) {
            continue
        }
        link := c.links[idx]

        // 统计上行发送字节
        atomic.AddInt64(&link.bytesSentInWindow, int64(n))

        _, werr := c.localConn.WriteToUDP(data, link.RemoteAddr)
        if werr != nil {
            // 同理区分临时/永久
            if ne, ok := werr.(net.Error); ok && ne.Temporary() {
                log.Printf("[Client] 向远程发送临时错误: %v", werr)
                continue
            }
            log.Printf("[Client] 向远程发送严重错误, goroutine 退出: %v", werr)
            return
        }
    }
}

func (c *UdpClient) handleServerRead() {
    defer c.wg.Done()
    buf := make([]byte, 64*1024)

    for {
        n, addr, err := c.localConn.ReadFromUDP(buf)
        if err != nil {
            select {
            case <-c.stopChan:
                return
            default:
                if ne, ok := err.(net.Error); ok && ne.Temporary() {
                    log.Printf("[Client] 服务器读取临时错误: %v", err)
                    continue
                }
                log.Printf("[Client] 服务器读取严重错误, goroutine 退出: %v", err)
                return
            }
        }

        data := make([]byte, n)
        copy(data, buf[:n])

        // 判断是否是心跳包
        if isHeartbeatPacket(data) && len(data) >= 12 {
            sendNano := bytesToInt64(data[4:12])
            rtt := time.Since(time.Unix(0, sendNano))
            c.updateLinkTest(addr, rtt)
            continue
        }

        // 否则是业务数据：回写本地端口
        // 同时可统计下行流量
        idx := atomic.LoadInt64(&c.activeIndex)
        if idx >= 0 && idx < int64(len(c.links)) {
            link := c.links[idx]
            atomic.AddInt64(&link.bytesRecvInWindow, int64(n))
        }

        // 回写到本地上层应用 (同一个UDPConn)
        _, werr := c.localConn.WriteToUDP(data, &net.UDPAddr{
            IP:   net.ParseIP("127.0.0.1"),
            Port: c.localConn.LocalAddr().(*net.UDPAddr).Port,
        })
        if werr != nil {
            if ne, ok := werr.(net.Error); ok && ne.Temporary() {
                log.Printf("[Client] 回写本地临时错误: %v", werr)
                continue
            }
            log.Printf("[Client] 回写本地严重错误, goroutine 退出: %v", werr)
            return
        }
    }
}

func (c *UdpClient) updateLinkTest(addr *net.UDPAddr, rtt time.Duration) {
    for _, link := range c.links {
        if link.RemoteAddr.IP.Equal(addr.IP) && link.RemoteAddr.Port == addr.Port {
            // 收到响应
            atomic.AddInt64(&link.testReceived, 1)
            // 计算丢包率
            sent := atomic.LoadInt64(&link.testSent)
            recv := atomic.LoadInt64(&link.testReceived)
            var lossRate float64
            if sent > 0 {
                lossRate = 1 - float64(recv)/float64(sent)
            }

            score := CalcScore(ScoreData{RTT: rtt, LossRate: lossRate},
                c.config.LossWeight, c.config.RttWeight)

            link.mu.Lock()
            link.ScoreHistory[link.HistoryIdx] = score
            link.HistoryIdx = (link.HistoryIdx + 1) % len(link.ScoreHistory)
            link.LastScore = score
            link.mu.Unlock()

            if c.config.Debug {
                log.Printf("[Client] Debug: link=%s score=%.2f rtt=%v loss=%.2f",
                    link.RemoteAddr.String(), score, rtt, lossRate)
            }

            // 成功收到 => ConsecutiveFail = 0
            atomic.StoreInt64(&link.ConsecutiveFail, 0)
            return
        }
    }
}

func (c *UdpClient) heartbeatRoutine() {
    defer c.wg.Done()
    interval := time.Duration(c.config.HeartbeatIntervalSec) * time.Second
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    for {
        select {
        case <-c.stopChan:
            return
        case <-ticker.C:
            // 1) 发心跳
            c.sendHeartbeat()

            // 2) 选择最佳线路
            c.selectBestLink()

            // 3) 重置吞吐窗口
            c.resetThroughputWindow()
        }
    }
}

func (c *UdpClient) sendHeartbeat() {
    now := time.Now().UnixNano()
    pkt := append(heartbeatMagic, int64ToBytes(now)...)

    for _, link := range c.links {
        // testSent +1
        atomic.AddInt64(&link.testSent, 1)

        _, err := c.localConn.WriteToUDP(pkt, link.RemoteAddr)
        if err != nil {
            // 发送错误本身并不一定意味着线路断开，是否“fail”要看有没有回包
            if ne, ok := err.(net.Error); ok && ne.Temporary() {
                log.Printf("[Client] 心跳发送临时错误 -> %s: %v", link.RemoteAddr, err)
                continue
            }
            log.Printf("[Client] 心跳发送严重错误 -> %s: %v", link.RemoteAddr, err)
        }
    }
}

func (c *UdpClient) selectBestLink() {
    bestIdx := -1
    bestAvgScore := -math.MaxFloat64

    currIdx := atomic.LoadInt64(&c.activeIndex)
    var currLink *ClientLink
    if currIdx >= 0 && currIdx < int64(len(c.links)) {
        currLink = c.links[currIdx]
    }

    // 找出分数最高的线路
    for i, link := range c.links {
        fails := atomic.LoadInt64(&link.ConsecutiveFail)
        if fails >= int64(c.config.MaxConsecutiveFail) {
            // 忽略已断开的线路
            continue
        }
        // 计算平均分
        link.mu.Lock()
        sum := 0.0
        count := 0
        for _, s := range link.ScoreHistory {
            if s != 0.0 {
                sum += s
                count++
            }
        }
        var avgScore float64
        if count > 0 {
            avgScore = sum / float64(count)
        } else {
            avgScore = link.LastScore
        }
        link.mu.Unlock()

        if avgScore > bestAvgScore {
            bestAvgScore = avgScore
            bestIdx = i
        }
    }

    // 没有可用线路
    if bestIdx == -1 {
        log.Printf("[Client] 所有线路都不可用!")
        return
    }

    // 若已是当前线路, 不必切换
    if int64(bestIdx) == currIdx {
        return
    }

    // 若当前线路仍在用，比较分数差
    if currLink != nil {
        // 计算当前线路平均分
        currLink.mu.Lock()
        sum := 0.0
        count := 0
        for _, s := range currLink.ScoreHistory {
            if s != 0.0 {
                sum += s
                count++
            }
        }
        var currAvg float64
        if count > 0 {
            currAvg = sum / float64(count)
        } else {
            currAvg = currLink.LastScore
        }
        currLink.mu.Unlock()

        diff := bestAvgScore - currAvg
        if diff < c.config.SwitchThreshold {
            // 分差不够, 不切
            return
        }

        // 判断是否当前链路流量过大, 避免切换
        if c.isCurrentLinkBusy(currLink) {
            return
        }
    }

    // 切换
    log.Printf("[Client] 切换线路: %d -> %d (avgScore=%.2f)", currIdx, bestIdx, bestAvgScore)
    atomic.StoreInt64(&c.activeIndex, int64(bestIdx))
}

func (c *UdpClient) isCurrentLinkBusy(link *ClientLink) bool {
    link.mu.Lock()
    sent := atomic.LoadInt64(&link.bytesSentInWindow)
    recv := atomic.LoadInt64(&link.bytesRecvInWindow)
    dur := time.Since(link.windowStart)
    link.mu.Unlock()

    if dur.Seconds() == 0 {
        return false
    }
    // 计算上下行合并吞吐量(kbps)
    kbps := float64(sent+recv) * 8.0 / 1024.0 / dur.Seconds()
    if kbps >= c.config.ThroughputThresholdKbps {
        log.Printf("[Client] 当前线路吞吐率=%.2f Kbps, 超过阈值=%.2f, 暂不切换",
            kbps, c.config.ThroughputThresholdKbps)
        return true
    }
    return false
}

func (c *UdpClient) resetThroughputWindow() {
    now := time.Now()
    for _, link := range c.links {
        link.mu.Lock()
        // 重置统计窗口
        link.windowStart = now
        atomic.StoreInt64(&link.bytesSentInWindow, 0)
        atomic.StoreInt64(&link.bytesRecvInWindow, 0)
        // 若连续无响应, 可能 fail++
        // （本例中只在 heartbeat 未回包时自动 fail++, 可在此加更多逻辑）
        link.mu.Unlock()
    }
}

// ==================== 服务端部分 ====================

type UdpServer struct {
    config     ServerConfig
    listenConn *net.UDPConn
    upConn     *net.UDPConn

    stopChan chan struct{}
    wg       sync.WaitGroup

    // 服务端只支持单客户端，记住最后一次传输的地址
    lastDataAddr      *net.UDPAddr
    mu                sync.RWMutex
    lastHeartbeatTime time.Time
}

func NewUdpServer(cfg ServerConfig) (*UdpServer, error) {
    return &UdpServer{
        config:  cfg,
        stopChan: make(chan struct{}),
    }, nil
}

func (s *UdpServer) Start(ctx context.Context) error {
    lAddr, err := net.ResolveUDPAddr("udp", s.config.ListenAddr)
    if err != nil {
        return fmt.Errorf("解析服务器监听地址失败: %w", err)
    }

    s.listenConn, err = net.ListenUDP("udp", lAddr)
    if err != nil {
        return fmt.Errorf("服务器监听失败: %w", err)
    }
    log.Printf("[Server] 已监听: %s", s.config.ListenAddr)

    upAddr, err := net.ResolveUDPAddr("udp", s.config.UpstreamAddr)
    if err != nil {
        return fmt.Errorf("解析上游地址失败: %w", err)
    }

    s.upConn, err = net.DialUDP("udp", nil, upAddr)
    if err != nil {
        return fmt.Errorf("连接上游失败: %w", err)
    }
    log.Printf("[Server] 上游地址: %s", s.config.UpstreamAddr)

    // 启动读客户端数据
    s.wg.Add(1)
    go s.handleClientRead()

    // 启动读上游数据
    s.wg.Add(1)
    go s.handleUpServerRead()

    // 启动心跳超时检测
    s.wg.Add(1)
    go s.heartbeatTimeoutChecker()

    return nil
}

func (s *UdpServer) Stop() {
    close(s.stopChan)
    if s.listenConn != nil {
        _ = s.listenConn.Close()
    }
    if s.upConn != nil {
        _ = s.upConn.Close()
    }
    s.wg.Wait()
}

func (s *UdpServer) handleClientRead() {
    defer s.wg.Done()

    buf := make([]byte, 64*1024)
    for {
        n, clientAddr, err := s.listenConn.ReadFromUDP(buf)
        if err != nil {
            select {
            case <-s.stopChan:
                return
            default:
                if ne, ok := err.(net.Error); ok && ne.Temporary() {
                    log.Printf("[Server] 读取客户端临时错误: %v", err)
                    continue
                }
                log.Printf("[Server] 读取客户端严重错误, goroutine 退出: %v", err)
                return
            }
        }

        data := make([]byte, n)
        copy(data, buf[:n])

        // 如果是心跳包
        if isHeartbeatPacket(data) && len(data) >= 12 {
            // 更新心跳时间
            s.mu.Lock()
            s.lastHeartbeatTime = time.Now()
            s.lastDataAddr = clientAddr // 有心跳也表明这个地址在用
            s.mu.Unlock()

            // 原样返回
            _, _ = s.listenConn.WriteToUDP(data, clientAddr)
            continue
        }

        // 业务数据
        s.mu.Lock()
        s.lastDataAddr = clientAddr
        s.lastHeartbeatTime = time.Now()
        s.mu.Unlock()

        _, werr := s.upConn.Write(data)
        if werr != nil {
            if ne, ok := werr.(net.Error); ok && ne.Temporary() {
                log.Printf("[Server] 转发上游临时错误: %v", werr)
                continue
            }
            log.Printf("[Server] 转发上游严重错误, goroutine 退出: %v", werr)
            return
        }
    }
}

func (s *UdpServer) handleUpServerRead() {
    defer s.wg.Done()
    buf := make([]byte, 64*1024)

    for {
        n, err := s.upConn.Read(buf)
        if err != nil {
            select {
            case <-s.stopChan:
                return
            default:
                if ne, ok := err.(net.Error); ok && ne.Temporary() {
                    log.Printf("[Server] 读取上游临时错误: %v", err)
                    continue
                }
                log.Printf("[Server] 读取上游严重错误, goroutine 退出: %v", err)
                return
            }
        }

        data := make([]byte, n)
        copy(data, buf[:n])

        s.mu.RLock()
        addr := s.lastDataAddr
        s.mu.RUnlock()

        if addr != nil {
            _, werr := s.listenConn.WriteToUDP(data, addr)
            if werr != nil {
                if ne, ok := werr.(net.Error); ok && ne.Temporary() {
                    log.Printf("[Server] 回写客户端临时错误: %v", werr)
                    continue
                }
                log.Printf("[Server] 回写客户端严重错误, goroutine 退出: %v", werr)
                return
            }
        }
    }
}

func (s *UdpServer) heartbeatTimeoutChecker() {
    defer s.wg.Done()

    ticker := time.NewTicker(time.Second)
    defer ticker.Stop()

    timeout := time.Duration(s.config.HeartbeatTimeoutSec) * time.Second

    for {
        select {
        case <-s.stopChan:
            return
        case <-ticker.C:
            s.mu.RLock()
            last := s.lastHeartbeatTime
            s.mu.RUnlock()

            if time.Since(last) > timeout {
                // 说明客户端长时间没发心跳或业务包, 清空地址
                s.mu.Lock()
                if s.lastDataAddr != nil {
                    log.Printf("[Server] 心跳超时, 清理客户端地址: %v", s.lastDataAddr)
                }
                s.lastDataAddr = nil
                s.mu.Unlock()
            }
        }
    }
}

// ==================== main & 启动逻辑 ====================

func main() {
    var configPath string
    flag.StringVar(&configPath, "config", "config.json", "配置文件路径")
    flag.Parse()

    // 读取并解析配置
    cfgData, err := os.ReadFile(configPath)
    if err != nil {
        log.Fatalf("读取配置文件失败: %v", err)
    }

    var cfg Config
    if err := json.Unmarshal(cfgData, &cfg); err != nil {
        log.Fatalf("解析配置失败: %v", err)
    }

    ctx := context.Background()

    if cfg.Mode == "server" {
        srv, err := NewUdpServer(cfg.Server)
        if err != nil {
            log.Fatalf("创建服务器失败: %v", err)
        }
        if err := srv.Start(ctx); err != nil {
            log.Fatalf("服务器启动失败: %v", err)
        }
        log.Printf("[Server] 服务器运行中 (listen=%s, upstream=%s)",
            cfg.Server.ListenAddr, cfg.Server.UpstreamAddr)
        select {}
    } else if cfg.Mode == "client" {
        cli, err := NewUdpClient(cfg.Client)
        if err != nil {
            log.Fatalf("创建客户端失败: %v", err)
        }
        if err := cli.Start(ctx); err != nil {
            log.Fatalf("客户端启动失败: %v", err)
        }
        log.Printf("[Client] 客户端运行中 (listen=%s)", cfg.Client.ListenAddr)
        select {}
    } else {
        log.Fatalf("无效的模式: %s (必须是 server 或 client)", cfg.Mode)
    }
}

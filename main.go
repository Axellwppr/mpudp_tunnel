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
    "crypto/ed25519"
    "encoding/base64"
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
    ServerPrivateKeyBase64 string `json:"server_private_key"`
    ClientPublicKeyBase64  string `json:"client_public_key"` 
    MaxPacketSize         int    `json:"max_packet_size"`
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
    DnsRefreshIntervalSec   int          `json:"dns_refresh_interval_sec"`
    Debug  bool         `json:"debug"`
    ClientPrivateKeyBase64 string `json:"client_private_key"`
    ServerPublicKeyBase64  string `json:"server_public_key"`
    MaxPacketSize         int    `json:"max_packet_size"`
}

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

func uint64ToBytes(n uint64) []byte {
    b := make([]byte, 8)
    for i := 0; i < 8; i++ {
        b[i] = byte(n >> (56 - 8*i))
    }
    return b
}

func bytesToUint64(b []byte) uint64 {
    var n uint64
    for i := 0; i < 8; i++ {
        n = (n << 8) | uint64(b[i])
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

// 服务端解析密钥
func parseServerKeys(cfg ServerConfig) (ed25519.PrivateKey, ed25519.PublicKey, error) {
    // 解码私钥
    skBytes, err := base64.StdEncoding.DecodeString(cfg.ServerPrivateKeyBase64)
    if err != nil {
        return nil, nil, fmt.Errorf("解码服务器私钥失败: %v", err)
    }
    if len(skBytes) != ed25519.PrivateKeySize {
        return nil, nil, fmt.Errorf("服务器私钥长度错误")
    }
    serverPrivateKey := ed25519.PrivateKey(skBytes)

    // 解码公钥
    pkBytes, err := base64.StdEncoding.DecodeString(cfg.ClientPublicKeyBase64)
    if err != nil {
        return nil, nil, fmt.Errorf("解码客户端公钥失败: %v", err)
    }
    if len(pkBytes) != ed25519.PublicKeySize {
        return nil, nil, fmt.Errorf("客户端公钥长度错误") 
    }
    clientPublicKey := ed25519.PublicKey(pkBytes)

    return serverPrivateKey, clientPublicKey, nil
}

// 客户端解析密钥
func parseClientKeys(cfg ClientConfig) (ed25519.PrivateKey, ed25519.PublicKey, error) {
    // 解码私钥
    skBytes, err := base64.StdEncoding.DecodeString(cfg.ClientPrivateKeyBase64)
    if err != nil {
        return nil, nil, fmt.Errorf("解码客户端私钥失败: %v", err)
    }
    if len(skBytes) != ed25519.PrivateKeySize {
        return nil, nil, fmt.Errorf("客户端私钥长度错误")
    }
    clientPrivateKey := ed25519.PrivateKey(skBytes)

    // 解码公钥
    pkBytes, err := base64.StdEncoding.DecodeString(cfg.ServerPublicKeyBase64)
    if err != nil {
        return nil, nil, fmt.Errorf("解码服务器公钥失败: %v", err)
    }
    if len(pkBytes) != ed25519.PublicKeySize {
        return nil, nil, fmt.Errorf("服务器公钥长度错误")
    }
    serverPublicKey := ed25519.PublicKey(pkBytes)

    return clientPrivateKey, serverPublicKey, nil
}

// 发送数据/心跳前先签名
func signPacket(priv ed25519.PrivateKey, data []byte) []byte {
    sig := ed25519.Sign(priv, data)
    return append(sig, data...)
}

// 验证签名
func verifyPacket(pub ed25519.PublicKey, data []byte) ([]byte, bool) {
    if len(data) < ed25519.SignatureSize {
        return nil, false
    }
    sig := data[:ed25519.SignatureSize]
    raw := data[ed25519.SignatureSize:]
    if ed25519.Verify(pub, raw, sig) {
        return raw, true
    }
    return nil, false
}

// ==================== 客户端部分 ====================

type ClientLink struct {
    RemoteAddr      *net.UDPAddr
    ScoreHistory    []float64
    HistoryIdx      int
    LastScore       float64
    ConsecutiveFail int64  // 连续心跳收不到响应

    testSent     int64
    testReceived int64

    // 用于统计吞吐量 (上行 + 下行)
    bytesSentInWindow int64
    bytesRecvInWindow int64
    windowStart       time.Time
    mu                sync.Mutex

    nextHeartbeatID    uint64  // 下一个要发送的心跳ID
    lastReceivedID     uint64  // 最后一个收到响应的心跳ID
}

type UdpClient struct {
    config     ClientConfig
    listenConn *net.UDPConn // 专门监听本地应用
    upConn     *net.UDPConn // 专门和远端服务器通信

    links       []*ClientLink
    activeIndex int64 // 当前使用的线路下标(原子操作)

    // 记录最近一次本地应用的地址 (只有一个客户端应用)
    lastLocalAddr *net.UDPAddr

    stopChan chan struct{}
    wg       sync.WaitGroup

    clientPrivateKey ed25519.PrivateKey
    serverPublicKey  ed25519.PublicKey
}

func NewUdpClient(cfg ClientConfig) (*UdpClient, error) {
    if len(cfg.Links) == 0 {
        return nil, fmt.Errorf("无可用线路")
    }

    links := make([]*ClientLink, 0, len(cfg.Links))
    for _, linkCfg := range cfg.Links {
        addr, err := net.ResolveUDPAddr("udp", linkCfg.RemoteAddr)
        if err != nil {
            return nil, fmt.Errorf("解析远程地址 [%s] 失败: %v", linkCfg.RemoteAddr, err)
        }
        links = append(links, &ClientLink{
            RemoteAddr:      addr,
            ScoreHistory:    make([]float64, 8),
            nextHeartbeatID: 1,
            lastReceivedID:  0,
        })
    }

    clientPrivateKey, serverPublicKey, err := parseClientKeys(cfg)
    if err != nil {
        return nil, fmt.Errorf("解析密钥失败: %v", err)
    }

    client := &UdpClient{
        config:           cfg,
        links:            links,
        stopChan:         make(chan struct{}),
        clientPrivateKey: clientPrivateKey,
        serverPublicKey:  serverPublicKey,
    }
    // 默认使用第 0 条线路
    atomic.StoreInt64(&client.activeIndex, 0)
    return client, nil
}

func (c *UdpClient) Start(ctx context.Context) error {
    // 1) listenConn: 用于监听本地应用
    lAddr, err := net.ResolveUDPAddr("udp", c.config.ListenAddr)
    if err != nil {
        return fmt.Errorf("解析本地监听地址失败: %w", err)
    }
    c.listenConn, err = net.ListenUDP("udp", lAddr)
    if err != nil {
        return fmt.Errorf("listenConn 监听失败: %w", err)
    }
    log.Printf("[Client] listenConn 已监听: %s", c.config.ListenAddr)

    // 2) upConn: 用于和远端服务器通信(使用随机端口)
    //    注意: 不指定远端, 后续通过 WriteToUDP(...) 来区分不同线路
    c.upConn, err = net.ListenUDP("udp", nil)
    if err != nil {
        return fmt.Errorf("upConn 创建失败: %w", err)
    }
    log.Printf("[Client] upConn 本地地址: %s (系统分配端口)", c.upConn.LocalAddr())

    // 初始化每条线路的 windowStart
    now := time.Now()
    for _, ln := range c.links {
        ln.windowStart = now
    }

    // 启动 goroutine: 读本地上层应用 -> 发往远端
    c.wg.Add(1)
    go c.handleListenRead()

    // 启动 goroutine: 读远端服务器 -> 回写本地
    c.wg.Add(1)
    go c.handleUpConnRead()

    // 启动 goroutine: 心跳/测速例行任务
    c.wg.Add(1)
    go c.heartbeatRoutine()

    c.wg.Add(1)
    go c.startDnsRefreshRoutine()

    return nil
}

func (c *UdpClient) Stop() {
    close(c.stopChan)
    if c.listenConn != nil {
        _ = c.listenConn.Close()
    }
    if c.upConn != nil {
        _ = c.upConn.Close()
    }
    c.wg.Wait()
}

func (c *UdpClient) handleListenRead() {
    defer c.wg.Done()
    buf := make([]byte, 64*1024)

    for {
        n, srcAddr, err := c.listenConn.ReadFromUDP(buf)
        if err != nil {
            select {
            case <-c.stopChan:
                return
            default:
                if ne, ok := err.(net.Error); ok && ne.Temporary() {
                    log.Printf("[Client] 本地读取临时错误: %v", err)
                    continue
                }
                log.Printf("[Client] 本地读取严重错误: %v", err)
                os.Exit(1)
            }
        }

        data := make([]byte, n)
        copy(data, buf[:n])

        // 记录本地应用地址(仅一个客户端)
        c.lastLocalAddr = srcAddr

        // 找到当前活跃线路
        idx := atomic.LoadInt64(&c.activeIndex)
        if idx < 0 || idx >= int64(len(c.links)) {
            continue
        }
        link := c.links[idx]

        // 统计上行流量
        atomic.AddInt64(&link.bytesSentInWindow, int64(n))

        // 发往远端(使用 upConn.WriteToUDP)
        signed := signPacket(c.clientPrivateKey, data)
        _, werr := c.upConn.WriteToUDP(signed, link.RemoteAddr)
        if werr != nil {
            if ne, ok := werr.(net.Error); ok && ne.Temporary() {
                log.Printf("[Client] 向远端发送临时错误: %v", werr)
                continue
            }
            log.Printf("[Client] 向远端发送严重错误: %v", werr)
            os.Exit(1)
        }
    }
}

func (c *UdpClient) handleUpConnRead() {
    defer c.wg.Done()
    buf := make([]byte, 64*1024)

    for {
        n, remoteAddr, err := c.upConn.ReadFromUDP(buf)
        if (n > c.config.MaxPacketSize) {
            continue
        }
        if err != nil {
            select {
            case <-c.stopChan:
                return
            default:
                if ne, ok := err.(net.Error); ok && ne.Temporary() {
                    log.Printf("[Client] 读远端临时错误: %v", err)
                    continue
                }
                log.Printf("[Client] 读远端严重错误: %v", err)
                os.Exit(1)
            }
        }

        data := make([]byte, n)
        copy(data, buf[:n])

        verifiedData, ok := verifyPacket(c.serverPublicKey, data)
        if (!ok) {
            // 丢弃
            continue
        }

        // 若是心跳响应
        if isHeartbeatPacket(verifiedData) && len(verifiedData) >= 20 { // 4+8+8=20
            sendNano := bytesToInt64(verifiedData[4:12])
            heartbeatID := bytesToUint64(verifiedData[12:20])
            
            // 检查时间戳,如果超过2秒就丢弃
            if time.Since(time.Unix(0, sendNano)) > 2*time.Second {
                if c.config.Debug {
                    log.Printf("[Debug] 丢弃过期心跳包")
                }
                continue
            }

            // 找到对应的link并验证心跳ID
            for _, link := range c.links {
                if link.RemoteAddr.IP.Equal(remoteAddr.IP) && link.RemoteAddr.Port == remoteAddr.Port {
                    link.mu.Lock()
                    // 检查ID是否是最新的
                    if heartbeatID <= link.lastReceivedID {
                        link.mu.Unlock()
                        if c.config.Debug {
                            log.Printf("[Debug] 丢弃过期心跳ID: received=%d, last=%d", 
                                heartbeatID, link.lastReceivedID)
                        }
                        continue
                    }
                    link.lastReceivedID = heartbeatID
                    link.mu.Unlock()

                    rtt := time.Since(time.Unix(0, sendNano))
                    c.updateLinkTest(remoteAddr, rtt)
                    break
                }
            }
            continue
        }

        // 否则是业务数据. 判断该 remoteAddr 是否是当前活跃线路
        idx := atomic.LoadInt64(&c.activeIndex)
        if idx >= 0 && idx < int64(len(c.links)) {
            link := c.links[idx]

            // 如果从当前活跃线路收来的包, 统计下行流量
            if link.RemoteAddr.IP.Equal(remoteAddr.IP) && link.RemoteAddr.Port == remoteAddr.Port {
                atomic.AddInt64(&link.bytesRecvInWindow, int64(n))
            }
        }

        // 回写本地应用(若上层还没发过包, lastLocalAddr 可能是 nil)
        if c.lastLocalAddr != nil {
            _, werr := c.listenConn.WriteToUDP(verifiedData, c.lastLocalAddr)
            if werr != nil {
                if ne, ok := werr.(net.Error); ok && ne.Temporary() {
                    log.Printf("[Client] 回写本地临时错误: %v", werr)
                    continue
                }
                log.Printf("[Client] 回写本地严重错误: %v", werr)
                os.Exit(1)
            }
        }
    }
}

// 刷新dns缓存
func (c *UdpClient) startDnsRefreshRoutine() {
    defer c.wg.Done()

    if c.config.DnsRefreshIntervalSec <= 0 {
        return
    }

    interval := time.Duration(c.config.DnsRefreshIntervalSec) * time.Second
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    for {
        select {
        case <-c.stopChan:
            return
        case <-ticker.C:
            c.refreshDns()
        }
    }
}

func (c *UdpClient) refreshDns() {
    for _, link := range c.links {
        addr, err := net.ResolveUDPAddr("udp", link.RemoteAddr.String())
        if err != nil {
            log.Printf("[Client] 刷新 DNS 失败: %v", err)
            continue
        }

        link.mu.Lock()
        link.RemoteAddr = addr
        link.mu.Unlock()

        if c.config.Debug {
            log.Printf("[Debug] DNS 刷新成功: %s -> %s", link.RemoteAddr.String(), addr.String())
        }
    }
}

// 心跳+测速: 每隔 HeartbeatIntervalSec 发送心跳
func (c *UdpClient) heartbeatRoutine() {
    defer c.wg.Done()

    interval := time.Duration(c.config.HeartbeatIntervalSec) * time.Second
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    // 初始化计数器
    tickCounter := 0

    for {
        select {
        case <-c.stopChan:
            return
        case <-ticker.C:
            if c.config.Debug {
                log.Printf("[Debug] heartbeatRoutine")
            }
            // 1) 发心跳
            c.sendHeartbeat()
            tickCounter++
            if tickCounter >= 10 {
                // 2) 选最佳线路
                c.selectBestLink()
                // 3) 重置吞吐窗口
                c.resetThroughputWindow()
                // 重置计数器
                tickCounter = 0
            }
        }
    }
}

func (c *UdpClient) sendHeartbeat() {
    now := time.Now().UnixNano()

    // 对每条线路都发送心跳, 即使它已标记为断线
    for _, link := range c.links {
        link.mu.Lock()
        // 构造心跳包: magic(4) + timestamp(8) + heartbeatID(8)
        id := atomic.AddUint64(&link.nextHeartbeatID, 1) - 1
        pkt := append(heartbeatMagic, int64ToBytes(now)...)
        pkt = append(pkt, uint64ToBytes(id)...)
        link.mu.Unlock()

        signedPkt := signPacket(c.clientPrivateKey, pkt)
        atomic.AddInt64(&link.testSent, 1)
        _, err := c.upConn.WriteToUDP(signedPkt, link.RemoteAddr)
        if err != nil {
            if ne, ok := err.(net.Error); ok && ne.Temporary() {
                log.Printf("[Client] 心跳发送临时错误 -> %s: %v", link.RemoteAddr, err)
                continue
            }
            log.Printf("[Client] 心跳发送严重错误 -> %s: %v", link.RemoteAddr, err)
        }
    }
}

func (c *UdpClient) updateLinkTest(remoteAddr *net.UDPAddr, rtt time.Duration) {
    // 根据 remoteAddr 找到对应的 link
    for _, link := range c.links {
        if link.RemoteAddr.IP.Equal(remoteAddr.IP) && link.RemoteAddr.Port == remoteAddr.Port {
            atomic.AddInt64(&link.testReceived, 1)
            // 计算丢包率
            sent := atomic.LoadInt64(&link.testSent)
            recv := atomic.LoadInt64(&link.testReceived)
            var loss float64
            if sent > 0 {
                loss = 1 - float64(recv)/float64(sent)
            }

            score := CalcScore(ScoreData{RTT: rtt, LossRate: loss},
                c.config.LossWeight, c.config.RttWeight)
            link.mu.Lock()
            link.ScoreHistory[link.HistoryIdx] = score
            link.HistoryIdx = (link.HistoryIdx + 1) % len(link.ScoreHistory)
            link.LastScore = score
            link.mu.Unlock()
            if c.config.Debug {
                log.Printf("[Debug] link=%s score=%.2f rtt=%v loss=%.2f",
                    link.RemoteAddr.String(), score, rtt, loss)
            }
            // 表示本次心跳成功
            atomic.StoreInt64(&link.ConsecutiveFail, 0)
            return
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

    // 找出平均分最高的 link
    for i, link := range c.links {
        fails := atomic.LoadInt64(&link.ConsecutiveFail)
        if fails >= int64(c.config.MaxConsecutiveFail) {
            continue
        }
        // 计算平均分
        link.mu.Lock()
        sum := 0.0
        count := 0
        for _, sc := range link.ScoreHistory {
            if sc != 0 {
                sum += sc
                count++
            }
        }
        var avg float64
        if count > 0 {
            avg = sum / float64(count)
        } else {
            avg = link.LastScore
        }
        link.mu.Unlock()

        if avg > bestAvgScore {
            bestAvgScore = avg
            bestIdx = i
        }
    }
    if c.config.Debug {
        log.Printf("[Debug] best Idx %v", bestIdx)
    }
    if bestIdx == -1 {
        // 所有线路都不可用
        log.Printf("[Client] 所有线路都不可用!")
        return
    }
    // 若已是当前线路, 不切
    if int64(bestIdx) == currIdx {
        return
    }

    // 若有现用线路, 看分数差是否足够
    if currLink != nil {
        // 计算当前线路平均分
        currLink.mu.Lock()
        sum := 0.0
        count := 0
        for _, sc := range currLink.ScoreHistory {
            if sc != 0 {
                sum += sc
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

        fails := atomic.LoadInt64(&currLink.ConsecutiveFail)
        if fails < int64(c.config.MaxConsecutiveFail) {
            diff := bestAvgScore - currAvg
            if diff < c.config.SwitchThreshold {
                return
            }
            // 判断是否当前线路流量过大, 不宜切换
            if c.isCurrentLinkBusy(currLink) {
                return
            }
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
    // 计算 (上行 + 下行) 吞吐量
    kbps := float64(sent+recv) * 8.0 / 1024.0 / dur.Seconds()
    if kbps >= c.config.ThroughputThresholdKbps {
        log.Printf("[Client] 当前线路吞吐=%.2f Kbps, 超过阈值=%.2f, 暂不切换",
            kbps, c.config.ThroughputThresholdKbps)
        return true
    }
    return false
}

func (c *UdpClient) resetThroughputWindow() {
    now := time.Now()
    for _, link := range c.links {
        link.mu.Lock()
        link.windowStart = now
        atomic.StoreInt64(&link.bytesSentInWindow, 0)
        atomic.StoreInt64(&link.bytesRecvInWindow, 0)

        // 未收到心跳时, 连续失败次数+1(粗略处理)
        // 也可更严格: 给每个心跳包设置序号+定时器
        sent := atomic.LoadInt64(&link.testSent)
        // recv := atomic.LoadInt64(&link.testReceived)
        if sent > 0 {
            // 本轮只要 testReceived 没变化 => fail+1
            // 但这里是简化, 真实环境下需更精细
            failNow := atomic.AddInt64(&link.ConsecutiveFail, 1)
            // 失败后, 依旧发心跳
            if failNow >= int64(c.config.MaxConsecutiveFail) {
                if c.config.Debug {
                    log.Printf("[Debug] 线路 %s 连续无响应, 判定断开!", link.RemoteAddr)
                }
            }
        }
        link.mu.Unlock()
    }
    if c.config.Debug {
        log.Printf("[Debug] resetThroughputWindowDone")
    }
}

// ==================== 服务端部分 ====================

type UdpServer struct {
    config     ServerConfig
    listenConn *net.UDPConn
    upConn     *net.UDPConn

    stopChan chan struct{}
    wg       sync.WaitGroup

    lastDataAddr      *net.UDPAddr
    mu                sync.RWMutex
    lastHeartbeatTime time.Time

    serverPrivateKey ed25519.PrivateKey
    clientPublicKey  ed25519.PublicKey
}

func NewUdpServer(cfg ServerConfig) (*UdpServer, error) {
    serverPrivateKey, clientPublicKey, err := parseServerKeys(cfg)
    if err != nil {
        return nil, fmt.Errorf("解析密钥失败: %v", err)
    }

    return &UdpServer{
        config:           cfg,
        stopChan:         make(chan struct{}),
        serverPrivateKey: serverPrivateKey,
        clientPublicKey:  clientPublicKey,
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

        if n > s.config.MaxPacketSize {
            continue
        }

        if err != nil {
            select {
            case <-s.stopChan:
                return
            default:
                if ne, ok := err.(net.Error); ok && ne.Temporary() {
                    log.Printf("[Server] 读取客户端临时错误: %v", err)
                    continue
                }
                log.Printf("[Server] 读取客户端严重错误: %v", err)
                os.Exit(1)
            }
        }

        data := make([]byte, n)
        copy(data, buf[:n])

        verifiedData, ok := verifyPacket(s.clientPublicKey, data)
        if !ok {
            // 丢弃
            continue
        }

        // 如果是心跳包
        if isHeartbeatPacket(verifiedData) && len(verifiedData) >= 12 {
            s.mu.Lock()
            s.lastHeartbeatTime = time.Now()
            s.lastDataAddr = clientAddr
            s.mu.Unlock()

            // 原样回
            signed := signPacket(s.serverPrivateKey, verifiedData)
            _, _ = s.listenConn.WriteToUDP(signed, clientAddr)
            continue
        }

        // 否则是业务数据
        s.mu.Lock()
        s.lastDataAddr = clientAddr
        s.lastHeartbeatTime = time.Now()
        s.mu.Unlock()

        _, werr := s.upConn.Write(verifiedData)
        if werr != nil {
            if ne, ok := werr.(net.Error); ok && ne.Temporary() {
                log.Printf("[Server] 向上游发送临时错误: %v", werr)
                continue
            }
            log.Printf("[Server] 向上游发送严重错误: %v", werr)
            os.Exit(1)
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
                log.Printf("[Server] 读取上游严重错误: %v", err)
                os.Exit(1)
            }
        }

        data := make([]byte, n)
        copy(data, buf[:n])

        s.mu.RLock()
        addr := s.lastDataAddr
        s.mu.RUnlock()

        if addr != nil {
            signed := signPacket(s.serverPrivateKey, data)
            _, werr := s.listenConn.WriteToUDP(signed, addr)
            if werr != nil {
                if ne, ok := werr.(net.Error); ok && ne.Temporary() {
                    log.Printf("[Server] 回写客户端临时错误: %v", werr)
                    continue
                }
                log.Printf("[Server] 回写客户端严重错误: %v", werr)
                os.Exit(1)
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
                s.mu.Lock()
                if s.lastDataAddr != nil {
                    log.Printf("[Server] 心跳超时，清理客户端地址: %v", s.lastDataAddr)
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
        log.Printf("[Server] 服务器启动完毕 (listen=%s, upstream=%s)",
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
        log.Printf("[Client] 客户端启动完毕 (listen=%s)", cfg.Client.ListenAddr)
        select {}
    } else {
        log.Fatalf("无效的模式: %s (必须是 server 或 client)", cfg.Mode)
    }
}

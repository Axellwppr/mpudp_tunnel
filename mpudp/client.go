package main

import (
    "context"
    "fmt"
    "log"
    "math"
    "net"
    "os"
    "sync"
    "sync/atomic"
    "time"
    "crypto/ed25519"
)

type ClientLink struct {
    RemoteAddr      *net.UDPAddr
    ConsecutiveFail int64

    // 心跳测速用
    testSent int64
    testLost int64

    // 新增用于记录 RTT
    accRTT   int64
    rttCount int64

    // 用于统计吞吐量 (上行 + 下行)
    bytesSentInWindow int64
    bytesRecvInWindow int64
    windowStart       time.Time
    mu                sync.Mutex

    nextHeartbeatID    uint64
    heartbeatSentTimes map[uint64]time.Time
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
            RemoteAddr:         addr,
            nextHeartbeatID:    1,
            heartbeatSentTimes: make(map[uint64]time.Time), // 新增
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
    lAddr, err := net.ResolveUDPAddr("udp", c.config.ListenAddr)
    if err != nil {
        return fmt.Errorf("解析本地监听地址失败: %w", err)
    }
    c.listenConn, err = net.ListenUDP("udp", lAddr)
    if err != nil {
        return fmt.Errorf("listenConn 监听失败: %w", err)
    }
    log.Printf("[Client] listenConn 已监听: %s", c.config.ListenAddr)

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

            c.updateLinkTest(remoteAddr, heartbeatID, sendNano)
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

func (c *UdpClient) updateLinkTest(remoteAddr *net.UDPAddr, heartbeatID uint64, sendNano int64) {
    now := time.Now()
    for _, link := range c.links {
        if link.RemoteAddr.IP.Equal(remoteAddr.IP) && link.RemoteAddr.Port == remoteAddr.Port {
            link.mu.Lock()

            // 先判断这个heartbeatID是否在发送记录中
            sendTime, found := link.heartbeatSentTimes[heartbeatID]
            if !found {
                // 未找到，说明是非常旧的包或重复包，直接丢弃
                link.mu.Unlock()
                return
            }

            // 计算 RTT
            rtt := now.Sub(sendTime)
            atomic.AddInt64(&link.accRTT, rtt.Milliseconds())
            atomic.AddInt64(&link.rttCount, 1)

            // 心跳包匹配成功，移除
            delete(link.heartbeatSentTimes, heartbeatID)

            for oldID, _ := range link.heartbeatSentTimes {
                if oldID < heartbeatID {
                    // 认为它们已丢失
                    delete(link.heartbeatSentTimes, oldID)
                    atomic.AddInt64(&link.testLost, 1)
                }
            }

            // 表示本次心跳成功 => 连续失败清零
            atomic.StoreInt64(&link.ConsecutiveFail, 0)

            link.mu.Unlock()
            return
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

    interval := time.Duration(int64(c.config.HeartbeatIntervalSec * 1000)) * time.Millisecond
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
            c.checkHeartbeatTimeout()
            tickCounter++
            if tickCounter >= 20 {
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
    now := time.Now()

    // 对每条线路都发送心跳, 即使它已标记为断线
    for _, link := range c.links {
        link.mu.Lock()
        id := atomic.AddUint64(&link.nextHeartbeatID, 1) - 1
        link.heartbeatSentTimes[id] = now
        link.mu.Unlock()
        pkt := append(heartbeatMagic, int64ToBytes(now.UnixNano())...)
        pkt = append(pkt, uint64ToBytes(id)...)

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

func (c *UdpClient) checkHeartbeatTimeout() {
    now := time.Now()
    for _, link := range c.links {
        link.mu.Lock()

        for hbID, t := range link.heartbeatSentTimes {
            if now.Sub(t) > 2*time.Second {
                // 视为超时，移除记录
                delete(link.heartbeatSentTimes, hbID)
                // 连续失败 +1
                atomic.AddInt64(&link.ConsecutiveFail, 1)
                atomic.AddInt64(&link.testLost, 1)
            }
        }

        link.mu.Unlock()
    }
}

func (c *UdpClient) selectBestLink() {
    bestIdx := -1
    bestScore := -math.MaxFloat64

    currIdx := atomic.LoadInt64(&c.activeIndex)
    currScore := -math.MaxFloat64

    // 找出平均分最高的 link
    for i, link := range c.links {
        fails := atomic.LoadInt64(&link.ConsecutiveFail)

        sent := atomic.SwapInt64(&link.testSent, 0)
        lost := atomic.SwapInt64(&link.testLost, 0)

        rttSum := atomic.SwapInt64(&link.accRTT, 0)
        rttCount := atomic.SwapInt64(&link.rttCount, 0)

        if fails >= int64(c.config.MaxConsecutiveFail) {
            if c.config.Debug {
                log.Printf("[Debug] %d 连续失败次数过多: %d", i, fails)
            }
            continue
        }

        // 计算丢包率
        if sent == 0 {
            continue
        }
        loss := float64(lost) / float64(sent)

        // 计算 RTT
        if rttCount == 0 {
            continue
        }
        rtt := float64(rttSum) / float64(rttCount)

        // 根据 rtt 和 loss 算分
        score := CalcScore(ScoreData{RTT: rtt, LossRate: loss}, c.config.LossWeight, c.config.RttWeight)

        if score > bestScore {
            bestScore = score
            bestIdx = i
        }

        if int64(i) == currIdx {
            currScore = score
        }

        if c.config.Debug {
            log.Printf("[Debug] %d: sent=%d, lost=%d, loss=%.2f, rtt=%.2f, score=%.2f", i, sent, lost, loss, rtt, score)
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

    if (bestScore - currScore) < c.config.SwitchThreshold {
        return
    }

    if (currIdx >= 0) && (currIdx < int64(len(c.links))) {
        if c.isCurrentLinkBusy(c.links[currIdx]) {
            return
        }
    }

    // 切换
    log.Printf("[Client] 切换线路: %d -> %d (avgScore=%.2f)", currIdx, bestIdx, bestScore)
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
        link.mu.Unlock()
    }
    if c.config.Debug {
        log.Printf("[Debug] resetThroughputWindowDone")
    }
}

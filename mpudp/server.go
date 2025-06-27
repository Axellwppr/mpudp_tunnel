package main

import (
    "context"
    "fmt"
    "log"
    "net"
    "os"
    "sync"
    "time"
    "github.com/cloudflare/circl/sign/ed25519"
)

type ClientState struct {
    upConn            *net.UDPConn
    lastDataAddr      *net.UDPAddr
    lastHeartbeatTime time.Time
    mu                sync.RWMutex
}

type UdpServer struct {
    config     ServerConfig
    listenConn *net.UDPConn

    // 每个客户端的状态
    clientStates     []*ClientState
    serverPrivateKey ed25519.PrivateKey
    clientPublicKeys []ed25519.PublicKey

    stopChan chan struct{}
    wg       sync.WaitGroup
}

func NewUdpServer(cfg ServerConfig) (*UdpServer, error) {
    serverPrivateKey, clientPublicKeys, err := parseServerKeys(cfg)
    if err != nil {
        return nil, fmt.Errorf("解析密钥失败: %v", err)
    }

    // 验证配置的一致性
    if len(cfg.UpstreamAddrs) != len(cfg.ClientPublicKeysBase64) {
        return nil, fmt.Errorf("上游地址数量(%d)与客户端公钥数量(%d)不匹配", 
            len(cfg.UpstreamAddrs), len(cfg.ClientPublicKeysBase64))
    }

    // 初始化客户端状态
    clientStates := make([]*ClientState, len(cfg.UpstreamAddrs))
    for i := range clientStates {
        clientStates[i] = &ClientState{}
    }

    return &UdpServer{
        config:           cfg,
        clientStates:     clientStates,
        stopChan:         make(chan struct{}),
        serverPrivateKey: serverPrivateKey,
        clientPublicKeys: clientPublicKeys,
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

    // 为每个客户端建立上游连接
    for i, upstreamAddr := range s.config.UpstreamAddrs {
        upAddr, err := net.ResolveUDPAddr("udp", upstreamAddr)
        if err != nil {
            return fmt.Errorf("解析客户端%d上游地址失败: %w", i, err)
        }
        s.clientStates[i].upConn, err = net.DialUDP("udp", nil, upAddr)
        if err != nil {
            return fmt.Errorf("连接客户端%d上游失败: %w", i, err)
        }
        log.Printf("[Server] 客户端%d上游地址: %s", i, upstreamAddr)
    }

    // 启动读客户端数据
    s.wg.Add(1)
    go s.handleClientRead()

    // 为每个客户端启动读上游数据的goroutine
    for i := range s.config.UpstreamAddrs {
        s.wg.Add(1)
        go s.handleUpServerRead(i)
    }

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
    for _, state := range s.clientStates {
        if state.upConn != nil {
            _ = state.upConn.Close()
        }
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

        if isHeartbeatPacket(buf[:n]) {
            // 处理心跳包
            s.handleHeartbeatPacket(buf[:n], clientAddr)
        } else {
            // 处理普通数据包
            s.handleDataPacket(buf[:n], clientAddr)
        }
    }
}

func (s *UdpServer) handleHeartbeatPacket(data []byte, clientAddr *net.UDPAddr) {
    // 先验证签名并提取数据
    verifiedData, clientID, ok := s.verifyAndExtractClientData(data)
    if !ok {
        return
    }

    if clientID >= len(s.clientStates) {
        log.Printf("[Server] 无效的客户端ID: %d", clientID)
        return
    }

    // 检查激活标志（现在位置是verifiedData[20]，因为有client ID）
    if len(verifiedData) > 20 && verifiedData[20] == activeMagic[0] {
        state := s.clientStates[clientID]
        state.mu.Lock()
        state.lastHeartbeatTime = time.Now()
        state.lastDataAddr = clientAddr
        state.mu.Unlock()
        log.Printf("[Server] 客户端%d心跳更新: %v", clientID, clientAddr)
    }

    // 回签名并发送响应
    signed := signPacket(s.serverPrivateKey, verifiedData)
    _, _ = s.listenConn.WriteToUDP(signed, clientAddr)
}

func (s *UdpServer) handleDataPacket(data []byte, clientAddr *net.UDPAddr) {
    if len(data) < 1 {
        return
    }

    clientID := int(data[0])
    if clientID >= len(s.clientStates) {
        log.Printf("[Server] 数据包包含无效的客户端ID: %d", clientID)
        return
    }

    // 提取实际数据（去掉client ID）
    actualData := data[1:]
    
    // 发送到对应的上游
    state := s.clientStates[clientID]
    _, werr := state.upConn.Write(actualData)
    if werr != nil {
        if ne, ok := werr.(net.Error); ok && ne.Temporary() {
            log.Printf("[Server] 向客户端%d上游发送临时错误: %v", clientID, werr)
            return
        }
        log.Printf("[Server] 向客户端%d上游发送严重错误: %v", clientID, werr)
        os.Exit(1)
    }
}

func (s *UdpServer) verifyAndExtractClientData(data []byte) ([]byte, int, bool) {
    if len(data) < ed25519.SignatureSize + 1 {
        return nil, 0, false
    }

    sig := data[:ed25519.SignatureSize]
    signedData := data[ed25519.SignatureSize:]
    
    if len(signedData) < 1 {
        return nil, 0, false
    }

    clientID := int(signedData[0])
    if clientID >= len(s.clientPublicKeys) {
        return nil, 0, false
    }

    // 验证签名
    if ed25519.Verify(s.clientPublicKeys[clientID], signedData, sig) {
        return signedData, clientID, true
    }
    return nil, 0, false
}

func (s *UdpServer) handleUpServerRead(clientID int) {
    defer s.wg.Done()
    buf := make([]byte, 64*1024)
    state := s.clientStates[clientID]

    for {
        n, err := state.upConn.Read(buf)
        if err != nil {
            select {
            case <-s.stopChan:
                return
            default:
                if ne, ok := err.(net.Error); ok && ne.Temporary() {
                    log.Printf("[Server] 读取客户端%d上游临时错误: %v", clientID, err)
                    continue
                }
                log.Printf("[Server] 读取客户端%d上游严重错误: %v", clientID, err)
                os.Exit(1)
            }
        }

        state.mu.RLock()
        addr := state.lastDataAddr
        state.mu.RUnlock()

        if addr != nil {
            _, werr := s.listenConn.WriteToUDP(buf[:n], addr)
            if werr != nil {
                if ne, ok := werr.(net.Error); ok && ne.Temporary() {
                    log.Printf("[Server] 回写客户端%d临时错误: %v", clientID, werr)
                    continue
                }
                log.Printf("[Server] 回写客户端%d严重错误: %v", clientID, werr)
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
            for i, state := range s.clientStates {
                state.mu.RLock()
                last := state.lastHeartbeatTime
                state.mu.RUnlock()

                if time.Since(last) > timeout {
                    state.mu.Lock()
                    if state.lastDataAddr != nil {
                        log.Printf("[Server] 客户端%d心跳超时，清理地址: %v", i, state.lastDataAddr)
                    }
                    state.lastDataAddr = nil
                    state.mu.Unlock()
                }
            }
        }
    }
}

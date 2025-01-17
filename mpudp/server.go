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

        if isHeartbeatPacket(buf[:n]){
            // 仅对心跳包进行验签
            verifiedData, ok := verifyPacket(s.clientPublicKey, buf[:n])
            if !ok {
                // 验签不通过，丢弃
                continue
            }

            // 如果该心跳包为激活包，则更新客户端地址
            if verifiedData[20] == activeMagic[0] {
                s.mu.Lock()
                s.lastHeartbeatTime = time.Now()
                s.lastDataAddr = clientAddr
                s.mu.Unlock()
            }

            // 回签名
            signed := signPacket(s.serverPrivateKey, verifiedData)
            _, _ = s.listenConn.WriteToUDP(signed, clientAddr)
        } else {
            // 直接把原始数据写给上游，不做签名
            _, werr := s.upConn.Write(buf[:n])
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

        s.mu.RLock()
        addr := s.lastDataAddr
        s.mu.RUnlock()

        if addr != nil {
            _, werr := s.listenConn.WriteToUDP(buf[:n], addr)
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

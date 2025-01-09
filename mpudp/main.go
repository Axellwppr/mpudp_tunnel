package main

import (
    "context"
    "encoding/json"
    "log"
    "os"
    "flag"
)

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

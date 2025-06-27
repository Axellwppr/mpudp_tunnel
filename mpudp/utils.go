package main

import (
    "github.com/cloudflare/circl/sign/ed25519"
    "encoding/base64"
    "fmt"
)

var heartbeatMagic = []byte{0xFF, 0x00, 0xFF, 0x00}

var nonActiveMagic = []byte{0x00}
var activeMagic = []byte{0xFF}

func isHeartbeatPacket(data []byte) bool {
    // 心跳包长度 = 签名(64) + client_id(1) + magic(4) + timestamp(8) + heartbeat_id(8) + active_flag(1) = 86字节
    if len(data) != ed25519.SignatureSize + 22 {
        return false
    }
    // 检查magic字节，现在位置偏移1字节（因为client ID）
    magicOffset := ed25519.SignatureSize + 1
    for i := 0; i < 4; i++ {
        if data[magicOffset + i] != heartbeatMagic[i] {
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
    RTT      float64
    LossRate float64 // 0~1
}

func CalcScore(sd ScoreData, lossWeight, rttWeight float64) float64 {
    rttMs := sd.RTT
    lossPct := sd.LossRate * 100
    return -(lossWeight*lossPct + rttWeight*rttMs)
}


// 服务端解析密钥 - 修改为支持多个客户端
func parseServerKeys(cfg ServerConfig) (ed25519.PrivateKey, []ed25519.PublicKey, error) {
    // 解码私钥
    skBytes, err := base64.StdEncoding.DecodeString(cfg.ServerPrivateKeyBase64)
    if err != nil {
        return nil, nil, fmt.Errorf("解码服务器私钥失败: %v", err)
    }
    if len(skBytes) != ed25519.PrivateKeySize {
        return nil, nil, fmt.Errorf("服务器私钥长度错误")
    }
    serverPrivateKey := ed25519.PrivateKey(skBytes)

    // 解码多个客户端公钥
    clientPublicKeys := make([]ed25519.PublicKey, len(cfg.ClientPublicKeysBase64))
    for i, pkBase64 := range cfg.ClientPublicKeysBase64 {
        pkBytes, err := base64.StdEncoding.DecodeString(pkBase64)
        if err != nil {
            return nil, nil, fmt.Errorf("解码客户端%d公钥失败: %v", i, err)
        }
        if len(pkBytes) != ed25519.PublicKeySize {
            return nil, nil, fmt.Errorf("客户端%d公钥长度错误", i)
        }
        clientPublicKeys[i] = ed25519.PublicKey(pkBytes)
    }

    return serverPrivateKey, clientPublicKeys, nil
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

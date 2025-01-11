package main

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
    HeartbeatIntervalSec    float64      `json:"heartbeat_interval_sec"`
    LossWeight              float64      `json:"loss_weight"`
    RttWeight               float64      `json:"rtt_weight"`
    SwitchThreshold         float64      `json:"switch_threshold"`
    ThroughputThresholdKbps float64      `json:"throughput_threshold_kbps"`
    MaxConsecutiveFail      int          `json:"max_consecutive_fail"`
    DnsRefreshIntervalSec   int          `json:"dns_refresh_interval_sec"`
    Debug                   bool          `json:"debug"`
    ClientPrivateKeyBase64  string       `json:"client_private_key"`
    ServerPublicKeyBase64   string       `json:"server_public_key"`
    MaxPacketSize          int          `json:"max_packet_size"`
}

type LinkConfig struct {
    RemoteAddr string  `json:"remote_addr"`
    Priority   float64 `json:"priority"` // 优先级，数值越大优先级越低
}

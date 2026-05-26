package main

import (
	"encoding/json"
	"log"
	"net"
	"os"

	"go-socks5/socks5"
)

// JSONConfig 是 config.json 对应的结构体
type JSONConfig struct {
	// 监听地址，例如 "127.0.0.1:8000"
	Listen string `json:"listen"`

	// 认证配置
	Auth *AuthConfig `json:"auth,omitempty"`

	// BIND/UDP 绑定的 IP
	BindIP string `json:"bind_ip,omitempty"`

	// 出站连接绑定的本地地址，例如 "192.168.1.100:0"
	LocalAddr string `json:"local_addr,omitempty"`

	// 访问规则
	Rules *RulesConfig `json:"rules,omitempty"`

	// 日志配置
	Log *LogConfig `json:"log,omitempty"`
}

// AuthConfig 认证配置
type AuthConfig struct {
	// 认证方式: "none" | "password"
	Method string `json:"method"`

	// 用户名密码表（method 为 "password" 时生效）
	Credentials map[string]string `json:"credentials,omitempty"`
}

// RulesConfig 访问规则
type RulesConfig struct {
	AllowConnect   bool `json:"allow_connect"`
	AllowBind      bool `json:"allow_bind"`
	AllowAssociate bool `json:"allow_associate"`
}

// LogConfig 日志配置
type LogConfig struct {
	// 日志文件路径，为空则输出到 stdout
	File string `json:"file,omitempty"`

	// 日志前缀，例如 "[SOCKS5] "
	Prefix string `json:"prefix,omitempty"`
}

func main() {
	conf, listenAddr, err := buildConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	if err := server.ListenAndServe("tcp", listenAddr); err != nil {
		panic(err)
	}
}

// buildConfig 读取 config.json 并转换为 socks5.Config，同时返回监听地址
func buildConfig(path string) (*socks5.Config, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()

	var jc JSONConfig
	if err := json.NewDecoder(f).Decode(&jc); err != nil {
		return nil, "", err
	}

	conf := &socks5.Config{}

	// ─── 认证 ───────────────────────────────────────────────────
	if jc.Auth != nil && jc.Auth.Method == "password" {
		if len(jc.Auth.Credentials) > 0 {
			conf.Credentials = socks5.StaticCredentials(jc.Auth.Credentials)
		}
	}

	// ─── 访问规则 ───────────────────────────────────────────────
	if jc.Rules != nil {
		conf.Rules = &socks5.PermitCommand{
			EnableConnect:   jc.Rules.AllowConnect,
			EnableBind:      jc.Rules.AllowBind,
			EnableAssociate: jc.Rules.AllowAssociate,
		}
	}

	// ─── Bind IP ────────────────────────────────────────────────
	if jc.BindIP != "" {
		conf.BindIP = net.ParseIP(jc.BindIP)
	}

	// ─── 本地地址绑定 ────────────────────────────────────────────
	conf.LocalAddr = jc.LocalAddr

	// ─── 日志 ───────────────────────────────────────────────────
	if jc.Log != nil {
		w := os.Stdout
		prefix := "[SOCKS5] "
		if jc.Log.File != "" {
			f, err := os.OpenFile(jc.Log.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return nil, "", err
			}
			w = f
		}
		if jc.Log.Prefix != "" {
			prefix = jc.Log.Prefix
		}
		conf.Logger = log.New(w, prefix, log.LstdFlags)
	}

	listenAddr := jc.Listen
	if listenAddr == "" {
		listenAddr = "127.0.0.1:8000"
	}

	return conf, listenAddr, nil
}

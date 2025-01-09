package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"crypto/ed25519"
)

func main() {
	// 生成密钥对
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// 将私钥和公钥编码为Base64字符串
	privKeyBase64 := base64.StdEncoding.EncodeToString(privKey)
	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKey)

	// 打印私钥和公钥
	fmt.Println("Private Key (Base64):", privKeyBase64)
	fmt.Println("Public Key (Base64):", pubKeyBase64)
}

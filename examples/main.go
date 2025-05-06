package main

import (
	"bytes"
	"fmt"
	"log"
	"os"

	pqmagic "github.com/pqcrypto-cn/PQMagic-Go"
)

func main() {
	fmt.Println("--- PQMagic Go 封装示例 ---")
	fmt.Println("注意：运行前请确保已正确设置 CGO_CFLAGS 和 CGO_LDFLAGS 环境变量！")
	fmt.Printf("示例 CGO_CFLAGS: %s\n", os.Getenv("CGO_CFLAGS"))
	fmt.Printf("示例 CGO_LDFLAGS: %s\n", os.Getenv("CGO_LDFLAGS"))
	fmt.Println("对于共享库，可能还需要设置运行时链接器路径 (Linux: LD_LIBRARY_PATH, macOS: DYLD_LIBRARY_PATH, Win: PATH)。")
	fmt.Println("---------------------------------")

	fmt.Println("\n--- 测试 ML-KEM 768 ---")
	kemPk, kemSk, err := pqmagic.KeyPairMlKem768()
	if err != nil {
		log.Fatalf("ML-KEM KeyPair 失败: %v", err)
	}
	fmt.Printf("ML-KEM 公钥长度: %d, 私钥长度: %d\n", len(kemPk), len(kemSk))

	ct, ssEnc, err := pqmagic.EncapsulateMlKem768(kemPk)
	if err != nil {
		log.Fatalf("ML-KEM Encapsulate 失败: %v", err)
	}
	fmt.Printf("ML-KEM 密文长度: %d, 封装的共享密钥长度: %d\n", len(ct), len(ssEnc))

	ssDec, err := pqmagic.DecapsulateMlKem768(kemSk, ct)
	if err != nil {

		if err == pqmagic.ErrPqmagicDecapsulationFailed {
			log.Fatalf("ML-KEM Decapsulate 失败 (这是预期的错误类型，但操作本身失败了): %v", err)
		} else {
			log.Fatalf("ML-KEM Decapsulate 发生意外错误: %v", err)
		}
	}
	fmt.Printf("ML-KEM 解封装的共享密钥长度: %d\n", len(ssDec))

	if !bytes.Equal(ssEnc, ssDec) {
		log.Fatalf("ML-KEM 共享密钥不匹配！")
	}
	fmt.Println("ML-KEM 封装/解封装成功，共享密钥匹配。")

	fmt.Println("\n--- 测试 ML-DSA 65 ---")
	sigPk, sigSk, err := pqmagic.KeyPairMlDsa65()
	if err != nil {
		log.Fatalf("ML-DSA KeyPair 失败: %v", err)
	}
	fmt.Printf("ML-DSA 公钥长度: %d, 私钥长度: %d\n", len(sigPk), len(sigSk))

	message := []byte("这是要签名的消息。")

	context := []byte{}

	signature, err := pqmagic.SignMlDsa65(sigSk, message, context)
	if err != nil {
		log.Fatalf("ML-DSA Sign 失败: %v", err)
	}
	fmt.Printf("ML-DSA 签名长度: %d\n", len(signature))

	err = pqmagic.VerifyMlDsa65(sigPk, message, signature, context)
	if err != nil {
		log.Fatalf("ML-DSA Verify 意外失败: %v", err)
	}
	fmt.Println("ML-DSA 验签成功 (签名正确)。")

	tamperedMessage := []byte("这不是要签名的消息。")
	err = pqmagic.VerifyMlDsa65(sigPk, tamperedMessage, signature, context)
	if err == nil {
		log.Fatalf("ML-DSA Verify 对篡改的消息意外成功！")
	} else if err == pqmagic.ErrPqmagicVerificationFailed {
		fmt.Println("ML-DSA 验签失败 (篡改消息，符合预期)。")
	} else {
		log.Fatalf("ML-DSA Verify 对篡改消息失败，但错误类型非预期: %v", err)
	}

	tamperedSignature := make([]byte, len(signature))
	copy(tamperedSignature, signature)
	if len(tamperedSignature) > 0 {
		tamperedSignature[0] ^= 0xff
	} else {
		log.Println("警告：签名为空，无法篡改第一个字节。")
	}
	err = pqmagic.VerifyMlDsa65(sigPk, message, tamperedSignature, context)
	if err == nil {
		log.Fatalf("ML-DSA Verify 对篡改的签名意外成功！")
	} else if err == pqmagic.ErrPqmagicVerificationFailed {
		fmt.Println("ML-DSA 验签失败 (篡改签名，符合预期)。")
	} else {
		log.Fatalf("ML-DSA Verify 对篡改签名失败，但错误类型非预期: %v", err)
	}

	fmt.Println("\n--- 示例结束 ---")
}

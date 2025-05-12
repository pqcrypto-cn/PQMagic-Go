# PQMagic-Go

The Golang bindings for PQMagic [https://github.com/pqcrypto-cn/PQMagic](https://github.com/pqcrypto-cn/PQMagic).

---

1. 构建并安装 [PQMagic](https://github.com/pqcrypto-cn/PQMagic) C 库 (如果尚未完成):
   - 确保已在 `/PQMagic-main/build/installdir` 成功安装。

2. 设置 CGO 环境变量:
   - 在运行 `go build` 或 `go run` *之前*，在你的终端会话中设置：

    ```shell
    export PQMAGIC_INSTALL_DIR="/PQMagic-main/build/installdir"
    export CGO_CFLAGS="-I${PQMAGIC_INSTALL_DIR}/include"
    export CGO_LDFLAGS="-L${PQMAGIC_INSTALL_DIR}/lib -lpqmagic_std"
    ```

3. 设置运行时链接器路径 (macOS):
   - 因为库安装在非标准路径，运行时需要找到 .dylib 文件：

    ```shell
    export DYLD_LIBRARY_PATH="${PQMAGIC_INSTALL_DIR}/lib:$
    {DYLD_LIBRARY_PATH}"
    ```

4. 构建和运行 Go 示例:
   - 确保你在执行了上述 `export` 命令的 *同一个终端会话* 中。
   - 进入 Go 项目目录: `cd "/pqmagic-go"`
   - 运行 Go 命令:

    ```shell
    go mod tidy
    go build ./...       # 尝试构建
    go run ./examples/main.go # 运行示例
    ```

5. 使用 PQMagic Go 封装:
   - 可使用两种调用风格：

   a. 对象风格 API (推荐):

    ```go
    kem := pqmagic.NewKEM("ML_KEM_768")
    pk, sk, err := kem.KeyPair()
    ct, ssEnc, err := kem.Encaps(pk)
    ssDec, err := kem.Decaps(sk, ct)

    dsa := pqmagic.NewDSA("ML_DSA_65")
    pk, sk, err := dsa.KeyPair()
    signature, err := dsa.Sign(sk, message, context)
    err = dsa.Verify(pk, message, signature, context)
    ```

   b. 函数风格 API (向后兼容):

    ```go
    pk, sk, err := pqmagic.KeyPairMlKem768()
    ct, ssEnc, err := pqmagic.EncapsulateMlKem768(pk)
    ssDec, err := pqmagic.DecapsulateMlKem768(sk, ct)
    ```

6. 扩展封装:
   - 按照 `pqmagic.go` 中的模式添加更多函数的封装。
   - 在 `pqmagic_const.go` 中添加对应的常量。
   - 扩展 KEM 或 DSA 结构体以支持更多算法。
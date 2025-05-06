package pqmagic

import (
	"errors"
	"fmt"
)

var (
	ErrPqmagicOperationFailed         = errors.New("pqmagic: 底层 C 库操作失败")
	ErrPqmagicVerificationFailed      = errors.New("pqmagic: 验签失败")
	ErrPqmagicDecapsulationFailed     = errors.New("pqmagic: 解封装失败")
	ErrPqmagicInvalidKeyLength        = errors.New("pqmagic: 无效的密钥长度")
	ErrPqmagicInvalidSignatureLength  = errors.New("pqmagic: 无效的签名长度")
	ErrPqmagicInvalidCiphertextLength = errors.New("pqmagic: 无效的密文长度")
	ErrPqmagicInvalidInputLength      = errors.New("pqmagic: 无效的输入数据长度")
	ErrPqmagicBufferTooSmall          = errors.New("pqmagic: 提供的输出缓冲区过小")
)

func handleCReturnCode(ret CInt, successRet CInt, specificFailError error) error {
	if ret == successRet {
		return nil
	}

	if specificFailError == ErrPqmagicVerificationFailed || specificFailError == ErrPqmagicDecapsulationFailed {

		return specificFailError
	}

	if ret < 0 {

		return ErrPqmagicOperationFailed
	}

	return fmt.Errorf("%w: C library returned unexpected code %d", ErrPqmagicOperationFailed, ret)
}

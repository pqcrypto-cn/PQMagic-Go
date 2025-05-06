package pqmagic

/*













#cgo CFLAGS: -I/usr/local/include
#cgo LDFLAGS: -L/usr/local/lib -lpqmagic_std


#include <stdlib.h>

#include <pqmagic_api.h>

*/
import "C"

import (
	"runtime"
	"sync"
	"unsafe"
)

var pqmagicMutex sync.Mutex

type CInt C.int

func KeyPairMlKem768() ([]byte, []byte, error) {
	pk := make([]byte, MlKem768PublicKeyBytes)
	sk := make([]byte, MlKem768SecretKeyBytes)

	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))

	pqmagicMutex.Lock()
	ret := C.pqmagic_ml_kem_768_std_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()

	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}

	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func EncapsulateMlKem768(pk []byte) ([]byte, []byte, error) {
	if len(pk) != MlKem768PublicKeyBytes {
		return nil, nil, ErrPqmagicInvalidKeyLength
	}

	ct := make([]byte, MlKem768CiphertextBytes)
	ss := make([]byte, MlKem768SharedSecretBytes)

	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cCtPtr := (*C.uchar)(unsafe.Pointer(&ct[0]))
	cSsPtr := (*C.uchar)(unsafe.Pointer(&ss[0]))

	pqmagicMutex.Lock()
	ret := C.pqmagic_ml_kem_768_std_enc(cCtPtr, cSsPtr, cPkPtr)
	pqmagicMutex.Unlock()

	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}

	runtime.KeepAlive(pk)
	runtime.KeepAlive(ct)
	runtime.KeepAlive(ss)
	return ct, ss, nil
}

func DecapsulateMlKem768(sk []byte, ct []byte) ([]byte, error) {
	if len(sk) != MlKem768SecretKeyBytes {
		return nil, ErrPqmagicInvalidKeyLength
	}
	if len(ct) != MlKem768CiphertextBytes {
		return nil, ErrPqmagicInvalidCiphertextLength
	}

	ss := make([]byte, MlKem768SharedSecretBytes)

	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	cCtPtr := (*C.uchar)(unsafe.Pointer(&ct[0]))
	cSsPtr := (*C.uchar)(unsafe.Pointer(&ss[0]))

	pqmagicMutex.Lock()
	ret := C.pqmagic_ml_kem_768_std_dec(cSsPtr, cCtPtr, cSkPtr)
	pqmagicMutex.Unlock()

	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicDecapsulationFailed); err != nil {

		return nil, err
	}

	runtime.KeepAlive(sk)
	runtime.KeepAlive(ct)
	runtime.KeepAlive(ss)
	return ss, nil
}

func KeyPairMlDsa65() ([]byte, []byte, error) {
	pk := make([]byte, MlDsa65PublicKeyBytes)
	sk := make([]byte, MlDsa65SecretKeyBytes)

	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))

	pqmagicMutex.Lock()
	ret := C.pqmagic_ml_dsa_65_std_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()

	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}

	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func SignMlDsa65(sk []byte, message []byte, context []byte) ([]byte, error) {
	if len(sk) != MlDsa65SecretKeyBytes {
		return nil, ErrPqmagicInvalidKeyLength
	}

	sigBuf := make([]byte, MlDsa65SignatureBytes)
	var actualSigLen C.size_t

	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	cSigPtr := (*C.uchar)(unsafe.Pointer(&sigBuf[0]))

	cMsgPtr := C.CBytes(message)
	defer C.free(unsafe.Pointer(cMsgPtr))

	var cCtxPtr *C.uchar = nil
	var cCtxLen C.size_t = 0
	if len(context) > 0 {
		cCtxPtr = (*C.uchar)(C.CBytes(context))
		defer C.free(unsafe.Pointer(cCtxPtr))
		cCtxLen = C.size_t(len(context))
	}

	pqmagicMutex.Lock()
	ret := C.pqmagic_ml_dsa_65_std_signature(
		cSigPtr,
		&actualSigLen,
		(*C.uchar)(cMsgPtr), C.size_t(len(message)),
		cCtxPtr, cCtxLen,
		cSkPtr,
	)
	pqmagicMutex.Unlock()

	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, err
	}

	if actualSigLen > MlDsa65SignatureBytes {

		return nil, ErrPqmagicBufferTooSmall
	}

	finalSig := make([]byte, int(actualSigLen))
	copy(finalSig, sigBuf[:actualSigLen])

	runtime.KeepAlive(sk)
	runtime.KeepAlive(sigBuf)
	return finalSig, nil
}

func VerifyMlDsa65(pk []byte, message []byte, signature []byte, context []byte) error {
	if len(pk) != MlDsa65PublicKeyBytes {
		return ErrPqmagicInvalidKeyLength
	}

	if len(signature) == 0 || len(signature) > MlDsa65SignatureBytes {
		return ErrPqmagicInvalidSignatureLength
	}

	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))

	cMsgPtr := C.CBytes(message)
	defer C.free(unsafe.Pointer(cMsgPtr))
	cSigPtr := C.CBytes(signature)
	defer C.free(unsafe.Pointer(cSigPtr))

	var cCtxPtr *C.uchar = nil
	var cCtxLen C.size_t = 0
	if len(context) > 0 {
		cCtxPtr = (*C.uchar)(C.CBytes(context))
		defer C.free(unsafe.Pointer(cCtxPtr))
		cCtxLen = C.size_t(len(context))
	}

	pqmagicMutex.Lock()
	ret := C.pqmagic_ml_dsa_65_std_verify(
		(*C.uchar)(cSigPtr), C.size_t(len(signature)),
		(*C.uchar)(cMsgPtr), C.size_t(len(message)),
		cCtxPtr, cCtxLen,
		cPkPtr,
	)
	pqmagicMutex.Unlock()

	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicVerificationFailed); err != nil {

		return err
	}

	runtime.KeepAlive(pk)
	return nil
}

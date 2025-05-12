package pqmagic

/*






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


type KEM struct {
	algorithm string
	pubKeySize int
	secKeySize int
	cipherTextSize int
	sharedSecretSize int
}


func NewKEM(algorithm string) *KEM {
	kem := &KEM{algorithm: algorithm}
	
	switch algorithm {
	case "ML_KEM_768":
		kem.pubKeySize = MlKem768PublicKeyBytes
		kem.secKeySize = MlKem768SecretKeyBytes
		kem.cipherTextSize = MlKem768CiphertextBytes
		kem.sharedSecretSize = MlKem768SharedSecretBytes
	
	default:
		
		kem.algorithm = "ML_KEM_768"
		kem.pubKeySize = MlKem768PublicKeyBytes
		kem.secKeySize = MlKem768SecretKeyBytes
		kem.cipherTextSize = MlKem768CiphertextBytes
		kem.sharedSecretSize = MlKem768SharedSecretBytes
	}
	
	return kem
}


func (k *KEM) KeyPair() ([]byte, []byte, error) {
	switch k.algorithm {
	case "ML_KEM_768":
		return keyPairMlKem768()
	
	default:
		return keyPairMlKem768()
	}
}


func (k *KEM) Encaps(pk []byte) ([]byte, []byte, error) {
	switch k.algorithm {
	case "ML_KEM_768":
		return encapsulateMlKem768(pk)
	
	default:
		return encapsulateMlKem768(pk)
	}
}


func (k *KEM) Decaps(sk []byte, ct []byte) ([]byte, error) {
	switch k.algorithm {
	case "ML_KEM_768":
		return decapsulateMlKem768(sk, ct)
	
	default:
		return decapsulateMlKem768(sk, ct)
	}
}


type DSA struct {
	algorithm string
	pubKeySize int
	secKeySize int
	signatureSize int
}


func NewDSA(algorithm string) *DSA {
	dsa := &DSA{algorithm: algorithm}
	
	switch algorithm {
	case "ML_DSA_65":
		dsa.pubKeySize = MlDsa65PublicKeyBytes
		dsa.secKeySize = MlDsa65SecretKeyBytes
		dsa.signatureSize = MlDsa65SignatureBytes
	
	default:
		
		dsa.algorithm = "ML_DSA_65"
		dsa.pubKeySize = MlDsa65PublicKeyBytes
		dsa.secKeySize = MlDsa65SecretKeyBytes
		dsa.signatureSize = MlDsa65SignatureBytes
	}
	
	return dsa
}


func (d *DSA) KeyPair() ([]byte, []byte, error) {
	switch d.algorithm {
	case "ML_DSA_65":
		return keyPairMlDsa65()
	
	default:
		return keyPairMlDsa65()
	}
}


func (d *DSA) Sign(sk []byte, message []byte, context []byte) ([]byte, error) {
	switch d.algorithm {
	case "ML_DSA_65":
		return signMlDsa65(sk, message, context)
	
	default:
		return signMlDsa65(sk, message, context)
	}
}


func (d *DSA) Verify(pk []byte, message []byte, signature []byte, context []byte) error {
	switch d.algorithm {
	case "ML_DSA_65":
		return verifyMlDsa65(pk, message, signature, context)
	
	default:
		return verifyMlDsa65(pk, message, signature, context)
	}
}



func keyPairMlKem768() ([]byte, []byte, error) {
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

func encapsulateMlKem768(pk []byte) ([]byte, []byte, error) {
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

func decapsulateMlKem768(sk []byte, ct []byte) ([]byte, error) {
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

func keyPairMlDsa65() ([]byte, []byte, error) {
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

func signMlDsa65(sk []byte, message []byte, context []byte) ([]byte, error) {
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

func verifyMlDsa65(pk []byte, message []byte, signature []byte, context []byte) error {
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



func KeyPairMlKem768() ([]byte, []byte, error) {
	return keyPairMlKem768()
}

func EncapsulateMlKem768(pk []byte) ([]byte, []byte, error) {
	return encapsulateMlKem768(pk)
}

func DecapsulateMlKem768(sk []byte, ct []byte) ([]byte, error) {
	return decapsulateMlKem768(sk, ct)
}

func KeyPairMlDsa65() ([]byte, []byte, error) {
	return keyPairMlDsa65()
}

func SignMlDsa65(sk []byte, message []byte, context []byte) ([]byte, error) {
	return signMlDsa65(sk, message, context)
}

func VerifyMlDsa65(pk []byte, message []byte, signature []byte, context []byte) error {
	return verifyMlDsa65(pk, message, signature, context)
}

func KeyPairMlDsa44() ([]byte, []byte, error) {
	pk := make([]byte, MlDsa44PublicKeyBytes)
	sk := make([]byte, MlDsa44SecretKeyBytes)

	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))

	pqmagicMutex.Lock()
	ret := C.pqmagic_ml_dsa_44_std_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()

	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}

	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairMlDsa87() ([]byte, []byte, error) {
	pk := make([]byte, MlDsa87PublicKeyBytes)
	sk := make([]byte, MlDsa87SecretKeyBytes)

	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))

	pqmagicMutex.Lock()
	ret := C.pqmagic_ml_dsa_87_std_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()

	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}

	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSlhDsaSha2_128fSimple() ([]byte, []byte, error) {
	pk := make([]byte, SlhDsaSha2_128fPublicKeyBytes)
	sk := make([]byte, SlhDsaSha2_128fSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_slh_dsa_sha2_128f_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSlhDsaSha2_128sSimple() ([]byte, []byte, error) {
	pk := make([]byte, SlhDsaSha2_128sPublicKeyBytes)
	sk := make([]byte, SlhDsaSha2_128sSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_slh_dsa_sha2_128s_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSlhDsaSha2_192fSimple() ([]byte, []byte, error) {
	pk := make([]byte, SlhDsaSha2_192fPublicKeyBytes)
	sk := make([]byte, SlhDsaSha2_192fSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_slh_dsa_sha2_192f_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSlhDsaSha2_192sSimple() ([]byte, []byte, error) {
	pk := make([]byte, SlhDsaSha2_192sPublicKeyBytes)
	sk := make([]byte, SlhDsaSha2_192sSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_slh_dsa_sha2_192s_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSlhDsaSha2_256fSimple() ([]byte, []byte, error) {
	pk := make([]byte, SlhDsaSha2_256fPublicKeyBytes)
	sk := make([]byte, SlhDsaSha2_256fSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_slh_dsa_sha2_256f_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSlhDsaSha2_256sSimple() ([]byte, []byte, error) {
	pk := make([]byte, SlhDsaSha2_256sPublicKeyBytes)
	sk := make([]byte, SlhDsaSha2_256sSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_slh_dsa_sha2_256s_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSlhDsaShake128fSimple() ([]byte, []byte, error) {
	pk := make([]byte, SlhDsaShake128fPublicKeyBytes)
	sk := make([]byte, SlhDsaShake128fSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_slh_dsa_shake_128f_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSlhDsaShake128sSimple() ([]byte, []byte, error) {
	pk := make([]byte, SlhDsaShake128sPublicKeyBytes)
	sk := make([]byte, SlhDsaShake128sSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_slh_dsa_shake_128s_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSlhDsaShake192fSimple() ([]byte, []byte, error) {
	pk := make([]byte, SlhDsaShake192fPublicKeyBytes)
	sk := make([]byte, SlhDsaShake192fSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_slh_dsa_shake_192f_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSlhDsaShake192sSimple() ([]byte, []byte, error) {
	pk := make([]byte, SlhDsaShake192sPublicKeyBytes)
	sk := make([]byte, SlhDsaShake192sSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_slh_dsa_shake_192s_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSlhDsaShake256fSimple() ([]byte, []byte, error) {
	pk := make([]byte, SlhDsaShake256fPublicKeyBytes)
	sk := make([]byte, SlhDsaShake256fSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_slh_dsa_shake_256f_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSlhDsaShake256sSimple() ([]byte, []byte, error) {
	pk := make([]byte, SlhDsaShake256sPublicKeyBytes)
	sk := make([]byte, SlhDsaShake256sSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_slh_dsa_shake_256s_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSlhDsaSm3_128fSimple() ([]byte, []byte, error) {
	pk := make([]byte, SlhDsaSm3_128fPublicKeyBytes)
	sk := make([]byte, SlhDsaSm3_128fSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_slh_dsa_sm3_128f_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSlhDsaSm3_128sSimple() ([]byte, []byte, error) {
	pk := make([]byte, SlhDsaSm3_128sPublicKeyBytes)
	sk := make([]byte, SlhDsaSm3_128sSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_slh_dsa_sm3_128s_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairAigisSig1() ([]byte, []byte, error) {
	pk := make([]byte, AigisSig1PublicKeyBytes)
	sk := make([]byte, AigisSig1SecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_aigis_sig1_std_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairAigisSig2() ([]byte, []byte, error) {
	pk := make([]byte, AigisSig2PublicKeyBytes)
	sk := make([]byte, AigisSig2SecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_aigis_sig2_std_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairAigisSig3() ([]byte, []byte, error) {
	pk := make([]byte, AigisSig3PublicKeyBytes)
	sk := make([]byte, AigisSig3SecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_aigis_sig3_std_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairDilithium2() ([]byte, []byte, error) {
	pk := make([]byte, Dilithium2PublicKeyBytes)
	sk := make([]byte, Dilithium2SecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_dilithium2_std_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairDilithium3() ([]byte, []byte, error) {
	pk := make([]byte, Dilithium3PublicKeyBytes)
	sk := make([]byte, Dilithium3SecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_dilithium3_std_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairDilithium5() ([]byte, []byte, error) {
	pk := make([]byte, Dilithium5PublicKeyBytes)
	sk := make([]byte, Dilithium5SecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_dilithium5_std_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSphincsASha2_128fSimple() ([]byte, []byte, error) {
	pk := make([]byte, SphincsASha2_128fPublicKeyBytes)
	sk := make([]byte, SphincsASha2_128fSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_sphincs_a_sha2_128f_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSphincsASha2_128sSimple() ([]byte, []byte, error) {
	pk := make([]byte, SphincsASha2_128sPublicKeyBytes)
	sk := make([]byte, SphincsASha2_128sSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_sphincs_a_sha2_128s_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSphincsASha2_192fSimple() ([]byte, []byte, error) {
	pk := make([]byte, SphincsASha2_192fPublicKeyBytes)
	sk := make([]byte, SphincsASha2_192fSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_sphincs_a_sha2_192f_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSphincsASha2_192sSimple() ([]byte, []byte, error) {
	pk := make([]byte, SphincsASha2_192sPublicKeyBytes)
	sk := make([]byte, SphincsASha2_192sSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_sphincs_a_sha2_192s_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSphincsASha2_256fSimple() ([]byte, []byte, error) {
	pk := make([]byte, SphincsASha2_256fPublicKeyBytes)
	sk := make([]byte, SphincsASha2_256fSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_sphincs_a_sha2_256f_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSphincsASha2_256sSimple() ([]byte, []byte, error) {
	pk := make([]byte, SphincsASha2_256sPublicKeyBytes)
	sk := make([]byte, SphincsASha2_256sSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_sphincs_a_sha2_256s_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSphincsAShake128fSimple() ([]byte, []byte, error) {
	pk := make([]byte, SphincsAShake128fPublicKeyBytes)
	sk := make([]byte, SphincsAShake128fSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_sphincs_a_shake_128f_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSphincsAShake128sSimple() ([]byte, []byte, error) {
	pk := make([]byte, SphincsAShake128sPublicKeyBytes)
	sk := make([]byte, SphincsAShake128sSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_sphincs_a_shake_128s_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSphincsAShake192fSimple() ([]byte, []byte, error) {
	pk := make([]byte, SphincsAShake192fPublicKeyBytes)
	sk := make([]byte, SphincsAShake192fSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_sphincs_a_shake_192f_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSphincsAShake192sSimple() ([]byte, []byte, error) {
	pk := make([]byte, SphincsAShake192sPublicKeyBytes)
	sk := make([]byte, SphincsAShake192sSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_sphincs_a_shake_192s_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSphincsAShake256fSimple() ([]byte, []byte, error) {
	pk := make([]byte, SphincsAShake256fPublicKeyBytes)
	sk := make([]byte, SphincsAShake256fSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_sphincs_a_shake_256f_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSphincsAShake256sSimple() ([]byte, []byte, error) {
	pk := make([]byte, SphincsAShake256sPublicKeyBytes)
	sk := make([]byte, SphincsAShake256sSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_sphincs_a_shake_256s_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSphincsASm3_128fSimple() ([]byte, []byte, error) {
	pk := make([]byte, SphincsASm3_128fPublicKeyBytes)
	sk := make([]byte, SphincsASm3_128fSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_sphincs_a_sm3_128f_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairSphincsASm3_128sSimple() ([]byte, []byte, error) {
	pk := make([]byte, SphincsASm3_128sPublicKeyBytes)
	sk := make([]byte, SphincsASm3_128sSecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_sphincs_a_sm3_128s_simple_std_sign_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairMlKem512() ([]byte, []byte, error) {
	pk := make([]byte, MlKem512PublicKeyBytes)
	sk := make([]byte, MlKem512SecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_ml_kem_512_std_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairMlKem1024() ([]byte, []byte, error) {
	pk := make([]byte, MlKem1024PublicKeyBytes)
	sk := make([]byte, MlKem1024SecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_ml_kem_1024_std_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairKyber512() ([]byte, []byte, error) {
	pk := make([]byte, Kyber512PublicKeyBytes)
	sk := make([]byte, Kyber512SecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_kyber512_std_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairKyber768() ([]byte, []byte, error) {
	pk := make([]byte, Kyber768PublicKeyBytes)
	sk := make([]byte, Kyber768SecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_kyber768_std_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairKyber1024() ([]byte, []byte, error) {
	pk := make([]byte, Kyber1024PublicKeyBytes)
	sk := make([]byte, Kyber1024SecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_kyber1024_std_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairAigisEnc1() ([]byte, []byte, error) {
	pk := make([]byte, AigisEnc1PublicKeyBytes)
	sk := make([]byte, AigisEnc1SecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_aigis_enc_1_std_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairAigisEnc2() ([]byte, []byte, error) {
	pk := make([]byte, AigisEnc2PublicKeyBytes)
	sk := make([]byte, AigisEnc2SecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_aigis_enc_2_std_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairAigisEnc3() ([]byte, []byte, error) {
	pk := make([]byte, AigisEnc3PublicKeyBytes)
	sk := make([]byte, AigisEnc3SecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_aigis_enc_3_std_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

func KeyPairAigisEnc4() ([]byte, []byte, error) {
	pk := make([]byte, AigisEnc4PublicKeyBytes)
	sk := make([]byte, AigisEnc4SecretKeyBytes)
	cPkPtr := (*C.uchar)(unsafe.Pointer(&pk[0]))
	cSkPtr := (*C.uchar)(unsafe.Pointer(&sk[0]))
	pqmagicMutex.Lock()
	ret := C.pqmagic_aigis_enc_4_std_keypair(cPkPtr, cSkPtr)
	pqmagicMutex.Unlock()
	if err := handleCReturnCode(CInt(ret), 0, ErrPqmagicOperationFailed); err != nil {
		return nil, nil, err
	}
	runtime.KeepAlive(pk)
	runtime.KeepAlive(sk)
	return pk, sk, nil
}

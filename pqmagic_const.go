package pqmagic

/*










#cgo CFLAGS: -I/usr/local/include
#cgo LDFLAGS: -L/usr/local/lib -lpqmagic_std


#include <pqmagic_api.h>

*/
import "C"

const (
	MlDsa44PublicKeyBytes = C.ML_DSA_44_PUBLICKEYBYTES
	MlDsa44SecretKeyBytes = C.ML_DSA_44_SECRETKEYBYTES
	MlDsa44SignatureBytes = C.ML_DSA_44_SIGBYTES

	MlDsa65PublicKeyBytes = C.ML_DSA_65_PUBLICKEYBYTES
	MlDsa65SecretKeyBytes = C.ML_DSA_65_SECRETKEYBYTES
	MlDsa65SignatureBytes = C.ML_DSA_65_SIGBYTES

	MlDsa87PublicKeyBytes = C.ML_DSA_87_PUBLICKEYBYTES
	MlDsa87SecretKeyBytes = C.ML_DSA_87_SECRETKEYBYTES
	MlDsa87SignatureBytes = C.ML_DSA_87_SIGBYTES
)

const (
	SlhDsaSha2_128fPublicKeyBytes = C.SLH_DSA_SHA2_128f_PUBLICKEYBYTES
	SlhDsaSha2_128fSecretKeyBytes = C.SLH_DSA_SHA2_128f_SECRETKEYBYTES
	SlhDsaSha2_128fSignatureBytes = C.SLH_DSA_SHA2_128f_SIGBYTES
)

const (
	Dilithium2PublicKeyBytes = C.DILITHIUM2_PUBLICKEYBYTES
	Dilithium2SecretKeyBytes = C.DILITHIUM2_SECRETKEYBYTES
	Dilithium2SignatureBytes = C.DILITHIUM2_SIGBYTES

	Dilithium3PublicKeyBytes = C.DILITHIUM3_PUBLICKEYBYTES
	Dilithium3SecretKeyBytes = C.DILITHIUM3_SECRETKEYBYTES
	Dilithium3SignatureBytes = C.DILITHIUM3_SIGBYTES

	Dilithium5PublicKeyBytes = C.DILITHIUM5_PUBLICKEYBYTES
	Dilithium5SecretKeyBytes = C.DILITHIUM5_SECRETKEYBYTES
	Dilithium5SignatureBytes = C.DILITHIUM5_SIGBYTES
)

const (
	MlKem512PublicKeyBytes    = C.ML_KEM_512_PUBLICKEYBYTES
	MlKem512SecretKeyBytes    = C.ML_KEM_512_SECRETKEYBYTES
	MlKem512CiphertextBytes   = C.ML_KEM_512_CIPHERTEXTBYTES
	MlKem512SharedSecretBytes = C.ML_KEM_512_SSBYTES

	MlKem768PublicKeyBytes    = C.ML_KEM_768_PUBLICKEYBYTES
	MlKem768SecretKeyBytes    = C.ML_KEM_768_SECRETKEYBYTES
	MlKem768CiphertextBytes   = C.ML_KEM_768_CIPHERTEXTBYTES
	MlKem768SharedSecretBytes = C.ML_KEM_768_SSBYTES

	MlKem1024PublicKeyBytes    = C.ML_KEM_1024_PUBLICKEYBYTES
	MlKem1024SecretKeyBytes    = C.ML_KEM_1024_SECRETKEYBYTES
	MlKem1024CiphertextBytes   = C.ML_KEM_1024_CIPHERTEXTBYTES
	MlKem1024SharedSecretBytes = C.ML_KEM_1024_SSBYTES
)

const (
	Kyber512PublicKeyBytes    = C.KYBER512_PUBLICKEYBYTES
	Kyber512SecretKeyBytes    = C.KYBER512_SECRETKEYBYTES
	Kyber512CiphertextBytes   = C.KYBER512_CIPHERTEXTBYTES
	Kyber512SharedSecretBytes = C.KYBER512_SSBYTES

	Kyber768PublicKeyBytes    = C.KYBER768_PUBLICKEYBYTES
	Kyber768SecretKeyBytes    = C.KYBER768_SECRETKEYBYTES
	Kyber768CiphertextBytes   = C.KYBER768_CIPHERTEXTBYTES
	Kyber768SharedSecretBytes = C.KYBER768_SSBYTES

	Kyber1024PublicKeyBytes    = C.KYBER1024_PUBLICKEYBYTES
	Kyber1024SecretKeyBytes    = C.KYBER1024_SECRETKEYBYTES
	Kyber1024CiphertextBytes   = C.KYBER1024_CIPHERTEXTBYTES
	Kyber1024SharedSecretBytes = C.KYBER1024_SSBYTES
)

const (
	AigisEnc1PublicKeyBytes    = C.AIGIS_ENC_1_PUBLICKEYBYTES
	AigisEnc1SecretKeyBytes    = C.AIGIS_ENC_1_SECRETKEYBYTES
	AigisEnc1CiphertextBytes   = C.AIGIS_ENC_1_CIPHERTEXTBYTES
	AigisEnc1SharedSecretBytes = C.AIGIS_ENC_1_SSBYTES
)

const (
	AigisSig1PublicKeyBytes = C.AIGIS_SIG1_PUBLICKEYBYTES
	AigisSig1SecretKeyBytes = C.AIGIS_SIG1_SECRETKEYBYTES
	AigisSig1SignatureBytes = C.AIGIS_SIG1_SIGBYTES
)

const (
	SphincsASha2_128fPublicKeyBytes = C.SPHINCS_A_SHA2_128f_PUBLICKEYBYTES
	SphincsASha2_128fSecretKeyBytes = C.SPHINCS_A_SHA2_128f_SECRETKEYBYTES
	SphincsASha2_128fSignatureBytes = C.SPHINCS_A_SHA2_128f_SIGBYTES
)

#define RV_OK                            0
#define BCA_ALGO_MD2                     1
#define BCA_ALGO_MD5                     2
#define BCA_ALGO_SHA1_160                3
#define BCA_ALGO_DES                     100
#define BCA_ALGO_3DES_2KEY               101
#define BCA_ALGO_3DES_3KEY               102
#define BCA_ALGO_AES                     103
#define BCA_ALGO_RC2                     104
#define BCA_ALGO_RC4                     105
#define BCA_ALGO_RSA                     200


#define BCA_MODE_ECB                     1
#define BCA_MODE_CBC                     2
#define BCA_MODE_CFB                     3
#define BCA_MODE_OFB                     4

#define RV_LOGINERR                      11
#define RV_PINTYPEErr                    12
#define RV_PINLENTHERR                   13
#define RV_KeyInfoTypeErr                57
#define RV_PinErr                        14
#define RV_INVALIDATEPIN                 26
#define KEY_NUM                          10
#define RV_KEYEXIST                      100
#define RV_KEYNUMERR                     9
#define RV_PINNOTINITERR                 15
#define RV_FILENOTFOUND                  55
#define RV_WRITEERR                      56
#define MAX_LENGTH                       2048
#define HASH_LENGTH                      20
#define MAXPINLEN                        16

#define RV_PARAMETERErr                     8
#define RV_AlgoTypeErr                      7
#define RV_MemoryErr                        100
#define RV_MODULUSLENERR                    16
#define RV_GenRsaKeyErr                     303
#define RV_RsaModulusLenErr                 304
#define RV_RsaEncErr                        306
#define RV_RsaDecErr                        307
#define RV_KeyNotFountErr                   309
#define RV_CertNotFountErr                  310
#define RV_ImportCertErr		     		315
#define RV_ImportRSAErr		    			316
#define RV_CertVerifyErr					317
#define RV_SignErr							319
#define RV_EncErr							321
#define RV_DecErr							322
#define RV_VerifyErr						323
#define RV_HashErr							324
#define RV_DATALENErr                       325
#define RV_IndataLenErr                     326
#define RV_BASE64DecodeErr					327
#define RV_PRIKEYErr						328

typedef struct passenger {

	char idno[32];
	char name[256];
	char id_kind[4];
	char folk[128];
	
}PASSENGER;

//unsigned long ict_encx(PASSENGER *pas,unsigned char *output,unsigned long *outputLen);

 unsigned long  GenRandom(unsigned long randLen,unsigned char *rand);
 void  init_cryt(void);
 void  free_cryt(void);
 int Nid_BCA2OpenSSL(int Algorithm ,int Mod);
 unsigned long Base64_Encode(unsigned char *inData ,unsigned long inDataLen,unsigned char *outData,unsigned long *outDataLen);
 unsigned long Base64_Decode(unsigned char *inData ,unsigned long inDataLen,unsigned char *outData,unsigned long *outDataLen);
 int Hash(unsigned long IdAlg,unsigned char *indata ,unsigned long indatalen,unsigned char *outdata,unsigned long *outlen);
 unsigned long CreateSymmKeyObj(unsigned long *symmKeyObj ,unsigned long algorithmType,unsigned long encOrDec ,unsigned long cryptoMode ,unsigned char *key ,unsigned long keyLen ,unsigned char *iv);
 unsigned long DestroySymmKeyObj(unsigned long symmKeyObj);
 unsigned long SymmEncrypt(unsigned long symmKeyObj ,unsigned char* indata ,unsigned long inDataLen ,unsigned char* outdata ,unsigned long* outDataLen);
 unsigned long SymmDecrypt(unsigned long symmKeyObj ,unsigned char* indata ,unsigned long inDataLen ,unsigned char* outdata ,unsigned long* outDataLen);
 unsigned long Pkcs1RsaPrivateKeyDec(unsigned char* privateKey, unsigned long privateKeyLen, unsigned char* indata, unsigned long indatalen, unsigned char* outdata, unsigned long* outdatalen);
 unsigned long Pkcs1RsaPublickKeyEnc(unsigned char*publicKey, unsigned long publickeylen, unsigned char* indata, unsigned long indatalen, unsigned char* outdata, unsigned long* outdatalen);
 unsigned long GenRsaKeyPair(unsigned long modulusLen, unsigned char*privatekey, unsigned long*privateLen, unsigned char*publickey, unsigned long* publickeylen);
 int BCA_RsaVerifySign_old(unsigned long hashAlgorithmType, unsigned char *hashValue, unsigned long hashValueLen, unsigned char *publicKey, unsigned long publicKeyLen, unsigned char *signData, unsigned long signDataLen);
 int RsaSign(unsigned char *privateKey, unsigned long privateKeyLen, unsigned long hashAlgorithmType, unsigned char *hashValue, unsigned long hashValueLen, unsigned char *signData, unsigned long *signDataLen);
int gen_license(const char *device_id, const char *connect_num, char *license);
int get_connect_num(const char *device_id, const char *license);
unsigned long p1PrivateKeyDecWithID(char *privateKey, char *device_id, unsigned char *indata, unsigned long indataLen, unsigned char *out, unsigned long *outlen);
unsigned long GenRsaKeyPair2File(unsigned long modulusLen, char *device_id);
int decryptPrivateKeyByDeviceID(unsigned char *privateKey,unsigned long privateKeyLen, char*device_id,unsigned char *outdata,unsigned long *outdatalen);

#include "sym.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ossl_typ.h>

typedef struct SymmKeyObj
{
	EVP_CIPHER_CTX ctx;
	char EncorDec;
	unsigned char buf[32];
	unsigned char key[32];

}SYMMKEYOBJ,*SYMMKEYOBJ_PTR;
unsigned long  GenRandom(unsigned long randLen,unsigned char *rand)
{
	RAND_bytes(rand, randLen);
	return RV_OK;
}
/*
unsigned long ict_initmsg(PASSENGER *pas,char *msg){
	char tmp[2048]={0};

	if(msg==NULL || strlen(pas->idno)==0 ||strlen(pas->name)==0 ||strlen(pas->folk)==0 || strlen(pas->id_kind)==0)
		return -1;

	sprintf(tmp,"<root><PASSENGER><CHECK_STATION_CODE> </CHECK_STATION_CODE><CHECK_WINDOW_NO> </CHECK_WINDOW_NO><ID_NO>%s</ID_NO><ID_NAME>%s</ID_NAME><ID_KIND>%s</ID_KIND><ID_FOLK>%s</ID_FOLK><OFFICE_NO> </OFFICE_NO><WINDOW_NO> </WINDOW_NO><STATISTICS_DATE> </STATISTICS_DATE><TICKET_NO> </TICKET_NO><BOARD_TRAIN_CODE> </BOARD_TRAIN_CODE><TRAIN_DATE> </TRAIN_DATE><START_TIME> </START_TIME><COACH_NO> </COACH_NO><SEAT_NO> </SEAT_NO><SEAT_TYPE_CODE> </SEAT_TYPE_CODE><FROM_TELE_CODE> </FROM_TELE_CODE><TO_TELE_CODE> </TO_TELE_CODE><CHECK_WINDOW_IP> </CHECK_WINDOW_IP></PASSENGER></root>",pas->idno,pas->name,pas->id_kind,pas->folk);

	strcpy(msg,tmp);

	return 0;


}



unsigned long ict_enc(unsigned char *input,unsigned long inputLen,unsigned char *output,unsigned long *outputLen){
	time_t now;
	char curtime[16]={0};
	struct tm *tm_now;
	int ret;
	int i=0;
	unsigned char  hashkey[32]={0};
	unsigned char  iv[16]={0};
	unsigned char sec[1024]={0};
	unsigned long seclen=0;
	unsigned long hashkey_len=0;
	unsigned long sym;
	unsigned char basesec[2048]={0};
	unsigned long baselen=0;
	unsigned char str1[512]={0};
	unsigned long str1len=0;
	unsigned char str2[512]={0};
	unsigned long str2len=0;
	time(&now);
	tm_now = localtime(&now);
	sprintf(curtime,"%d%02d%02d", 1900+tm_now->tm_year, 1+tm_now->tm_mon, tm_now->tm_mday);
	ret=Hash(BCA_ALGO_MD5,(unsigned char *)curtime,strlen(curtime),hashkey,&hashkey_len);
	for (i;i<8;++i)
	{
		iv[i]=hashkey[i];
	}


	if(output == NULL || input==NULL || inputLen==0){
		return -9;
	}

	ret =CreateSymmKeyObj(&sym,BCA_ALGO_3DES_2KEY,1,BCA_MODE_CBC,hashkey,16,iv);
	if(ret !=0){
		return -1;
	}

	ret=SymmEncrypt(sym,(unsigned char *)input,inputLen,sec,&seclen);
	if(ret !=0){
		DestroySymmKeyObj(sym);
		return -2;
	}

	ret =Base64_Encode(sec,seclen,output,outputLen);
	if(ret !=0){
		DestroySymmKeyObj(sym);
		return -3;
	}

	DestroySymmKeyObj(sym);
	return 0;
}

unsigned long ict_encx(PASSENGER *pas,unsigned char *output,unsigned long *outputLen){
	int ret;
	char msg[2048]={0};
	ret=ict_initmsg(pas,msg);
	if(ret !=0)
		return -1;
	else{
		ret=ict_enc((unsigned char*)msg,strlen(msg),output,outputLen);
		if(ret!=0)
			return  -2;
	}
	return 0;
}
*/



void  init_cryt(void){

	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();

}
void  free_cryt(void){
	EVP_cleanup();
}

unsigned long Base64_Encode(unsigned char *inData ,unsigned long inDataLen,unsigned char *outData,unsigned long *outDataLen)
{

	int tmplen;

	if (inDataLen==0) {
		return RV_OK;
	}

	if (outData==NULL) {
		return RV_MemoryErr;
	}

	tmplen=EVP_EncodeBlock(outData, inData, inDataLen);

	*outDataLen=tmplen;
	return RV_OK;
}

unsigned long Base64_Decode(unsigned char *inData ,unsigned long inDataLen,unsigned char *outData,unsigned long *outDataLen)
{
	unsigned char *tmp=NULL;
	int pad=0;

	int tmplen;
	if (inDataLen==0) {
		return RV_OK;
	}

	

	tmp=inData+inDataLen-1;
	for (int i=0; i<4; ++i) {
		if(*tmp=='=')
			pad++;
		tmp--;
	}

	tmplen=EVP_DecodeBlock(outData,inData,inDataLen);
	if (tmplen <= 0){
		return RV_BASE64DecodeErr;
	}
	tmplen-=pad;
	*outDataLen=tmplen;

	return RV_OK;

}


int Hash(unsigned long IdAlg,unsigned char *indata ,unsigned long indatalen,unsigned char *outdata,unsigned long *outlen)
{
	//EVP_MD_CTX ctx;
	const EVP_MD* type;
	unsigned char *tmp=NULL;
	unsigned int tmplen;

	type=(EVP_MD*)EVP_get_digestbynid(Nid_BCA2OpenSSL(IdAlg,0));
	if (type==NULL) 
		return RV_AlgoTypeErr;

	tmp=(unsigned char *)malloc(HASH_LENGTH);
	if (tmp==NULL) {
		
		return RV_MemoryErr;
	}	
	//EVP_MD_CTX_init(&ctx);
	EVP_Digest(indata, indatalen, tmp, &tmplen, type, NULL);
	*outlen=tmplen;
	if (outdata!=NULL) {
		memcpy(outdata, tmp, tmplen);
	}
	free(tmp);
	//EVP_MD_CTX_cleanup(&ctx);
	return RV_OK;
}

unsigned long CreateSymmKeyObj(unsigned long *symmKeyObj ,unsigned long algorithmType,unsigned long encOrDec ,unsigned long cryptoMode ,unsigned char *key ,unsigned long keyLen ,unsigned char *iv)
{
	SYMMKEYOBJ_PTR psymmKeyObj;
	EVP_CIPHER *cipher;
	EVP_CIPHER_CTX *ctx;
	int rv;
	unsigned char keytmp[24];
	cipher=(EVP_CIPHER *)EVP_get_cipherbynid(Nid_BCA2OpenSSL(algorithmType ,cryptoMode));
	if (cipher==NULL) {
		OpenSSL_add_all_algorithms();
		cipher=(EVP_CIPHER *)EVP_get_cipherbynid(Nid_BCA2OpenSSL(algorithmType ,cryptoMode));
		if (cipher==NULL) {
			return RV_AlgoTypeErr;
		}
	}
	psymmKeyObj=(SYMMKEYOBJ_PTR)malloc(sizeof(SYMMKEYOBJ));
	if (psymmKeyObj==NULL) {
		return RV_MemoryErr;
	}
	ctx=&(psymmKeyObj->ctx);
	psymmKeyObj->EncorDec=(char)encOrDec;
	EVP_CIPHER_CTX_init(ctx);
	if (algorithmType==BCA_ALGO_3DES_2KEY)
	{
		for (int i=0; i<16; i++) {
			keytmp[i]=key[i];
		}
		for (int i=0; i<8; ++i) {
			keytmp[i+16]=key[i];
		}
		memcpy(psymmKeyObj->key, keytmp, 24);
		if (encOrDec==1) 
			rv=EVP_EncryptInit(ctx, cipher, keytmp, iv);
		else
			rv = EVP_DecryptInit(ctx,cipher,keytmp,iv);		

	}
	else
	{
		memcpy(psymmKeyObj->key,key,keyLen);
		if(encOrDec == 1)
			rv = EVP_EncryptInit(ctx,cipher,key,iv);
		else
			rv = EVP_DecryptInit(ctx,cipher,key,iv);
	}
	if(rv != 1)
	{
		free(psymmKeyObj);
		*symmKeyObj = 0;
		return RV_EncErr;
	}
	*symmKeyObj = (unsigned long)psymmKeyObj;
	return 0;
}

unsigned long DestroySymmKeyObj(unsigned long symmKeyObj)
{
	SYMMKEYOBJ_PTR psymmKeyObj;
	EVP_CIPHER_CTX *ctx;
	psymmKeyObj=(SYMMKEYOBJ_PTR)symmKeyObj;
	if (psymmKeyObj==NULL) {
		return RV_MemoryErr;
	}
	ctx=&(psymmKeyObj->ctx);
	EVP_CIPHER_CTX_cleanup(ctx);
	free(psymmKeyObj);

	return RV_OK;
}


unsigned long SymmEncrypt(unsigned long symmKeyObj ,unsigned char* indata ,unsigned long inDataLen ,unsigned char* outdata ,unsigned long* outDataLen)
{

	if (inDataLen<1) {
		return RV_IndataLenErr;
	}
	SYMMKEYOBJ_PTR psymmKeyObj;
	EVP_CIPHER_CTX *ctx;
	int outl=0;

	psymmKeyObj=(SYMMKEYOBJ_PTR)symmKeyObj;
	if (psymmKeyObj==NULL) {
		return RV_MemoryErr;
	}
	ctx=&(psymmKeyObj->ctx);
	if (EVP_EncryptUpdate(ctx, outdata, &outl, indata, inDataLen)!=1) {
		return RV_EncErr;
	}
	int len;
	if (EVP_EncryptFinal(ctx, outdata+outl, &len)!=1) {
		return RV_EncErr;
	}
	*outDataLen=len+outl;
	return RV_OK;
}



unsigned long SymmDecrypt(unsigned long symmKeyObj ,unsigned char* indata ,unsigned long inDataLen ,unsigned char* outdata ,unsigned long* outDataLen)
{
	SYMMKEYOBJ_PTR psymmKeyObj;
	EVP_CIPHER_CTX *ctx;
	int tmplen;
	int outl=0;

	if (inDataLen < 1)
	{
		return RV_IndataLenErr;
	}

	psymmKeyObj=(SYMMKEYOBJ_PTR)symmKeyObj;
	if (psymmKeyObj==NULL) {
		return RV_MemoryErr;
	}
	ctx=&(psymmKeyObj->ctx);
	if (EVP_DecryptUpdate(ctx, outdata, &outl, indata, inDataLen)!=1) {
		return RV_EncErr;
	}
	if (EVP_DecryptFinal(ctx, outdata+outl, &tmplen)!=1) {
		return RV_EncErr;
	}
	*outDataLen=outl+tmplen;

	return RV_OK;
}

unsigned long GenRsaKeyPair(unsigned long modulusLen, unsigned char*privatekey, unsigned long*privateLen, unsigned char*publickey, unsigned long* publickeylen)
{
	if (!(modulusLen == 512 || modulusLen == 1024)) {
		return RV_MODULUSLENERR;
	}

	RSA *rsa = RSA_new();
	EVP_PKEY *evpkey;
	unsigned char* derprivatekey;
	unsigned char* derpublickey;
	unsigned char* tmp;
	int derprivatekeylen;
	unsigned long e = RSA_F4;
	BIGNUM *bne;

	bne = BN_new();
	int ret = BN_set_word(bne, e);


	evpkey = EVP_PKEY_new();
	if (evpkey == NULL) {
		BN_free(bne);
		return RV_MemoryErr;
	}
	ret = RSA_generate_key_ex(rsa, modulusLen, bne, NULL);
	if (!rsa) {
		BN_free(bne);
		EVP_PKEY_free(evpkey);
		return RV_AlgoTypeErr;
	}
	BN_free(bne);
	int rv = EVP_PKEY_set1_RSA(evpkey, rsa);
	if (rv != 1) {
		EVP_PKEY_free(evpkey);
		return RV_AlgoTypeErr;
	}

	derprivatekeylen = i2d_PrivateKey(evpkey, NULL);
	derprivatekey = (unsigned char*)malloc(derprivatekeylen + 1);
	if (derprivatekey == NULL) {
		EVP_PKEY_free(evpkey);
		return RV_MemoryErr;
	}
	tmp = derprivatekey;

	int derpublickeylen = i2d_PublicKey(evpkey, NULL);
	derpublickey = (unsigned char*)malloc(derpublickeylen + 1);
	if (derpublickey == NULL) {
		EVP_PKEY_free(evpkey);
		free(derprivatekey);
		return RV_MemoryErr;
	}
	unsigned char* tmp2 = derpublickey;

	rv = i2d_PrivateKey(evpkey, &tmp);
	rv = i2d_PublicKey(evpkey, &tmp2);

	EVP_PKEY_free(evpkey);
	if (privatekey == NULL) {
		free(derprivatekey);
		free(derpublickey);
		return RV_MemoryErr;
	}
	memcpy(privatekey, derprivatekey, derprivatekeylen);
	*privateLen = derprivatekeylen;
	if (publickey == NULL) {
		free(derprivatekey);
		free(derpublickey);
		return RV_MemoryErr;
	}
	memcpy(publickey, derpublickey, derpublickeylen);
	*publickeylen = derpublickeylen;

	free(derprivatekey);
	free(derpublickey);
	return RV_OK;
}


int decryptPrivateKeyByDeviceID(unsigned char *privateKey, unsigned long privateKeyLen, char*device_id, unsigned char *outdata, unsigned long *outdatalen) {
	int ret = 0;
	unsigned long sym;
	unsigned char key[16] = { 0 };
	unsigned char iv[16] = { 0 };
	unsigned char hash_mac[20] = { 0 };
	unsigned long hash_len = 0;
	unsigned long tmplen = 0;
	unsigned char indata[32] = { 0 };
	unsigned long outlen = 0;
	unsigned char out[1024] = { 0 };

	if (device_id == NULL || privateKey == NULL || strlen(device_id) == 0) return -2;

	ret = Hash(BCA_ALGO_SHA1_160, (unsigned char*)device_id, strlen(device_id), hash_mac, &hash_len);
	if (ret != RV_OK) return ret;
	for (size_t i = 0; i < 16; i++)
	{
		key[i] = hash_mac[i];
	}
	ret = Hash(BCA_ALGO_MD5, hash_mac, hash_len, iv, &tmplen);
	if (ret != RV_OK) return ret;
	ret = CreateSymmKeyObj(&sym, BCA_ALGO_AES, 0, BCA_MODE_CBC, key, 16, iv);
	if (ret != RV_OK) return ret;
	ret = SymmDecrypt(sym, privateKey, privateKeyLen, out, &outlen);
	if (ret != RV_OK) return ret;

	memcpy(outdata, out, outlen);
	*outdatalen = outlen;
	ret = DestroySymmKeyObj(sym);
	if (ret != RV_OK) return ret;

	return RV_OK;
}

/**********************************************************************
func: 验证私钥是否与设备匹配
para:
device_id: 设备唯一号
private_key：加密+base64处理过的私钥

return:
license
************************************************************************/
int isMatchedKey(char *device_id, char* private_key) {
	unsigned char b64_decode[1024] = { 0 };
	unsigned long b64_decode_len = 0;
	unsigned char out[1024] = { 0 };
	unsigned long outlen = 0;
	int ret = Base64_Decode((unsigned char*)private_key, strlen(private_key), b64_decode, &b64_decode_len);
	if (ret != RV_OK) return ret;

	ret = decryptPrivateKeyByDeviceID(b64_decode, b64_decode_len, device_id, out, &outlen);
	if (ret != RV_OK) return ret;
	
	return RV_OK;

}

int encryptPrivateKeyWithDeviceID(unsigned char *privateKey, unsigned long privateKeyLen, char*device_id, unsigned char *outdata, unsigned long *outdatalen) {
	int ret = 0;
	unsigned long sym;
	unsigned char key[16] = { 0 };
	unsigned char iv[16] = { 0 };
	unsigned char hash_mac[20] = { 0 };
	unsigned long hash_len = 0;
	unsigned long tmplen = 0;
	unsigned char indata[32] = { 0 };
	unsigned long outlen = 0;
	unsigned char out[1024] = { 0 };

	if (device_id == NULL || privateKey == NULL || strlen(device_id) == 0) return -2;

	ret = Hash(BCA_ALGO_SHA1_160, (unsigned char*)device_id, strlen(device_id), hash_mac, &hash_len);
	if (ret != RV_OK) return ret;
	for (size_t i = 0; i < 16; i++)
	{
		key[i] = hash_mac[i];
	}
	ret = Hash(BCA_ALGO_MD5, hash_mac, hash_len, iv, &tmplen);
	if (ret != RV_OK) return ret;
	ret = CreateSymmKeyObj(&sym, BCA_ALGO_AES, 1, BCA_MODE_CBC, key, 16, iv);
	if (ret != RV_OK) return ret;
	ret = SymmEncrypt(sym, privateKey, privateKeyLen, out, &outlen);
	if (ret != RV_OK) return ret;

	memcpy(outdata, out, outlen);
	*outdatalen = outlen;
	ret = DestroySymmKeyObj(sym);
	if (ret != RV_OK) return ret;

	return RV_OK;
}

#ifdef GEN

/**********************************************************************
func: 生成公私密钥对，公钥base64编码保存，私钥用device_id加密，再base64保存
para:
modulusLen:模长
device_id: 设备唯一号

return:
license
************************************************************************/
unsigned long GenRsaKeyPair2File(unsigned long modulusLen, char *device_id)
{
	if (!(modulusLen == 512 || modulusLen == 1024 || device_id == NULL)) {
		return RV_MODULUSLENERR;
	}

	RSA *rsa = RSA_new();
	EVP_PKEY *evpkey;
	unsigned char* derprivatekey;
	unsigned char* derpublickey;
	unsigned char* tmp;
	int derprivatekeylen;
	unsigned char privatekey[1024] = { 0 };
	unsigned char publickey[1024] = { 0 };
	unsigned char e_privatekey[2048] = { 0 };
	unsigned long e_derprivatekeylen =0;

	unsigned long e = RSA_F4;
	unsigned char *base64_pri = NULL;
	unsigned long base64_pri_len = 0;
	unsigned char *base64_pub = NULL;
	unsigned long base64_pub_len = 0;

	BIGNUM *bne;
	FILE *fp_pub;
	FILE *fp_pri;

	bne = BN_new();
	int ret = BN_set_word(bne, e);


	evpkey = EVP_PKEY_new();
	if (evpkey == NULL) {
		BN_free(bne);
		return RV_MemoryErr;
	}
	ret = RSA_generate_key_ex(rsa, modulusLen, bne, NULL);
	if (!rsa) {
		BN_free(bne);
		EVP_PKEY_free(evpkey);
		return RV_AlgoTypeErr;
	}
	BN_free(bne);
	int rv = EVP_PKEY_set1_RSA(evpkey, rsa);
	if (rv != 1) {
		EVP_PKEY_free(evpkey);
		return RV_AlgoTypeErr;
	}

	derprivatekeylen = i2d_PrivateKey(evpkey, NULL);
	derprivatekey = (unsigned char*)malloc(derprivatekeylen + 1);
	if (derprivatekey == NULL) {
		EVP_PKEY_free(evpkey);
		return RV_MemoryErr;
	}
	tmp = derprivatekey;

	int derpublickeylen = i2d_PublicKey(evpkey, NULL);
	derpublickey = (unsigned char*)malloc(derpublickeylen + 1);
	if (derpublickey == NULL) {
		EVP_PKEY_free(evpkey);
		free(derprivatekey);
		return RV_MemoryErr;
	}
	unsigned char* tmp2 = derpublickey;

	rv = i2d_PrivateKey(evpkey, &tmp);
	rv = i2d_PublicKey(evpkey, &tmp2);

	EVP_PKEY_free(evpkey);
	if (privatekey == NULL) {
		free(derprivatekey);
		free(derpublickey);
		return RV_MemoryErr;
	}
	else {
		memcpy(privatekey, derprivatekey, derprivatekeylen);
		//*privateLen = derprivatekeylen;

		//encrypt with device_id
		ret = encryptPrivateKeyWithDeviceID(privatekey,derprivatekeylen,device_id,e_privatekey,&e_derprivatekeylen);
		if (ret != RV_OK) {
			free(derprivatekey);
			return ret;
		}
		base64_pri = (unsigned char*)malloc(2 * e_derprivatekeylen);
		memset(base64_pri, 0, 2 * e_derprivatekeylen);
		ret = Base64_Encode(e_privatekey, e_derprivatekeylen, base64_pri, &base64_pri_len);
		fp_pri = fopen("private_key.pem", "w");
		fwrite(base64_pri, base64_pri_len, 1, fp_pri);
		fclose(fp_pri);
		free(base64_pri);
	}
	if (publickey == NULL) {
		free(derprivatekey);
		free(derpublickey);
		return RV_MemoryErr;
	}
	else {
		memcpy(publickey, derpublickey, derpublickeylen);
		//*publickeylen = derpublickeylen;
		base64_pub = (unsigned char*)malloc(2 * derpublickeylen);
		memset(base64_pub, 0, 2 * derpublickeylen);
		ret = Base64_Encode(publickey, derpublickeylen, base64_pub, &base64_pub_len);
		fp_pub = fopen("public_key.pem", "w");
		fwrite(base64_pub, base64_pub_len, 1, fp_pub);
		fclose(fp_pub);
		free(base64_pub);
	}
	free(derprivatekey);
	free(derpublickey);
	return RV_OK;
}

#endif


//p1 encrypt
unsigned long Pkcs1RsaPublickKeyEnc(unsigned char*publicKey, unsigned long publickeylen, unsigned char* indata, unsigned long indatalen, unsigned char* outdata, unsigned long* outdatalen)
{
	EVP_PKEY *pkey;
	unsigned char* derpublickey;
	unsigned char* tmp = NULL;
	unsigned char* outTmp;

	if (indatalen<0 || indatalen>117) {
		return RV_IndataLenErr;
	}
	derpublickey = (unsigned char *)malloc(publickeylen);
	memcpy(derpublickey, publicKey, publickeylen);
	tmp = publicKey;
	pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, (const unsigned char **)&tmp, publickeylen);
	if (pkey == NULL) {
		free(derpublickey);
		return RV_MemoryErr;
	}
	free(derpublickey);
	*outdatalen = EVP_PKEY_bits(pkey) / 8;
	outTmp = (unsigned char *)malloc(*outdatalen + 1);
	//int rv = EVP_PKEY_encrypt_old(outTmp, indata, indatalen, pkey);
	int rv = EVP_PKEY_encrypt(outTmp, indata, indatalen, pkey);
	//EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey,NULL);
	//int rv = EVP_PKEY_encrypt(ctx,outTmp,outdatalen,indata,indatalen);

	if (rv <= 0) {
		free(outTmp);
		free(derpublickey);
		return RV_EncErr;
	}
	if (outdata != NULL) {
		memcpy(outdata, outTmp, *outdatalen);
	}

	free(outTmp);
	return RV_OK;
}


unsigned long Pkcs1RsaPrivateKeyDec(unsigned char* privateKey, unsigned long privateKeyLen, unsigned char* indata, unsigned long indatalen, unsigned char* outdata, unsigned long* outdatalen)
{
	EVP_PKEY *pkey;
	unsigned char *tmp;
	unsigned char* outTmp;
	//EVP_PKEY_CTX *ctx = NULL;

	if (!(indatalen == 64 || indatalen == 128 || indatalen == 256)) {
		return RV_DATALENErr;
	}
	if (privateKey == NULL) {
		return RV_MemoryErr;
	}

	
	tmp = privateKey;
	pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, (const unsigned char **)&tmp, privateKeyLen);
	if (pkey == NULL) {
		return RV_PRIKEYErr;
	}

	/*ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (ctx == NULL) {
		EVP_PKEY_free(pkey);
		return -1;
	}
	*/
	*outdatalen = EVP_PKEY_bits(pkey) / 8;
        
	outTmp = (unsigned char *)malloc(*outdatalen + 1);
	int rv = EVP_PKEY_decrypt(outTmp, indata, indatalen, pkey);
	//int rv = EVP_PKEY_decrypt_old(outTmp, indata, indatalen, pkey);
	if (rv<0) {
		free(outTmp);
		return RV_DecErr;
	}
	*outdatalen = rv;
	if (outdata != NULL) {
		memcpy(outdata, outTmp, *outdatalen);
	}

	free(outTmp);
	EVP_PKEY_free(pkey);
	return RV_OK;
}

//algorithm
int Nid_BCA2OpenSSL(int Algorithm ,int Mod)
{
	switch(Algorithm)
	{
	case BCA_ALGO_MD2:
		return NID_md2;
		break;
	case BCA_ALGO_MD5:
		return NID_md5;
		break;
	case BCA_ALGO_SHA1_160:
		return NID_sha1;
		break;
	case BCA_ALGO_DES:
		switch(Mod) 
		{
		case BCA_MODE_ECB:
			return NID_des_ecb;
			break;
		case BCA_MODE_CBC:
			return NID_des_cbc;
			break;
		case BCA_MODE_CFB:
			return NID_des_cfb64;
			break;
		case BCA_MODE_OFB:
			return NID_des_ofb64;
			break;
		default:
			return 0;
		}
		break;
	case BCA_ALGO_AES:
		switch (Mod)
		{
		case BCA_MODE_ECB:
			return NID_aes_128_ecb;
			break;
		case BCA_MODE_CBC:
			return NID_aes_128_cbc;
			break;
		case BCA_MODE_CFB:
			return NID_aes_128_cfb128;
			break;
		case BCA_MODE_OFB:
			return NID_aes_128_ofb128;
			break;
		default:
			break;
		}

	case BCA_ALGO_3DES_2KEY:
		switch(Mod) 
		{
		case BCA_MODE_ECB:
			return NID_des_ede3_ecb;
			break;
		case BCA_MODE_CBC:
			return NID_des_ede3_cbc;
			break;
		case BCA_MODE_CFB:
			return NID_des_ede3_cfb64;
			break;
		case BCA_MODE_OFB:
			return NID_des_ede3_ofb64;
			break;
		default:
			return 0;
		}
		break;

	case BCA_ALGO_3DES_3KEY:
		switch(Mod) 
		{
		case BCA_MODE_ECB:
			return NID_des_ede3_ecb;
			break;
		case BCA_MODE_CBC:
			return NID_des_ede3_cbc;
			break;
		case BCA_MODE_CFB:
			return NID_des_ede3_cfb64;
			break;
		case BCA_MODE_OFB:
			return NID_des_ede3_ofb64;
			break;
		default:
			return 0;
		}

		break;
	case BCA_ALGO_RC2:
		switch(Mod) 
		{
		case BCA_MODE_ECB:
			return NID_rc2_ecb;
			break;
		case BCA_MODE_CBC:
			return NID_rc2_cbc;
			break;
		case BCA_MODE_CFB:
			return NID_rc2_cfb64;
			break;
		case BCA_MODE_OFB:
			return NID_rc2_ofb64;
			break;
		default:
			return 0;
		}
		break;
	case BCA_ALGO_RC4:
		return NID_rc4;
		break;
	case BCA_ALGO_RSA:
		return NID_rsa;
		break;
	default:
		return 0;
	}//end switch
	return 0;
}


unsigned char * encryptWithPublicKey(const char *publicKeyPath, char *src) {
	BIO *in;
	RSA *read;
	unsigned char *p_en;
	unsigned char *errmsg = (unsigned char *)malloc(32 + 1);
	unsigned char*tmp = (unsigned char *)"00000000000000000000000000000000";
	OpenSSL_add_all_algorithms();

	memcpy(errmsg, tmp, 33);
	in = BIO_new_file(publicKeyPath, "rb");
	if (in == NULL) {
		return errmsg;
		EVP_cleanup();
	}
	read = RSA_new();
	read = PEM_read_bio_RSAPublicKey(in, &read, NULL, "123456");
	if (read != NULL) {
		int rsa_len = RSA_size(read);
		p_en = (unsigned char*)malloc(rsa_len + 1);
		memset(p_en, 0, rsa_len + 1);

		BIO_free(in);
		int ret = RSA_public_encrypt(rsa_len, (unsigned char *)src, (unsigned char*)p_en, read, RSA_NO_PADDING);
		if (ret< 0) {
			RSA_free(read);
			return errmsg;
		}
	}
	else {
		RSA_free(read);
		return errmsg;
	}
	RSA_free(read);
	EVP_cleanup();
	return p_en;
}


unsigned char* decryptWithPrivateKey(const char *privateKeyPath, unsigned char *src) {
	BIO *in;
	RSA *read;
	unsigned char *p_en;
	unsigned char *errmsg = (unsigned char *)malloc(32 + 1);
	unsigned char*tmp = (unsigned char *)"00000000000000000000000000000000";
	OpenSSL_add_all_algorithms();

	memcpy(errmsg, tmp, 33);

	in = BIO_new_file(privateKeyPath, "rb");
	if (in == NULL) {
		return errmsg;
		EVP_cleanup();
	}
	read = RSA_new();
	read = PEM_read_bio_RSAPrivateKey(in, &read, NULL, "123456");
	if (read != NULL) {
		int rsa_len = RSA_size(read);
		p_en = (unsigned char*)malloc(rsa_len + 1);
		memset(p_en, 0, rsa_len + 1);

		BIO_free(in);
		int ret = RSA_private_decrypt(rsa_len, src, (unsigned char*)p_en, read, RSA_NO_PADDING);
		if (ret< 0) {
			RSA_free(read);
			return errmsg;
		}
	}
	else {
		RSA_free(read);
		return errmsg;
	}
	RSA_free(read);
	EVP_cleanup();
	return p_en;
}

void freeEncDec(unsigned char * data) {
	if (data) {
		free(data);
		data = NULL;
	}
}



int RsaSign(
	unsigned char *privateKey,
	unsigned long privateKeyLen,
	unsigned long hashAlgorithmType,
	unsigned char *hashValue,
	unsigned long hashValueLen,
	unsigned char *signData,
	unsigned long *signDataLen)
{

	EVP_PKEY *evpKey = NULL;

	int rv;

	unsigned char *derTmp;
	unsigned char *TmpOutData;
	EVP_MD_CTX ctx;
	EVP_MD *type;
	unsigned int tmpLen;

	*signDataLen = 0;
	type = (EVP_MD *)EVP_get_digestbynid(Nid_BCA2OpenSSL(hashAlgorithmType, 0));
	if (type == NULL)
		return RV_AlgoTypeErr;



	derTmp = privateKey;
	evpKey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, (const unsigned char**)&derTmp, privateKeyLen);
	if (evpKey == NULL)
	{
		return -1;
	}

	*signDataLen = EVP_PKEY_bits(evpKey) / 8;
	EVP_MD_CTX_init(&ctx);
	if (EVP_SignInit(&ctx, type) != 1)
	{
		EVP_MD_CTX_cleanup(&ctx);
		EVP_PKEY_free(evpKey);
		return -1;
	}
	if (EVP_SignUpdate(&ctx, hashValue, hashValueLen) != 1)
	{
		EVP_MD_CTX_cleanup(&ctx);
		EVP_PKEY_free(evpKey);
		return -2;
	}
	TmpOutData = (unsigned char*)malloc(2 * (*signDataLen));

	rv = EVP_SignFinal(&ctx, TmpOutData, &tmpLen, evpKey);
	if (rv != 1)
	{
		EVP_MD_CTX_cleanup(&ctx);
		free(TmpOutData);
		EVP_PKEY_free(evpKey);
		return -3;
	}
	*signDataLen = tmpLen;
	if (signData != NULL)
	{
		memcpy(signData, TmpOutData, *signDataLen);
	}
	free(TmpOutData);
	EVP_MD_CTX_cleanup(&ctx);
	if (evpKey != NULL)
		EVP_PKEY_free(evpKey);
	return 0;
}



int BCA_RsaVerifySign_old(
	unsigned long hashAlgorithmType,
	unsigned char *hashValue,
	unsigned long hashValueLen,
	unsigned char *publicKey,
	unsigned long publicKeyLen,
	unsigned char *signData,
	unsigned long signDataLen)
{
	EVP_PKEY *evpKey = NULL;
	int rv;
	unsigned char *derPubKey;
	unsigned char *derTmp;
	EVP_MD_CTX ctx;
	EVP_MD *type = NULL;

	type = (EVP_MD *)EVP_get_digestbynid(Nid_BCA2OpenSSL(hashAlgorithmType, 0));
	if (type == NULL)
		return RV_AlgoTypeErr;

	derPubKey = (unsigned char *)malloc(publicKeyLen);
	derTmp = derPubKey;
	memcpy(derPubKey, publicKey, publicKeyLen);

	evpKey = d2i_PublicKey(EVP_PKEY_RSA, NULL, (const unsigned char**)&derTmp, publicKeyLen);
	if (evpKey == NULL)
	{
		free(derPubKey);
		return -9;
	}
	free(derPubKey);
	EVP_MD_CTX_init(&ctx);
	if (EVP_VerifyInit(&ctx, type) != 1)
	{
		EVP_MD_CTX_cleanup(&ctx);
		return -1;
	}
	if (EVP_VerifyUpdate(&ctx, hashValue, hashValueLen) != 1)
	{
		EVP_MD_CTX_cleanup(&ctx);
		return -8;
	}
	rv = EVP_VerifyFinal(&ctx, signData, signDataLen, evpKey);
	if (rv != 1)
	{
		EVP_MD_CTX_cleanup(&ctx);
		return -7;
	}
	if (evpKey != NULL)
		EVP_PKEY_free(evpKey);
	EVP_MD_CTX_cleanup(&ctx);
	return 0;
}


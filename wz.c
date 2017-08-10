#include "sym.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

unsigned long p1PublicKeyEnc(char* publicKey, unsigned char *indata, unsigned long indataLen, unsigned char *out, unsigned long *outlen) {

	unsigned char *public_key = NULL;
	unsigned long public_key_len = 0;
	int ret = 0;
	int publicKey_len = 0;
	//base64_dec
	if (publicKey == NULL || out == NULL) {
		*outlen = 0;
		return RV_PARAMETERErr;
	}
	publicKey_len = strlen(publicKey);
	public_key = (unsigned char*)malloc(publicKey_len);
	if (public_key == NULL) {
		return RV_MemoryErr;
	}
	memset(public_key, 0, sizeof(public_key));

	ret = Base64_Decode((unsigned char*)publicKey, publicKey_len, public_key, &public_key_len);
	if (ret != RV_OK) {

		free(public_key);
		return RV_BASE64DecodeErr;
	}
	ret = Pkcs1RsaPublickKeyEnc(public_key, public_key_len, indata, indataLen, out, outlen);
	if (ret != RV_OK) {
		free(public_key);
		return RV_RsaEncErr;
	}
	free(public_key);
	return RV_OK;
}
/*
int decryptPrivateKeyByDeviceID(unsigned char *privateKey,unsigned long privateKeyLen, char*device_id,unsigned char *outdata,unsigned long *outdatalen) {
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
*/
/**********************************************************
  private_key--->E(device_id)[private_key]---->Base64
**********************************************************/
unsigned long p1PrivateKeyDecWithID(char *privateKey, char *device_id, unsigned char *indata, unsigned long indataLen, unsigned char *out, unsigned long *outlen) {
	unsigned char *private_key = NULL;
	unsigned long private_key_len = 0;
	unsigned char u_private_key[1024] = { 0 };
	unsigned long u_private_key_len = 0;
	int ret = 0;
	int privateKey_len = 0;

	if (privateKey == NULL || out == NULL||device_id==NULL||strlen(device_id)==0) {
		return RV_PARAMETERErr;
	}

	//base64_dec
	privateKey_len = strlen(privateKey);
	private_key = (unsigned char*)malloc(privateKey_len);
	if (private_key == NULL) {
		return RV_MemoryErr;
	}
	memset(private_key, 0, privateKey_len);
	ret = Base64_Decode((unsigned char*)privateKey, privateKey_len, private_key, &private_key_len);
	if (ret != RV_OK) {
		free(private_key);
		return RV_BASE64DecodeErr;
	}

	//decrypt by device_id
	ret = decryptPrivateKeyByDeviceID(private_key, private_key_len, device_id, u_private_key, &u_private_key_len);
	if (ret != RV_OK) {
		free(private_key);
		return RV_RsaDecErr;
	}
	ret = Pkcs1RsaPrivateKeyDec(u_private_key, u_private_key_len, indata, indataLen, out, outlen);
	if (ret != RV_OK) {
		free(private_key);
		return RV_RsaDecErr;
	}
	free(private_key);
	return RV_OK;
}

unsigned long p1PrivateKeyDec(char* privateKey, unsigned char *indata, unsigned long indataLen, unsigned char *out, unsigned long *outlen) {

	unsigned char *private_key = NULL;
	unsigned long private_key_len = 0;
	int ret = 0;
	int privateKey_len = 0;
	
	if (privateKey == NULL || out == NULL) {
		return RV_PARAMETERErr;
	}

	//base64_dec
	privateKey_len = strlen(privateKey);
	private_key = (unsigned char*)malloc(privateKey_len);
	if (private_key == NULL) {
		return RV_MemoryErr;
	}
	memset(private_key, 0, privateKey_len);
	ret = Base64_Decode((unsigned char*)privateKey, privateKey_len, private_key, &private_key_len);
	if (ret != RV_OK) {
		free(private_key);
		return RV_BASE64DecodeErr;
	}

	ret = Pkcs1RsaPrivateKeyDec(private_key, private_key_len, indata, indataLen, out, outlen);
	if (ret != RV_OK) {
		free(private_key);
		return RV_RsaDecErr;
	}
	free(private_key);
	return RV_OK;
}



int pkcs1_rsa_sign(
	unsigned long hashAlgorithmType,
	unsigned char* hash_value,
	unsigned long hash_len,
	char *private_key,
	unsigned char* sign_value,
	unsigned long *sign_value_len)
{

	int ret = RV_OK;
	unsigned char *privateKey = NULL;
	unsigned long privateKey_len = 0;
	unsigned long pri_len = 0;
	

	if (private_key != NULL && private_key != NULL && sign_value != NULL) {
		//base64_dec
		privateKey_len = strlen(private_key);
		privateKey = (unsigned char*)malloc(privateKey_len);
		if (privateKey == NULL) {
			return RV_MemoryErr;
		}
		memset(privateKey, 0, privateKey_len);
		ret = Base64_Decode((unsigned char*)private_key, privateKey_len, privateKey, &pri_len);
		if (ret != RV_OK) {
			free(privateKey);
			return RV_BASE64DecodeErr;
		}
		
		ret = RsaSign(privateKey, privateKey_len, hashAlgorithmType, hash_value, hash_len, sign_value, sign_value_len);
		if (ret != RV_OK) {
			free(privateKey);
			return RV_SignErr;
		}
	}else {
		return RV_PARAMETERErr;
	}

	return ret;

}
/******************************************************
 private_key--->E(device_id)[private_key]---->Base64
******************************************************/
int pkcs1_rsa_sign_with_deviceID(
	unsigned long hashAlgorithmType,
	unsigned char* hash_value,
	unsigned long hash_len,
	char *private_key,
	char *device_id,
	unsigned char* sign_value,
	unsigned long *sign_value_len)
{

	int ret = RV_OK;
	unsigned char *privateKey = NULL;
	unsigned long privateKey_len = 0;
	unsigned long pri_len = 0;
	unsigned char u_private_key[1024] = { 0 };
	unsigned long u_private_key_len = 0;

	if (private_key != NULL && private_key != NULL && sign_value != NULL) {
		//base64_dec
		privateKey_len = strlen(private_key);
		privateKey = (unsigned char*)malloc(privateKey_len);
		if (privateKey == NULL) {
			return RV_MemoryErr;
		}
		memset(privateKey, 0, privateKey_len);
		ret = Base64_Decode((unsigned char*)private_key, privateKey_len, privateKey, &pri_len);
		if (ret != RV_OK) {
			free(privateKey);
			return RV_BASE64DecodeErr;
		}
		//decrypt by device_id
		ret = decryptPrivateKeyByDeviceID(privateKey, pri_len, device_id, u_private_key, &u_private_key_len);
		if (ret != RV_OK) {
			free(privateKey);
			return RV_RsaDecErr;
		}
		ret = RsaSign(u_private_key, u_private_key_len, hashAlgorithmType, hash_value, hash_len, sign_value, sign_value_len);
		if (ret != RV_OK) {
			free(privateKey);
			return RV_SignErr;
		}
	}
	else {
		return RV_PARAMETERErr;
	}

	return ret;

}

int pkcs1_rsa_verify(
	unsigned long hashAlgorithmType,
	unsigned char *hashValue,
	unsigned long hashValueLen,
	char *public_Key,
	unsigned char *signData,
	unsigned long signDataLen)
{
	//base64 decode publickey
	unsigned char *publicKey = NULL;
	int publicKey_len = 0;
	int ret = 0;
	unsigned long privateKey_len = 0;

	publicKey_len = strlen(public_Key);
	publicKey = (unsigned char*)malloc(publicKey_len);
	if (publicKey == NULL) {
		return RV_MemoryErr;
	}
	ret = Base64_Decode((unsigned char*)public_Key, publicKey_len, publicKey, &privateKey_len);
	if (ret != RV_OK) {
		free(publicKey);
		return RV_BASE64DecodeErr;
	}
	return BCA_RsaVerifySign_old(hashAlgorithmType, hashValue, hashValueLen, publicKey, privateKey_len, signData, signDataLen);
}

/*******************************************************
 
********************************************************/
int pkcs1_rsa_sign_with_hash(
	unsigned char* rand,//随机数
	unsigned long rand_len,
	char *private_key,
	char *device_id,
	unsigned char* sign_value,//hash+signature
	unsigned long *sign_value_len) {

	int ret = RV_OK;
	unsigned char hash_value[64] = { 0 };
	unsigned long hash_len = 0;
	unsigned char signature[256] = { 0 };
	unsigned long signature_len = 0;

	if (private_key == NULL || sign_value == NULL||rand==NULL) {
		memset(sign_value, '1', 148);
		*sign_value_len = 148;
		return RV_PARAMETERErr;
	}

	ret = Hash(BCA_ALGO_SHA1_160, rand, rand_len, hash_value, &hash_len);
	if (ret != RV_OK)
	{
		memset(sign_value, '2', 148);
		*sign_value_len = 148;
		return RV_HashErr;
	}else {
		//ret = pkcs1_rsa_sign(BCA_ALGO_SHA1_160, hash_value, hash_len, private_key, signature, &signature_len);
		ret = pkcs1_rsa_sign_with_deviceID(BCA_ALGO_SHA1_160, hash_value, hash_len, private_key, device_id, signature, &signature_len);
		if (ret != RV_OK) {
			memset(sign_value, '3', 148);
			*sign_value_len = 148;
			return ret;
		}
		memcpy(sign_value, hash_value, hash_len);
		memcpy(sign_value + hash_len, signature, signature_len);
		*sign_value_len = hash_len + signature_len;
		return RV_OK;
	}

}

int pkcs1_rsa_verify_with_hash(unsigned char *signature,unsigned signature_len, char *public_Key) {
	unsigned char hashValue[64] = { 0 };
	unsigned char sign_data[256] = { 0 };
	int ret = RV_OK;

	if (signature == NULL || signature_len != 148) {
		return RV_PARAMETERErr;
	}
	memcpy(hashValue, signature, 20);
	memcpy(sign_data, signature + 20, 128);

	ret = pkcs1_rsa_verify(BCA_ALGO_SHA1_160, hashValue, 20, public_Key, sign_data, 128);
	return ret;
}

#ifdef GEN

/***************************************************************
func: 根据连接数与设备唯一号生成license
para:
	device_id: 设备唯一号
	connct_num：连接数

return:
    license
***************************************************************/
int gen_license(const char *device_id, const char *connect_num, char *license) {
	int ret = 0;
	unsigned long sym;
	unsigned char key[16] = { 0 };
	unsigned char iv[16] = { 0 };
	unsigned char hash_mac[20] = { 0 };
	unsigned long hash_len = 0;
	char indata[128] = { 0 };
	unsigned long tmplen = 0;
	unsigned char out[128] = { 0 };
	unsigned long outlen = 0;

	int k = 0, i = 0;
	char tmp[128] = { 0 };
	if (license == NULL ||device_id==NULL|| strlen(device_id) == 0) {
		return -1;
	}
	ret = Hash(BCA_ALGO_SHA1_160, (unsigned char*)device_id, strlen(device_id), hash_mac, &hash_len);
	if (ret != RV_OK) {
		return -2;
	}
	for (size_t i = 0; i < 16; i++)
	{
		key[i] = hash_mac[i];
	}
	ret = Hash(BCA_ALGO_MD5, hash_mac, hash_len, iv, &tmplen);
	if (ret != RV_OK) {
		return -3;
	}

	ret = CreateSymmKeyObj(&sym, BCA_ALGO_AES, 1, BCA_MODE_CBC, key, 16, iv);
	if (ret != RV_OK) return -4;

	//sprintf(indata, "%s@%s", device_id, connect_num);
	snprintf(indata, sizeof(indata), "%s@%s", device_id, connect_num);
	ret = SymmEncrypt(sym, (unsigned char*)indata, strlen(indata), out, &outlen);
	if (ret != RV_OK) return -5;
	for (int i = 0; i < outlen; i++) {
		//printf("%02x", out[i]);
		k = i * 2;
		sprintf(tmp + k, "%02x", out[i]);

	}
	//license = _strupr(tmp);
	//return ;

	memcpy(license, tmp, 2 * outlen);
	return RV_OK;
}

#endif
/***************************************************************
 func: 根据license与设备唯一号获取连接数
 para:
	device_id: 设备唯一号
	license：序列号

 return:
	连接数
***************************************************************/
int get_connect_num(const char *device_id, const char *license) {
	int ret = 0;
	unsigned long sym;
	unsigned char key[16] = { 0 };
	unsigned char iv[16] = { 0 };
	unsigned char hash_mac[20] = { 0 };
	unsigned long hash_len = 0;
	unsigned long tmplen = 0;
	unsigned char indata[32] = { 0 };
	unsigned long outlen = 0;
	unsigned char out[32] = { 0 };
	unsigned char tmp[64] = { 0 };
	char x[2] = { 0 };
	if (device_id == NULL || license == NULL || strlen(device_id) == 0) return -2;

	ret = Hash(BCA_ALGO_SHA1_160, (unsigned char*)device_id, strlen(device_id), hash_mac, &hash_len);
	if (ret != RV_OK) return -3;
	for (size_t i = 0; i < 16; i++)
	{
		key[i] = hash_mac[i];
	}
	ret = Hash(BCA_ALGO_MD5, hash_mac, hash_len, iv, &tmplen);
	if (ret != RV_OK) return -4;
	ret = CreateSymmKeyObj(&sym, BCA_ALGO_AES, 0, BCA_MODE_CBC, key, 16, iv);
	if (ret != RV_OK) return -5;

	for (int i = 0; i < strlen(license) / 2; i++) {
		memcpy(x, license + 2 * i, 2);
		indata[i] = strtol(x, NULL, 16);
	}
	ret = SymmDecrypt(sym, (unsigned char*)indata, strlen(license) / 2, out, &outlen);
	if (ret != RV_OK) return -6;
	out[outlen] = '\0';
	char *p = strtok((char *)out, "@");
	p = strtok(NULL, "@");
	int num = atoi(p);

	return num;
}


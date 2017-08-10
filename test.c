#include "stdio.h"
#include "sym.h"
int main()
{
	char buf[128+1];
	char buf2[1024];
	char buf3[1024];
	char key[2048];
	FILE *fp = NULL;
	int ret;
	int outlen;
	int sign_value_len;
	fp = fopen("private_key.pem","r");
	fgets(key,sizeof(key),fp);
	fclose(fp);
	printf("%s\n",key);
	sprintf(buf,"%s","11111111112222222222333333333344444444445555555555666666666677777777778888888888999999999900000000001111111111222222222288888888");
    init_cryt();

	ret = p1PrivateKeyDecWithID(key,"aaaaaaaa", buf, strlen(buf), buf2, &outlen);
	printf("declen=%d\n",outlen);
	ret = pkcs1_rsa_sign_with_hash(buf2,outlen,key,"aaaaaaaa",buf3,&sign_value_len);

	int i = 0;
	for(i=0;i<sign_value_len;i++)
	{
		printf("%2x ",buf3[i]);
	}
    printf("\n buf3=%s\n",buf3);
	printf("sig_len=%d\n",sign_value_len);
	free_cryt();
	return 0;
}

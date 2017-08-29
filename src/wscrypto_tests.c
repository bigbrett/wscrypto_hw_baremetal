#include "sha256test.h"
#include "aestest.h"
#include "rsa1024test.h"


#define TESTAES 1
#define TESTSHA 1
#define TESTRSA 1


int main(void)
{
	xil_printf("\n**************Starting WS crypto hardware tests**************\n");
	int32_t res = 0;

	int numfails = 0;

#if TESTAES
	xil_printf("\n1. Testing AES...\n");
	res = aestest();
	xil_printf("aes result = %d\n",res);
	if (res) {
		numfails++;
		xil_printf("AES FAILED\n");
	}
	else
		xil_printf("AES SUCCESS!\n");
#endif

#if TESTSHA
	xil_printf("\n2. Testing SHA25...\n");
	res = sha256test();
	xil_printf("SHA256 result = %d\n",res);
	if (res) {
		numfails++;
		xil_printf("SHA256 FAILED\n");
	}
	else
		xil_printf("SHA256 SUCCESS!\n");
#endif


#if TESTRSA
	xil_printf("\n3. Testing RSA...\n");
	res = rsa_test();
	xil_printf("RSA result = %d\n",res);
	if (res) {
		numfails++;
		xil_printf("RSA FAILED\n");
	}
	else
		xil_printf("RSA SUCCESS!\n");
#endif

	if (numfails > 0)
		xil_printf("\n**************TEST RUN UNSUCCESSFUL**************\n");
	else
		xil_printf("\n**************TEST RUN SUCCESSFUL**************\n");

	return 0;
}

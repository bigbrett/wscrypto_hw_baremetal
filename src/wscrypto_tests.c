/*
 * main.c
 *
 *  Created on: Aug 16, 2017
 *      Author: brett
 */
#include "rsa1024test.h"
#include "sha256test.h"
#include "aestest.h"
#include <sleep.h>


#define TESTAES 0
#define TESTSHA 1
#define TESTRSA 0


int main(void)
{
	xil_printf("Starting WS crypto hardware tests\n");
	int32_t res = 0;

#if TESTAES
	xil_printf("Testing AES...\n");
	res = aestest();
	xil_printf("aes result = %d\n",res);
#endif

#if TESTSHA
	xil_printf("Testing SHA25...\n");
	res = sha256test();
	xil_printf("SHA256 result = %d\n",res);
#endif


#if TESTRSA
	xil_printf("Testing RSA...\n");
//	res = rsatest();
	xil_printf("RSA result = %d\n",res);
#endif

	while(1)
		sleep(1);



	return 0;
}

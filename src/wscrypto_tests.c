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

int main(void)
{
	xil_printf("Starting WS crypto hardware tests\n");
	xil_printf("Testing AES...\n");

	int32_t res = 0;
	res = aestest();
	xil_printf("aes result = %d\n",res);


	while(1)
		sleep(1);



	return 0;
}

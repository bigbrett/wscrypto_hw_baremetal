/*
 * sha256test.c
 *
 *  Created on: Apr 7, 2017
 *      Author: brett
 */


#include <xil_printf.h>
#include <stdio.h>
#include "xil_printf.h"
#include "xparameters.h"
#include "wssha.h" // Device driver for HLS HW block
#include "xil_cache.h"

#define DATASIZE 256
#define SHA256_HASHSIZE 32

static const uint8_t golden_ans[SHA256_HASHSIZE] = {0x6c,0x50,0x76,0x06,0x1b,0x0c,0xc3,0x1f,0x39,0x87,0x76,0x7c,0x06,0x2c,0xd1,0x33,0xab,0x13,0x07,0x34,0xa0,0xb8,0x18,0x4c,0x65,0xd0,0x65,0x88,0x18,0x23,0xb9,0x92};

int sha256test(void)
{
	uint8_t data[DATASIZE];                   // the data to hash
	volatile uint8_t digest[SHA256_HASHSIZE]; // the location of the digest
	uint32_t digest_len = SHA256_HASHSIZE;     // dummy variable will be overwritten

	// Fill data buffer with something interesting to hash
	xil_printf("\tData to hash: ");
	for (int i=0; i<DATASIZE; i++) {
		data[i] = 'A'+(i%26);
		xil_printf("%02X ",data[i]);
	}
	xil_printf("\n");


	int32_t status = sha256(data, DATASIZE, digest, &digest_len);

	print("\tRECIEVED SHA256_HASH: ");
	for (int i=0; i<SHA256_HASHSIZE; i++) {
		xil_printf("%02X ", digest[i]);
	}
	xil_printf("\n");

	if (memcmp(golden_ans,digest,SHA256_HASHSIZE))
	{
		xil_printf("\tERROR, SHA256 DIGEST INCORRECT\n");
		return -1;
	}

	else
		xil_printf("\tSHA256 SUCCESS!\n");
	return status;
}

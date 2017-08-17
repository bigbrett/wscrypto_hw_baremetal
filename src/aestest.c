/*
 * aestest.c
 *
 *  Created on: Jun 6, 2017
 *      Author: brett
 */

#include <xil_printf.h>
#include <stdio.h>
#include "xil_printf.h"
#include "xparameters.h"
#include "wsaes.h" // Device driver for HLS HW block
#include "xaescbc.h"
#include "xil_cache.h"

uint8_t vRAM[1024];
uint8_t key[AESKEYSIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
							0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
							0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
uint8_t iv[AESIVSIZE] = {  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		 	 	   	   	   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
char openSSL_result[32] = { 0xA8, 0x87, 0x01, 0xE4, 0x43, 0x4F, 0x59, 0x00, 0x9F, 0xF8, 0x9A, 0x40, 0x29, 0x98, 0x49, 0x57,
							0x99, 0x29, 0x0C, 0x6C, 0xB1, 0xB1, 0x6D, 0x1A, 0x8B, 0x0A, 0xF7, 0xAF, 0x2D, 0x96, 0x7E, 0xF1};
const char teststr[32] = "The Quick Brown Fox Jumped Over "; // string to encrypt


static void dumpmsg( uint8_t *pbuf )
{
	int index;

	for( index = 0; index < 16; index++ )
		xil_printf("%02X ", pbuf[index]);

	xil_printf("\n");
}


int aestest(void)
{
	print("\r\nTesting AES CBC 256...\r\n");

	// Initialize engine
	xil_printf("Initializing AES...\n");
	int status = aes256init();
	xil_printf("Init Result == %d\n",status);


	xil_printf("Beginning test...\n");

	Xil_DCacheDisable();

	uint8_t buf0[32];
	uint8_t buf1[32];
	memset(buf0,0,32);
	memset(buf1,0,32);

	// Text to encrypt/decrypt
	strncpy((char *)buf0, teststr, 32);
	xil_printf("TEXT  :\n");
	dumpmsg(buf0);
	dumpmsg(&(buf0[16]));

	// Test our engine
	aes256setkey(key);
	aes256setiv(iv);

	// Encrypt Text
//	XAescbc_Set_mode(&xaescbc, ENCRYPT);
//	XAescbc_Write_data_in_Bytes(&xaescbc, 0, (char*)buf0, 16);
//	startwait();
//	XAescbc_Read_data_out_Bytes(&xaescbc, 0, (char*)buf1,16);
//	XAescbc_Write_data_in_Bytes(&xaescbc, 0, (char*)&(buf0[16]),16);
//	startwait();
//	XAescbc_Read_data_out_Bytes(&xaescbc, 0, (char*)&(buf1[16]),16);
	aes256reset();
	aes256encrypt((char*)buf0,(char*)buf1);
	aes256encrypt((char*)&(buf0[16]), (char*)&buf1[16]);

	xil_printf("Encrypted text:\n");
	dumpmsg(buf1);
	dumpmsg(&(buf1[16]));

	if (memcmp(buf1, openSSL_result, 32))
	{
		xil_printf("ERROR: ENCRYPTED DATA NOT CORRECT\n");
		return -1;
	}

	// Erase the original plain text
	memset(buf0,0,32);

	// Decrypt
//	XAescbc_Set_mode(&xaescbc, DECRYPT);
//	XAescbc_Write_data_in_Bytes(&xaescbc, 0, (char*)buf1, 16);
//	startwait();
//	XAescbc_Read_data_out_Bytes(&xaescbc, 0, (char*)buf0,16);
//	XAescbc_Write_data_in_Bytes(&xaescbc, 0, (char*)&(buf1[16]),16);
//	startwait();
//	XAescbc_Read_data_out_Bytes(&xaescbc, 0, (char*)&(buf0[16]),16);
	aes256reset();
	aes256decrypt((char*)buf1, (char*)buf0);
	aes256decrypt((char*)&(buf1[16]), (char*)&buf0[16]);

	xil_printf("Decrypted text:\n");
	dumpmsg(buf0);
	dumpmsg(&(buf0[16]));

	//	if (strncmp(vRAM, teststr, 32))
	if (memcmp(buf0, teststr, 32))
	{
		xil_printf("ERROR: DECRYPTED DATA NOT CORRECT\n");
		return -1;
	}

	xil_printf("Success!\n");

	Xil_DCacheEnable();
	return 0;
}

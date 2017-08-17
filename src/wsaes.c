/*
 * wsaes.c
 *
 *  Created on: Jun 6, 2017
 *      Author: brett
 */
#include "wsaes.h"
#include "xaescbc.h"
#include <stdio.h>

// device structs
XAescbc xaescbc;
XAescbc_Config *aescbcPtr;

/*
 *
 */
static void startwait(void)
{
	XAescbc_Start(&xaescbc);
	// wait for result
	while( !XAescbc_IsDone(&xaescbc));
}


/*
 *
 */
int32_t aes256setkey(uint8_t *keyp)
{
	XAescbc_Set_mode(&xaescbc, SET_KEY);
	XAescbc_Write_data_in_Bytes(&xaescbc, 0, (char*)keyp, AESKEYSIZE);
	startwait();
	return XST_SUCCESS;
}


/*
 *
 */
int32_t aes256setiv(uint8_t *ivp)
{
	XAescbc_Set_mode(&xaescbc, SET_IV);
	XAescbc_Write_data_in_Bytes(&xaescbc, 0, (char*)ivp,  AESIVSIZE);
	startwait();
	return XST_SUCCESS;
}


/*
 *
 */
int32_t aes256encrypt(char *plaintext, char* ciphertext)
{
	XAescbc_Set_mode(&xaescbc, ENCRYPT);
	XAescbc_Write_data_in_Bytes(&xaescbc, 0, plaintext, 16);
	startwait();
	XAescbc_Read_data_out_Bytes(&xaescbc, 0, ciphertext ,16);
	return XST_SUCCESS;
}


/*
 *
 */
int32_t aes256decrypt(char *ciphertext, char* plaintext)
{
	XAescbc_Set_mode(&xaescbc, DECRYPT);
	XAescbc_Write_data_in_Bytes(&xaescbc, 0, ciphertext, 16);
	startwait();
	XAescbc_Read_data_out_Bytes(&xaescbc, 0, plaintext ,16);
	return XST_SUCCESS;
}


/*
 *
 */
int32_t aes256init(void)
{
	// Look Up the device configuration
	aescbcPtr = XAescbc_LookupConfig(XPAR_XAESCBC_0_DEVICE_ID);
	if (!aescbcPtr) {
		print("ERROR: Lookup of AES accelerator configuration failed.\n\r");
		return XST_FAILURE;
	}

	// Initialize the Device
	int status = XAescbc_CfgInitialize(&xaescbc, aescbcPtr);
	if (status != XST_SUCCESS) {
		print("ERROR: Could not initialize AES accelerator.\n\r");
		return XST_FAILURE;
	}
	XAescbc_DisableAutoRestart(&xaescbc);

	return XST_SUCCESS;
}


/*
 *
 */
int32_t aes256reset(void)
{
	XAescbc_Set_mode(&xaescbc, RESET);
	// start encryption
	startwait();
	return XST_SUCCESS;

}


/*
 *
 */
int32_t aes256(int mode,uint8_t *inp, uint32_t inlen, uint8_t *outp, uint32_t *outlenp)
{
//	XAescbc_Set_mode(&xaescbc, (mode_t)mode);
//	if (mode==RESET)
//		return XST_SUCCESS;
//	if (inlen%16 != 0)
//		return XST_FAILURE;
//
//	for (int i=0; i<inlen; i++)
//	{
//		XAescbc_Write_data_in_Bytes(&xaescbc, 0, inp, 16);
//		startwait();
//		XAescbc_Read_data_out_Bytes(&xaescbc, 0, outp ,16);
//		inp += 2;
//		outp +=2;
//	}
	return XST_SUCCESS;
}





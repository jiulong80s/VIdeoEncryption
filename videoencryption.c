/*
 * videoencryption.c
 *
 *  Created on: May 29, 2014
 *      Author: fabio
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "functions.h"
#include "encryptionlibrary.h"

// main entrypoint
int main(int argc, char **argv) {

	char *TS_FILE;
	char *TS_OUTPUT_FILE;
	unsigned char *aes_key;
	unsigned char *aes_iv;

	/* initialization */
	int computation_time, video_pid = -1;
	unsigned char *input_buffer;
	int buffer_size;
	int encrypt = 0;
	aes_key = malloc(16 * sizeof(char));
	aes_iv = malloc(16 * sizeof(char));
	TS_FILE = malloc(255 * sizeof(char));
	TS_OUTPUT_FILE = malloc(255 * sizeof(char));

	convert_input_params_to_vars(argc, argv, &TS_FILE, &TS_OUTPUT_FILE,
			&aes_key, &aes_iv, &encrypt);
	printf("\n Input clear file:%s", TS_FILE);
	printf("\n Output encrypted file:%s", TS_OUTPUT_FILE);
	printf("\n Key:");
	hex_print(aes_key, 16);
	printf("\n Iv:");
	hex_print(aes_iv, 16);
	if (encrypt)
		printf("\n ENCRYPTION \n");
	else
		printf("\n DECRYPTION \n");
	printf("\n");

	if (encrypt) {
		/*********** ENCRYPTION **************/
		// load file into memory
		buffer_size = loadFile(TS_FILE, &input_buffer);

		video_pid = extracth264VideoPid(input_buffer, buffer_size);
		if (video_pid < 0) {
			printf("\n ERROR: no H264 bitstream found. Quit\n");
			return 0;
		}
		printf("\n video_pid = %d\n", video_pid);

		computation_time = encryptTsStream(input_buffer, buffer_size, video_pid,
				aes_key, aes_iv);

		int result = saveFile(TS_OUTPUT_FILE, input_buffer, buffer_size);
		if (result)
			printf("\n encryption completed correctly in %d seconds \n",
					computation_time);
		else
			printf("\n encryption ERROR\n");
	} else {
		/*********** DECRYPTION **************/
		// load file into memory
		buffer_size = loadFile(TS_OUTPUT_FILE, &input_buffer);
		computation_time = decryptTsStream(input_buffer, buffer_size, aes_key,
				aes_iv);

		int result = saveFile(TS_OUTPUT_FILE, input_buffer, buffer_size);
		if (result)
			printf("\n decryption completed correctly in %d seconds \n",
					computation_time);
		else
			printf("\n decryption ERROR\n");
	}

	return 0;
}

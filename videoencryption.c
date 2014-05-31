/*
 * videoencryption.c
 *
 *  Created on: May 29, 2014
 *      Author: fabio
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "encryptionlibrary.h"

// main entrypoint
int main(int argc, char **argv) {

	char *TS_FILE = "/home/fabio/workspace2/DemoTS/file34-10MB.mpg";
	char *TS_OUTPUT_FILE = "/home/fabio/workspace2/DemoTS/encX-file34-10MB.mpg";

	unsigned char aes_key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F }; // 128:8=16

	unsigned char aes_iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

	const int VIDEO_PID = 0x31; // depending on the stream used

	/* initialization */
	unsigned char *input_buffer;
	int buffer_size;

	// load file into memory
	buffer_size = loadFile(TS_FILE, &input_buffer);

	encryptTsStream(input_buffer, buffer_size, VIDEO_PID, aes_key,
			aes_iv);

	int result = saveFile(TS_OUTPUT_FILE, input_buffer, buffer_size);
	if (result)
		printf("\n encryption completed correctly\n");
	else
		printf("\n encryption ERROR\n");

	return 0;
}

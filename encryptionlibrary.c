/*
 * encryptionlibrary.c
 *
 *  Created on: May 29, 2014
 *      Author: fabio
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include "encryptionlibrary.h"

// a simple hex-print routine. could be modified to print 16 bytes-per-line
void hex_print(const unsigned char *pv, size_t len) {

	if (NULL == pv)
		printf("NULL");
	else {
		size_t i = 0;
		int x = 0;
		printf("\n.0..1..2..3  | ..4..5..6..7\n");
		for (; i < len; ++i) {
			if (x==0) {
				printf("\n%d..", i);
			}
			printf("%02x ", pv[i]);
			if (x == 3)
				printf(" | ");
			if (x == 7) {
				x = 0;
//				printf("\n");
			} else
				x++;
		}
	}
	printf("\n");
}

int saveFile(char *path, unsigned char *buffer, int size) {
	FILE *fp; /*filepointer*/

	fp = fopen(path, "wb"); /*open file*/
	fseek(fp, 0, SEEK_SET);
	if (fp == NULL) { /*ERROR detection if file == empty*/
		printf("1 Error: There was an Error opening for W the file %s \n",
				path);
		exit(1);
	}
	int res = fwrite(buffer, size, sizeof(char), fp);
	return res;
}

int loadFile(char *path, unsigned char **buffer) {
	FILE *fp; /*filepointer*/
	size_t size; /*filesize*/

	fp = fopen(path, "rb"); /*open file*/
	fseek(fp, 0, SEEK_END);
	size = ftell(fp); /*calc the size needed*/
	fseek(fp, 0, SEEK_SET);
	*buffer = malloc(size * sizeof(char)); /*allocalte space on heap*/
	if (fp == NULL) { /*ERROR detection if file == empty*/
		printf("1 Error: There was an Error reading the file %s \n", path);
		exit(1);
	}

	int bytes_read = fread(*buffer, sizeof(char), size, fp);
	if (bytes_read != size) { /* if count of read bytes != calculated size of .bin file -> ERROR*/
		printf("2 Error: There was an Error reading the file %s size=%d", path,
				size);
		printf("2 Error: bytes_read =%d", bytes_read);
		exit(1);
	}
	return size;
}

int getH264StartCodeIndex(const unsigned char *pes_packet,
		int start_index, int pes_packet_length) {
	unsigned int H264_IFRAME_START_CODE[] = { 0x00, 0x00, 0x00, 0x01 }; // 5 bytes
	int H264_IFRAME_START_CODE_LEN = 4;
	int i, j;
	/* Searching */
	for (j = start_index; j <= pes_packet_length - H264_IFRAME_START_CODE_LEN; ++j) {
		for (i = 0;
				i < H264_IFRAME_START_CODE_LEN
						&& H264_IFRAME_START_CODE[i] == pes_packet[i + j]; ++i)
			;
		if (i >= H264_IFRAME_START_CODE_LEN)
			return j;
	}
	return -1;
}

void setTransportScramblingControl(unsigned char *ts_packet, unsigned char byte) {
	unsigned char transport_scrambling_control = (byte & 0x03);
	// clear the TSC
	ts_packet[3] = (ts_packet[3] & 0x3F);
	// set the TSC
	ts_packet[3] = (ts_packet[3] | (transport_scrambling_control << 6));
}

void Log(char * msg) {
	printf("\n-------> %s \n", msg);
}

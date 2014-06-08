/*
 * functions.c
 *
 *  Created on: June 8, 2014
 *      Author: fabio
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <openssl/evp.h>

#include "encryptionlibrary.h"
#include "functions.h"

void print_menu(char *this_program_name) {
	printf("\nUsage:");
	printf("%s -i [Input File Name] -o [Output File Name]",this_program_name);
	printf("\n-k [Key] -v [Vector] -l [progress log file name] -e [encryption(none for decryption)]");
	printf("\n");
}

void convert_Hex_string_to_uchar(char *myarg, unsigned char **uchar) {

	char *str = malloc(2 * sizeof(char));
	int i = 0, j = 0, value;
	char *p;
	for (; i < 2 * (16); i++) {
		str[0] = myarg[0 + i];
		str[1] = myarg[1 + i];
		value = strtoul(str, &p, 16);
		(*uchar)[j++] = value;
//		printf("\n-->%d", value);
		i++;
	}
}

void convert_input_params_to_vars(int argc, char **argv, char **TS_FILE,
		char **TS_OUTPUT_FILE, unsigned char **aes_key, unsigned char **aes_iv,
		int * video_pid, int *encrypt) {
	int c;
	while ((c = getopt(argc, argv, "h:i:o:k:v:l:p:e:")) != -1)
		switch (c) {
		case 'i':
			*TS_FILE = strdup(optarg);
			break;
		case 'o':
			*TS_OUTPUT_FILE = strdup(optarg);
			break;
		case 'k':
			convert_Hex_string_to_uchar(optarg, aes_key);
			break;
		case 'v':
			convert_Hex_string_to_uchar(optarg, aes_iv);
			break;
		case 'p':
			*video_pid = atoi(optarg) & 0xFF;
			break;
		case 'l':
			break;
		case 'e':
			printf("\ENCRYPTION");
			*encrypt = 1;
			break;
		case '?':
			print_menu(argv[0]);
			break;
		default:
			abort();
		}
}

// a simple hex-print routine. could be modified to print 16 bytes-per-line
void hex_print(const unsigned char *pv, size_t len) {

	if (NULL == pv)
		printf("NULL");
	else {
		size_t i = 0;
		int x = 0;
		printf("\n.0..1..2..3  | ..4..5..6..7\n");
		for (; i < len; ++i) {
			if (x == 0) {
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

void Log(char * msg) {
	printf("\n-------> %s \n", msg);
}




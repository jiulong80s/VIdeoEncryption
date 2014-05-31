/*
 * encryptionlibrary.c
 *
 *  Created on: May 29, 2014
 *      Author: fabio
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <openssl/evp.h>

#include "encryptionlibrary.h"

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

int getH264StartCodeIndex(const unsigned char *pes_packet, int start_index,
		int pes_packet_length) {
	unsigned int H264_IFRAME_START_CODE[] = { 0x00, 0x00, 0x00, 0x01 }; // 5 bytes
	int H264_IFRAME_START_CODE_LEN = 4;
	int i, j;
	/* Searching */
	for (j = start_index; j <= pes_packet_length - H264_IFRAME_START_CODE_LEN;
			++j) {
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

int encryptTsStream(unsigned char *input_buffer, int buffer_size, int VIDEO_PID,
		unsigned char aes_key[16], unsigned char aes_iv[16]) {

	static time_t time_start, time_end;

	int H264_IFRAME_START_CODE_LEN = 3;
	static int TS_PACKET_LEN = 188;
	int index = 0, pid, h264Index, inIframe = 0, out_len;
	int lastPacketIsIFrame = 0, pes_packet_length;

	unsigned char* ts_packet;
	unsigned char* pes_packet;
	unsigned char* aes_input;

	int interations = buffer_size / TS_PACKET_LEN;
	printf("-> %d iterations", interations);
	time_start = time(0);  // record initial time
	while (index < interations) {
//	while (index < 15) {
		ts_packet = input_buffer + (index * TS_PACKET_LEN);

		// 1) check we have the sync byte
		if (ts_packet[0] == 0x47) {

			// 2) check it's a video packet
			pid = ts_packet[2] + ((ts_packet[+1] & 0x1F) << 8);
			if (pid == VIDEO_PID) {
//				Log("Found a Video Pid");

				// 3) check Unit Start Indicator (USI) is 1
				if ((ts_packet[1] & 0x40) == 0x40) {
//					Log("Unit start Indicator :: Start of Video frame (I/P/B)");

					// 4) Check the TS packet has PAYLOAD B[3]&0x10 == 1.
					if ((ts_packet[3] & 0x10) == 0x10) {
//						Log("Found payload");
						int AFC_len = 0;

						// 4a) Se ha il payload, controllo che ci sia Adaptation Field Control (AFC)
						// B[3]&0x20 == 0x20
						if ((ts_packet[3] & 0x20) == 0x20) {
							// 4b) Se ha AFC, calcolo la sua lunghezza
							// AFC_len=B[4] altrimenti AFC_len=0
							AFC_len = ts_packet[4];
//							Log("Found AFC");
						} else {
//							Log("AFC not Found");
						}
//						printf("AFC len=%d", AFC_len);

						pes_packet = ts_packet + 4 + AFC_len;
						pes_packet_length = TS_PACKET_LEN - (4 + AFC_len);

						// getH264StartCodeIndex( bufer, startIndex, buffer_len)
						h264Index = getH264StartCodeIndex(pes_packet, 4,
								pes_packet_length);

						if (h264Index > -1) {
//							printf("trovato h264 payload a h264Index=%d",
//									h264Index);

							// 5) per ogni sequenza S, prendo il
							// NAL_unit_type S[3]
							int NAL_unit_type = pes_packet[h264Index
									+ H264_IFRAME_START_CODE_LEN + 1] & 0x1F;

//							printf("\n++++++++++++++++++++++++++++++++");
//							printf("\n-------indexh264=%d", h264Index);
//							hex_print(pes_packet, pes_packet_length);
//							printf("\n-------\n");
//							printf("\nNAL_unit_type=0x%02x", NAL_unit_type);
//							printf("\nNAL_unit index=%d",
//									(h264Index + H264_IFRAME_START_CODE_LEN + 1));
//							printf("\n------------------------------");

							// 6b) se e' 0x09 e' un Access Delimiter
							if (NAL_unit_type == 0x09) {
//								Log("Found a Access Delimiter");

								// 6c) Poi prendo il prox byte
								int primary_pic_type = pes_packet[h264Index
										+ H264_IFRAME_START_CODE_LEN + 1]
										& 0x60;
								primary_pic_type = primary_pic_type >> 5;
								switch (primary_pic_type) {
								case 0:
//									Log("I-Frame");
									inIframe = 1;
									break;
								case 1:
//									Log("P-Frame");
									inIframe = 0;
									break;
								case 2:
//									Log("B-Frame");
									inIframe = 0;
									break;
								default:
									Log("ERROR: frame undefined");
									return -1;
								}

							}
						} else {
//							Log("NOT a Access Delimiter");
						}

					} else {
//						Log("NO h264 payload");
					}

				} else {
//					Log("payload not Found");
				}
			} else {
//				Log("Not a a Video Pid");
			}

			if (inIframe == 1) {
//				Log("setTransportScramblingControl");
				unsigned char transport_scrambling_control = 0x00;
				if (lastPacketIsIFrame == 1) {
					transport_scrambling_control = 0x02; // [1][0]
				} else {
					// start of I-Frame !!!!
					transport_scrambling_control = 0x03; // [1][1]
				}
				setTransportScramblingControl(ts_packet,
						transport_scrambling_control);

				// +++++ encryption +++
				aes_input = ts_packet + 12;
				// Initialize OpenSSL
				EVP_CIPHER_CTX ctx;
				EVP_CIPHER_CTX_init(&ctx);
				EVP_CIPHER_CTX_set_padding(&ctx, 0); //0 for no padding, 1 for padding  // ret ==1 here
				EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, aes_key,
						aes_iv);
				EVP_EncryptUpdate(&ctx, aes_input, &out_len, aes_input, 176);
				// ----- encryption ---

				lastPacketIsIFrame = 1;
			} else {
				lastPacketIsIFrame = 0;
			}
			index++;
		} else {
			Log("ERROR: missed a sync byte. not a TS stream");
			return -1;
		}

	} // while()
	time_end = time(0);
	return (time_end - time_start);
}

int decryptTsStream(unsigned char *input_buffer, int buffer_size,
		unsigned char aes_key[16], unsigned char aes_iv[16]) {

	static time_t time_start, time_end;
	static int TS_PACKET_LEN = 188;
	int out_len, index = 0;
	unsigned char* ts_packet;
	unsigned char* aes_input;

	int interations = buffer_size / TS_PACKET_LEN;
	printf("-> %d iterations", interations);
	time_start = time(0);  // record initial time

	while (index < interations) {
		ts_packet = input_buffer + (index * TS_PACKET_LEN);

		// 1) check we have the sync byte
		if (ts_packet[0] == 0x47) {

			// 2) check it's encrypted
			// [1][0]  part of I-frame
			// [1][1] start of I-Frame
			if ((ts_packet[3] & 0x80) == 0x80) { // TO DO !!!!!!
				setTransportScramblingControl(ts_packet, 0x00);
				// +++++ dencryption +++
				aes_input = ts_packet + 12;
				// Initialize OpenSSL
				EVP_CIPHER_CTX ctx;
				EVP_CIPHER_CTX_init(&ctx);
				EVP_CIPHER_CTX_set_padding(&ctx, 0); //0 for no padding, 1 for padding  // ret ==1 here
				EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, aes_key,
						aes_iv);
				EVP_DecryptUpdate(&ctx, aes_input, &out_len, aes_input, 176);
				// ----- encryption ---

			}
			index++;
		} else {
			Log("ERROR: missed a sync byte. not a TS stream");
			return -1;
		}

	} // while()
	time_end = time(0);
	return (time_end - time_start);
}

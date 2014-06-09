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
#include "functions.h"

typedef enum MPEG2StreamType {
	BDA_UNITIALIZED_MPEG2STREAMTYPE = -1,
	Reserved1 = 0x00,
	ISO_IEC_11172_2_VIDEO = 0x01,
	ISO_IEC_13818_2_VIDEO = 0x02,
	ISO_IEC_11172_3_AUDIO = 0x03,
	ISO_IEC_13818_3_AUDIO = 0x04,
	ISO_IEC_13818_1_PRIVATE_SECTION = 0x05,
	ISO_IEC_13818_1_PES = 0x06,
	ISO_IEC_13522_MHEG = 0x07,
	ANNEX_A_DSM_CC = 0x08,
	ITU_T_REC_H_222_1 = 0x09,
	ISO_IEC_13818_6_TYPE_A = 0x0A,
	ISO_IEC_13818_6_TYPE_B = 0x0B,
	ISO_IEC_13818_6_TYPE_C = 0x0C,
	ISO_IEC_13818_6_TYPE_D = 0x0D,
	ISO_IEC_13818_1_AUXILIARY = 0x0E,
	ISO_IEC_13818_7_AUDIO = 0x0F,
	ISO_IEC_14496_2_VISUAL = 0x10,
	ISO_IEC_14496_3_AUDIO = 0x11,
	ISO_IEC_14496_1_IN_PES = 0x12,
	ISO_IEC_14496_1_IN_SECTION = 0x13,
	ISO_IEC_13818_6_DOWNLOAD = 0x14,
	METADATA_IN_PES = 0x15,
	METADATA_IN_SECTION = 0x16,
	METADATA_IN_DATA_CAROUSEL = 0x17,
	METADATA_IN_OBJECT_CAROUSEL = 0x18,
	METADATA_IN_DOWNLOAD_PROTOCOL = 0x19,
	IRPM_STREAMM = 0x1A,
	ITU_T_H264 = 0x1B, // ****
	ISO_IEC_13818_1_RESERVED = 0x1C,
	USER_PRIVATE = 0x10,
	ISO_IEC_USER_PRIVATE = 0x80,
	DOLBY_AC3_AUDIO = 0x81,
	DOLBY_DIGITAL_PLUS_AUDIO_ATSC = 0X87
} MPEG2StreamType;

/**
 * returns the video pid (if present) of the H264 video stream.
 * @params input_buffer: pointer to the ts stream
 * @params buffer_size: the size of the ts stream
 * @return the video pid.
 * If no H264 video pid is found returns -1;
 **/
int extracth264VideoPid(unsigned char *input_buffer, int buffer_size) {

	static int TS_PACKET_LEN = 188;
	int found = 0;
	int pid, index = 0;
	int PMT_pid = -1;
	int video_pid = -1, stream_type, stream_pid;
	unsigned char* ts_packet;

//	int index = 0, pid, h264Index, inIframe = 0, out_len;
//	int lastPacketIsIFrame = 0, pes_packet_length;

	int interations = buffer_size / TS_PACKET_LEN;
	while (index < interations && !found) {
		ts_packet = input_buffer + (index * TS_PACKET_LEN);

		// 1) check we have the sync byte
		if (ts_packet[0] == 0x47) {

			// 2) check it's a PAT (pid=0x00)
			pid = ts_packet[2] + ((ts_packet[+1] & 0x1F) << 8);
			if (pid == 0x00) {
				// found PAT, get the PMT pid
				PMT_pid = ((ts_packet[15] & 0x1F) << 8) + ts_packet[16];
//				printf("\ntrovato PAT !!! PMT pid = 0x%02x \n", PMT_pid);
			} else if (pid == PMT_pid) {
				// found PMT, extract the programs
//				printf("\ntrovato PMT !! \n");
//				hex_print(ts_packet, TS_PACKET_LEN);
				found = 1;
				int section_length = ((ts_packet[6] & 0x0F) << 8)
						+ ts_packet[7];
				int offset = 17;

				while ((offset - 4) < section_length) {
					stream_type = ts_packet[offset];
					stream_pid = ((ts_packet[offset + 1] & 0x1F) << 8)
							+ ts_packet[offset + 2];
//					printf(
//							"\n offset(%d) :: stream:: type=0x%02x , pid=0x%02x \n",
//							offset, stream_type, stream_pid);
					// check if it's h264 video stream
					if (stream_type == ITU_T_H264) {
//						printf("\nvideo is h264\n");
						video_pid = stream_pid;
//						printf("\ntrovato h264 video pid=0x%02x \n", video_pid);
					}
					offset += (5 + ((ts_packet[offset + 3] & 0x0F) << 8)
							+ ts_packet[offset + 4]);
//					printf("\n new offset=%d\n", offset);
				}

			}

		} else {
			printf("\n no sync byte ???? \n");
		}
		index++;
	} // while
	return video_pid;
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

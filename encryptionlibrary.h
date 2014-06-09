/*
 * encryptionlibrary.h
 *
 *  Created on: May 29, 2014
 *      Author: fabio
 */

#ifndef ENCRYPTIONLIBRARY_H_
#define ENCRYPTIONLIBRARY_H_

/**
 * returns the video pid (if present) of the H264 video stream.
 * @params input_buffer: pointer to the ts stream
 * @params buffer_size: the size of the ts stream
 * @return the video pid.
 * If no H264 video pid is found returns -1;
 **/
int extracth264VideoPid(unsigned char *input_buffer, int buffer_size);

int getH264StartCodeIndex(const unsigned char *pes_packet, int start_index,
		int pes_packet_length);

void setTransportScramblingControl(unsigned char *ts_packet, unsigned char byte);

int encryptTsStream(unsigned char *input_buffer, int buffer_size, int VIDEO_PID,
		unsigned char aes_key[16], unsigned char aes_iv[16]);

int decryptTsStream(unsigned char *input_buffer, int buffer_size,
		unsigned char aes_key[16], unsigned char aes_iv[16]);

#endif /* ENCRYPTIONLIBRARY_H_ */

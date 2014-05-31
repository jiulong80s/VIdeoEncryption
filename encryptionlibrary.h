/*
 * encryptionlibrary.h
 *
 *  Created on: May 29, 2014
 *      Author: fabio
 */

#ifndef ENCRYPTIONLIBRARY_H_
#define ENCRYPTIONLIBRARY_H_

void hex_print(const unsigned char *pv, size_t len);
int loadFile(char *path, unsigned char **buffer);
int saveFile(char *path, unsigned char *buffer, int size);

void Log(char * msg);

int getH264StartCodeIndex(const unsigned char *pes_packet, int start_index,
		int pes_packet_length);

void setTransportScramblingControl(unsigned char *ts_packet, unsigned char byte);

int encryptTsStream(unsigned char *input_buffer, int buffer_size, int VIDEO_PID,
		unsigned char aes_key[16], unsigned char aes_iv[16]);

int decryptTsStream(unsigned char *input_buffer, int buffer_size,
		unsigned char aes_key[16], unsigned char aes_iv[16]);

void print_menu(char *this_program_name);
void convert_Hex_string_to_uchar(char *myarg, unsigned char **uchar);
void convert_input_params_to_vars(int argc, char **argv, char **TS_FILE,
		char **TS_OUTPUT_FILE, unsigned char **aes_key, unsigned char **aes_iv,
		int * video_pid, int *encrypt);

#endif /* ENCRYPTIONLIBRARY_H_ */

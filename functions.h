/*
 * functions.h
 *
 *  Created on: June 6, 2014
 *      Author: fabio
 */

#ifndef FUNCTIONS_H_
#define FUNCTIONS_H_

int loadFile(char *path, unsigned char **buffer);
int saveFile(char *path, unsigned char *buffer, int size);

void Log(char * msg);

void print_menu(char *this_program_name);
void hex_print(const unsigned char *pv, size_t len);
void convert_Hex_string_to_uchar(char *myarg, unsigned char **uchar);
void convert_input_params_to_vars(int argc, char **argv, char **TS_FILE,
		char **TS_OUTPUT_FILE, unsigned char **aes_key, unsigned char **aes_iv,
		int * video_pid, int *encrypt);

#endif /* FUNCTIONS_H_ */

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

int getH264StartCodeIndex(const unsigned char *pes_packet,
		int start_index, int pes_packet_length);

void setTransportScramblingControl(unsigned char *ts_packet, unsigned char byte);

#endif /* ENCRYPTIONLIBRARY_H_ */

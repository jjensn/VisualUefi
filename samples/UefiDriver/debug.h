
#ifndef _DEBUG_H_
#define _DEBUG_H_

#define BACKDOOR_DEBUG_SERIAL_BUILTIN
#define SERIAL_BAUDRATE 115200
#define SERIAL_PORT_NUM SERIAL_PORT_0

#define BACKDOOR_DEBUG

#define MAX_STR_LEN 255

#define DbgStop() while (TRUE) {}

#ifdef BACKDOOR_DEBUG

void DbgMsg(char *lpszFile, int Line, char *lpszMsg, ...);

#else

#define DbgMsg

#endif
#endif

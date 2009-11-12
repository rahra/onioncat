#ifndef OCAT_I2P_H
#define OCAT_I2P_H


#define I2P_PREFIX {{{0xFD,0x60,0xDB,0x4D,0xDD,0xB5,0,0,0,0,0,0,0,0,0,0}}}
#define I2P_PREFIX_LEN 48

/*
23:16 <@zzz> #zzz.i2p FD87:D87E:EB43:a289:4dab:aec0:8c00:51a4
             ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p
23:16 <@zzz> ukeu3k5oycgaaune.onion=GKapJ8koUcBj~jmQzH (500 more chars)
*/

//! Length of an .i2p-URL (without ".b32.i2p" and '\0')
#define I2P_URL_LEN 16
//! Total length of .onion-URL
#define I2P_NAME_SIZE (I2P_URL_LEN + 9)
//! Total length of .onion-URL (equal to ONION_NAME_SIZE)
#define I2P_NAME_LEN I2P_NAME_SIZE

//! SOCKS port of TOR proxy
#define I2P_SOCKS_PORT 9050

#endif


# Example for ESP8266 and ESP32 of Encryption AES128 or AES256 mode CBC with PKCS7Padding.

It uses Using BearSSL of arduino.
It uses base64 library https://github.com/Densaugeo/base64_arduino.git to encode/decode strings to be sent/received through HTTP. 

[![GitHub version](https://img.shields.io/github/release/jjsanma1/Encryption-example-for-ESP8266-and-ESP32.AES128-or-AES256-CBCPKS7.svg)](https://github.com/jjsanma1/Encryption-example-for-ESP8266-and-ESP32.AES128-or-AES256-CBCPKS7/releases/latest)
[![GitHub download](https://img.shields.io/github/downloads/jjsanma1/Encryption-example-for-ESP8266-and-ESP32.AES128-or-AES256-CBCPKS7/total.svg)](https://github.com/jjsanma1/Encryption-example-for-ESP8266-and-ESP32.AES128-or-AES256-CBCPKS7/releases/latest)
[![GitHub stars](https://img.shields.io/github/stars/jjsanma1/Encryption-example-for-ESP8266-and-ESP32.AES128-or-AES256-CBCPKS7.svg)](https://github.com/jjsanma1/Encryption-example-for-ESP8266-and-ESP32.AES128-or-AES256-CBCPKS7/stargazers)

 **Author: JJ - December 2023**

 Tested in ESP8266 ESP12F (not tested for ESP32) .Platform IO v3.3.1. VSCode 1.85.0. ESP8266 boards 3.1.2 . 

 Basic Code:
  ```c
#if defined(ESP8266)
      #include <ESP8266WiFi.h> // OJO USAR SIEMPRE LA LIBRERIA INCLUIDA EN ESP8266/ARDUINO NO LA QUE SE CARGA DESDE EL GESTOR DE LIBRERIAS 
#elif defined(ESP32)
      #include <WiFi.h>
#else
//#error "This ain't a ESP8266 or ESP32, dumbo!"
#endif
#define BASE64_URL //https://github.com/Densaugeo/base64_arduino.git . in order to use url mode of base64 
#include "base64.hpp"
//key for encryption
  byte cipher_key[32]= {0xfa, 0x27, 0xf2, 0xf5, 0xe4, 0x19, 0x46, 0x77,
                 0x88, 0x96, 0xa6, 0x0B, 0xd9, 0xd7, 0xE5, 0x2F,
                 0xae, 0x14, 0x23, 0x15, 0x45, 0xe7, 0xed, 0xef,
                 0xcc, 0x22, 0xb6, 0xc4, 0xde, 0x34, 0x22, 0x11};


  //initial value for encryption
  byte cipher_iv[16] = {0x1a, 0x25, 0xf1, 0xa3, 0xf4, 0x29, 0x4f, 0x7a,
                 0x82, 0x1d, 0x6f, 0x0B, 0xd4, 0xd1, 0xb5, 0x1F};
  
/* Returns an String that is encrypted (AES128 or 256) and encoded (Base64 URL) and ready to be sent through HTTP.
 Uses PKCS7Padding= fulfills the last incomplete block with the number of bytes until 16.  
Warning : if the string is > 1000 Bytes , the ESP8266 crashes trying to encrypt the string -> use < 1000 Bytes in ESP8266
*/
String Encrypt(String plain_data,byte* c_key,byte* c_iv,int bits){//bits corresponds to 128 or 256
  int keybits=16;
  if (bits==256) keybits=32;
  int i;
  // PKCS#7 Padding (Encryption), Block Size : 16
  int len = plain_data.length();
  int n_blocks = len / 16 + 1;
  //****** PKCS#7 Padding
  uint8_t n_padding = n_blocks * 16 - len;//calculates padding required
  uint8_t data[n_blocks*16]; // creates the array to put the final encrypted text
  memcpy(data, plain_data.c_str(), len);//copies the original string to a new array of char
  for(i = len; i < n_blocks * 16; i++){ //padding of the last block
    data[i] = n_padding;
  }
  //****** encryption ******  
  uint8_t key[keybits], iv[16]; 
  memcpy(key, c_key, keybits);
  memcpy(iv, c_iv, 16);  
  br_aes_big_cbcenc_keys encCtx;// encryption context
  // resets the encryption context and encrypt the data
  br_aes_big_cbcenc_init(&encCtx, key, keybits);
  br_aes_big_cbcenc_run( &encCtx, iv, data, n_blocks*16);

  //****** Base64 encode ******
  len = n_blocks*16; 
  unsigned int base64_length =encode_base64_length(len); //calculates the lenght of the array of chars required to save the encoded string
  Serial.print("base64_length needed to encode: ");Serial.println(base64_length);  
  char encoded_data[ base64_length ];//creates the array to store the string encoded in base64
  base64_length = encode_base64(data,len, (unsigned char*)encoded_data);//encodes the array    
  return String(encoded_data);
}

/* Returns an String that is decrypted (AES128 or 256) and decoded (Base64 URL).
   Uses PKCS7Padding= fulfills the last incomplete block with the number of bytes until 16.     
*/
String Decrypt(String encoded_data_str,byte* c_key,byte* c_iv,int bits){  
  int keybits=16;
  if (bits==256) keybits=32; 
  char *encoded_data = const_cast<char*>(encoded_data_str.c_str()); //copies the encrypted string to char array
  //****** Base64 decode ******
  int nb=decode_base64_length((const unsigned char*) encoded_data);
  uint8_t data[ nb ];
  size_t len=decode_base64((unsigned char*)encoded_data, data);
  //******decyption ******
  uint8_t key[keybits], iv[16];
  memcpy(key, c_key, keybits);
  memcpy(iv, c_iv, 16);
  int n_blocks = len / 16;
  br_aes_big_cbcdec_keys decCtx;// decryption context
  // reset the decryption context and decrypt the data
  br_aes_big_cbcdec_init(&decCtx, key, keybits);
  br_aes_big_cbcdec_run( &decCtx, iv, data, n_blocks*16 );

  // PKCS#7 Padding (for Decryption)
  uint8_t n_padding = data[n_blocks*16-1];
  len = n_blocks*16 - n_padding;
  char plain_data[len + 1];
  memcpy(plain_data, data, len);
  plain_data[len] = '\0';

  return String(plain_data);
}
void setup()
{
  Serial.begin(74880);
  delay(500);
  Serial.println("Encrypting...");  
  String encdata = Encrypt("this is the encrypted string",cipher_key,cipher_iv,256);

  Serial.println("encrypted:");  
  Serial.println(encdata);  

  String decdata = Decrypt(encdata,cipher_key,cipher_iv,256);

  Serial.println("decrypted:");  
  Serial.println(decdata);
}

void loop()
{ 

}
```

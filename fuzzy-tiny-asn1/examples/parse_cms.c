#include "tiny-asn1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

void print_hex(uint8_t* data, unsigned int len)
{
  unsigned int count = 0;
  unsigned int blockCount = 0;
  while(count < len) {
    printf("%02x ", data[count]);
    ++count;
    ++blockCount;
    if(blockCount == 4)
      printf("  ");
    if(blockCount == 8) {
      printf("\n");
      blockCount = 0;
    }
  }
  printf("\n");
}

//int main(void)
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  // Created with echo "12345678901234567890"|openssl cms -EncryptedData_encrypt -aes128 -secretkey 39904F36D98779D00F9A2B8139D2957F -outform der|xxd --i
  uint8_t cms_data[] = {
  	0x31, 0x84, 0xff, 0xff, 0xff, 0xfa, 0xb0
  };

  int32_t asn1_object_count = der_object_count((uint8_t *)data, size);
  if(asn1_object_count < 0) {
    return 0;
  }

  asn1_tree* asn1_objects = (asn1_tree*)(malloc(sizeof(asn1_tree) * asn1_object_count));
  if(asn1_objects == NULL){
    return 0;
  }

  asn1_tree cms;

  der_decode((uint8_t *)data, size, &cms, asn1_objects, asn1_object_count);

  free(asn1_objects);

  return 0;
}

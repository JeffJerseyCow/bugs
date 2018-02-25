/*
 * Copyright (C) 2016 Mathias Tausig, FH Campus Wien
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3. See the file LICENSE in the top level
 * directory for more details.
 */

#include "tiny-asn1.h"
#include <stdio.h>

#test der_encoded_len_test
  asn1_tree asn1;
  list_init(&asn1);

  asn1.type = 0x01;
  asn1.length = 1;
  uint8_t data[] = {0x42};
  asn1.data = data;
  ck_assert_int_eq(3, get_der_encoded_length(&asn1));

  asn1.length = 127;
    ck_assert_int_eq(129, get_der_encoded_length(&asn1));

  asn1.length = 128;
    ck_assert_int_eq(131, get_der_encoded_length(&asn1));

  asn1.length = 255;
    ck_assert_int_eq(258, get_der_encoded_length(&asn1));

  asn1.length = 257;
    ck_assert_int_eq(261, get_der_encoded_length(&asn1));

#test fetch_tlv_length_one_byte_short_test
      uint8_t data[512];
      uint32_t offset;
      data[0] = 0x04;
      data[1] = 0x03;
      ck_assert_int_eq(5, fetch_tlv_length(data, 512, &offset));
      ck_assert_int_eq(2, offset);

#test fetch_tlv_length_one_byte_long_test
      uint8_t data[512];
      uint32_t offset;
      data[0] = 0x04;
      data[1] = 0x81;
      data[2] = 0xff;
      ck_assert_int_eq(258, fetch_tlv_length(data, 512, &offset));
      ck_assert_int_eq(3, offset);

#test fetch_tlv_length_two_bytes_test
      uint8_t data[512];
      uint32_t offset;
      data[0] = 0x04;
      data[1] = 0x82;
      data[2] = 0x01;
      data[3] = 0x00;
      ck_assert_int_eq(260, fetch_tlv_length(data, 512, &offset));
      ck_assert_int_eq(4, offset);

#test fetch_data_length_one_byte_short_test
      uint8_t data[512];
      data[0] = 0x04;
      data[1] = 0x03;
      ck_assert_int_eq(3, fetch_data_length(data, 512));

#test fetch_data_length_one_byte_long_test
      uint8_t data[512];
      data[0] = 0x04;
      data[1] = 0x81;
      data[2] = 0xff;
      ck_assert_int_eq(255, fetch_data_length(data, 512));

#test fetch_data_length_two_bytes_test
      uint8_t data[512];
      data[0] = 0x04;
      data[1] = 0x82;
      data[2] = 0x01;
      data[3] = 0x00;
      ck_assert_int_eq(256, fetch_data_length(data, 512));

#test der_object_count_one_object_test
  uint8_t der[] = {0x04, 0x01, 0x01};
  ck_assert_int_eq(1, der_object_count(der, sizeof(der)));

#test der_object_count_sequence_test
  uint8_t der[] = {0x30, 0x06, 0x04, 0x01, 0x01, 0x04, 0x01, 0x02};
  ck_assert_int_eq(3, der_object_count(der, sizeof(der)));

#test der_object_count_nested_sequence_test
    uint8_t der[] = {0x30, 0x0b, 0x04, 0x01, 0xff, 0x30, 0x06, 0x04, 0x01, 0x01, 0x04, 0x01, 0x02};
    ck_assert_int_eq(5, der_object_count(der, sizeof(der)));

#test der_object_count_nested_sequence_with_follower_test
    uint8_t der[] = {0x30, 0x08, 0x30, 0x03, 0x04, 0x01, 0x01, 0x04, 0x01, 0x02};
    ck_assert_int_eq(4, der_object_count(der, sizeof(der)));

#test der_decode_one_object_test
  uint8_t der[] = {0x04, 0x01, 0x01};
  asn1_tree asn1;
  asn1_tree child_objects[0];
  ck_assert_int_le(0, der_decode(der, sizeof(der), &asn1, child_objects, 0));
  ck_assert_int_eq(0x04, asn1.type);
  ck_assert_int_eq(1, asn1.length);
  ck_assert_ptr_eq(der+2, asn1.data);
  ck_assert_ptr_eq(NULL, asn1.child);
  ck_assert_ptr_eq(NULL, asn1.parent);
  ck_assert_ptr_eq(NULL, asn1.next);
  ck_assert_ptr_eq(NULL, asn1.prev);

#test der_decode_sequence_test
    uint8_t der[] = {0x30, 0x06, 0x04, 0x01, 0x01, 0x05, 0x01, 0x02};
    asn1_tree asn1;
    asn1_tree child_objects[2];
    //Test if the decoding works
    ck_assert_int_le(0, der_decode(der, sizeof(der), &asn1, child_objects, 2));
    //Test the linkage of the elements
    ck_assert_ptr_eq(NULL, asn1.parent);
    ck_assert_ptr_eq(NULL, asn1.next);
    ck_assert_ptr_eq(NULL, asn1.prev);
    ck_assert_ptr_ne(NULL, asn1.child);
    asn1_tree* child1 = asn1.child;
    ck_assert_ptr_eq(&asn1, child1->parent);
    ck_assert_ptr_eq(NULL, child1->prev);
    ck_assert_ptr_eq(NULL, child1->child);
    ck_assert_ptr_ne(NULL, child1->next);
    asn1_tree* child2 = child1->next;
    ck_assert_ptr_eq(&asn1, child2->parent);
    ck_assert_ptr_eq(child1, child2->prev);
    ck_assert_ptr_eq(NULL, child2->next);
    ck_assert_ptr_eq(NULL, child2->child);
    //Test the values of the elements
    ck_assert_int_eq(0x30, asn1.type);
    ck_assert_int_eq(6, asn1.length);
    ck_assert_ptr_eq(der+2, asn1.data);

    ck_assert_int_eq(0x04, child1->type);
    ck_assert_int_eq(1, child1->length);
    ck_assert_ptr_eq(der+4, child1->data);

    ck_assert_int_eq(0x05, child2->type);
    ck_assert_int_eq(1, child2->length);
    ck_assert_ptr_eq(der+7, child2->data);

#test der_decode_nested_sequence_test
    uint8_t der[] = {0x30, 0x0b, 0x04, 0x01, 0xff, 0x30, 0x06, 0x05, 0x01, 0x01, 0x06, 0x01, 0x02};
    asn1_tree asn1;
    asn1_tree child_objects[4];
    //Test if the decoding works
    ck_assert_int_le(0, der_decode(der, sizeof(der), &asn1, child_objects, 4));
    //Test the linkage of the elements
    ck_assert_ptr_eq(NULL, asn1.parent);
    ck_assert_ptr_eq(NULL, asn1.next);
    ck_assert_ptr_eq(NULL, asn1.prev);
    ck_assert_ptr_ne(NULL, asn1.child);

    asn1_tree* child1 = asn1.child;
    ck_assert_ptr_eq(&asn1, child1->parent);
    ck_assert_ptr_eq(NULL, child1->prev);
    ck_assert_ptr_eq(NULL, child1->child);
    ck_assert_ptr_ne(NULL, child1->next);

    asn1_tree* child_seq = child1->next;
    ck_assert_ptr_eq(&asn1, child_seq->parent);
    ck_assert_ptr_eq(child1, child_seq->prev);
    ck_assert_ptr_eq(NULL, child_seq->next);
    ck_assert_ptr_ne(NULL, child_seq->child);

    asn1_tree* seq_child1 = child_seq->child;
    ck_assert_ptr_eq(child_seq, seq_child1->parent);
    ck_assert_ptr_eq(NULL, seq_child1->prev);
    ck_assert_ptr_eq(NULL, seq_child1->child);
    ck_assert_ptr_ne(NULL, seq_child1->next);

    asn1_tree* seq_child2 = seq_child1->next;
    ck_assert_ptr_eq(child_seq, seq_child2->parent);
    ck_assert_ptr_eq(seq_child1, seq_child2->prev);
    ck_assert_ptr_eq(NULL, seq_child2->child);
    ck_assert_ptr_eq(NULL, seq_child2->next);

    //Test the values of the elements
    ck_assert_int_eq(0x30, asn1.type);
    ck_assert_int_eq(11, asn1.length);
    ck_assert_ptr_eq(der+2, asn1.data);

    ck_assert_int_eq(0x04, child1->type);
    ck_assert_int_eq(1, child1->length);
    ck_assert_ptr_eq(der+4, child1->data);

    ck_assert_int_eq(0x30, child_seq->type);
    ck_assert_int_eq(6, child_seq->length);
    ck_assert_ptr_eq(der+7, child_seq->data);

    ck_assert_int_eq(0x05, seq_child1->type);
    ck_assert_int_eq(1, seq_child1->length);
    ck_assert_ptr_eq(der+9, seq_child1->data);

    ck_assert_int_eq(0x06, seq_child2->type);
    ck_assert_int_eq(1, seq_child2->length);
    ck_assert_ptr_eq(der+12, seq_child2->data);

#test get_length_encoding_length_test
    ck_assert_int_eq(1, get_length_encoding_length (0));
    ck_assert_int_eq(1, get_length_encoding_length (1));
    ck_assert_int_eq(1, get_length_encoding_length (127));
    ck_assert_int_eq(2, get_length_encoding_length (128));
    ck_assert_int_eq(3, get_length_encoding_length (256));
    ck_assert_int_eq(3, get_length_encoding_length (65535));
    ck_assert_int_eq(4, get_length_encoding_length (65536));

#test get_der_encoded_length_recursive_test
  asn1_tree asn1;
  list_init(&asn1);

  //Test an empty element
  ck_assert_int_eq(2, get_der_encoded_length_recursive(&asn1));

  //Test a discrete element
  asn1.type = 0x04;
  asn1.length = 0x02;
  ck_assert_int_eq(4, get_der_encoded_length_recursive(&asn1));

  //Test a sequence with a single child
  asn1_tree child1;
  list_init(&child1);
  child1.type = 0x04;
  child1.length = 0x02;
  asn1.type = 0x30;
  asn1.child = &child1;
  ck_assert_int_eq(6, get_der_encoded_length_recursive(&asn1));

  //Test a sequence with a two children
  asn1_tree child2;
  list_init(&child2);
  child2.type = 0x04;
  child2.length = 0x03;
  child1.next = &child2;
  child2.prev = &child1;
  ck_assert_int_eq(11, get_der_encoded_length_recursive(&asn1));

  //Test a sequence with a two children and one grandchild
  asn1_tree grandchild;
  list_init(&grandchild);
  grandchild.type = 0x04;
  grandchild.length = 0xff;
  child2.type = 0x30;
  child2.child = &grandchild;
  ck_assert_int_eq(258, get_der_encoded_length_recursive(&grandchild));
  ck_assert_int_eq(262, get_der_encoded_length_recursive(&child2));
  ck_assert_int_eq(4, get_der_encoded_length_recursive(&child1));
  ck_assert_int_eq(270, get_der_encoded_length_recursive(&asn1));

#test get_data_length_recursive_test
    asn1_tree asn1;
    list_init(&asn1);

    //Test an empty element
    ck_assert_int_eq(0, get_data_length_recursive(&asn1));

    //Test a discrete element
    asn1.type = 0x04;
    asn1.length = 0x02;
    ck_assert_int_eq(2, get_data_length_recursive(&asn1));

    //Test a sequence with a single child
    asn1_tree child1;
    list_init(&child1);
    child1.type = 0x04;
    child1.length = 0x02;
    asn1.type = 0x30;
    asn1.child = &child1;
    ck_assert_int_eq(4, get_data_length_recursive(&asn1));

    //Test a sequence with a two children
    asn1_tree child2;
    list_init(&child2);
    child2.type = 0x04;
    child2.length = 0x03;
    child1.next = &child2;
    child2.prev = &child1;
    ck_assert_int_eq(9,  get_data_length_recursive(&asn1));

    //Test a sequence with a two children and one grandchild
    asn1_tree grandchild;
    list_init(&grandchild);
    grandchild.type = 0x04;
    grandchild.length = 0xff;
    child2.type = 0x30;
    child2.child = &grandchild;
    ck_assert_int_eq(255,  get_data_length_recursive(&grandchild));
    ck_assert_int_eq(258,  get_data_length_recursive(&child2));
    ck_assert_int_eq(266,  get_data_length_recursive(&asn1));

#test der_encode_length_test
  uint8_t encoded[3] = {0xff, 0xff, 0xff};
  //length = 1 -> encoded = {0x01}
  ck_assert_int_eq(0xff, encoded[2]); //remaining memory should not be touched

  //length = 128 -> encoded = {0x81, 0x80}
  ck_assert_int_eq(2, der_encode_length(128, encoded, 5));
  ck_assert_int_eq(0x81, encoded[0]);
  ck_assert_int_eq(0x80, encoded[1]);
  ck_assert_int_eq(0xff, encoded[2]); //remaining memory should not be touched

  //length = 256 -> encoded = {0x82, 0x01, 0x00}
  ck_assert_int_eq(3, der_encode_length(256, encoded, 5));
  ck_assert_int_eq(0x82, encoded[0]);
  ck_assert_int_eq(0x01, encoded[1]);
  ck_assert_int_eq(0x00, encoded[2]);

#test der_encode_test
    asn1_tree asn1;
    list_init(&asn1);
    uint8_t encoded[13];
    //Test an empty element
    ck_assert_int_eq(2, der_encode(&asn1, encoded, sizeof(encoded)));
    ck_assert_int_eq(0x00, encoded[0]);
    ck_assert_int_eq(0x00, encoded[1]);
    //ck_assert_int_eq(0, memcmp(encoded, (uint8_t[]){0x00, 0x01}, 2));

    //Test a discrete element
    asn1.type = 0x04;
    asn1.length = 0x02;
    uint8_t data[] = {0x10, 0x11};
    asn1.data = data;
    ck_assert_int_eq(4, der_encode(&asn1, encoded, sizeof(encoded)));
    ck_assert_int_eq(0x04, encoded[0]);
    ck_assert_int_eq(0x02, encoded[1]);
    ck_assert_int_eq(0x10, encoded[2]);
    ck_assert_int_eq(0x11, encoded[3]);

    //Test a sequence with a single child
    asn1_tree child1;
    list_init(&child1);
    child1.type = 0x04;
    child1.length = 0x02;
    child1.data = data;
    asn1.type = 0x30;
    asn1.child = &child1;
    ck_assert_int_eq(6, der_encode(&asn1, encoded, sizeof(encoded)));
    ck_assert_int_eq(0x30, encoded[0]);
    ck_assert_int_eq(0x04, encoded[1]);
    ck_assert_int_eq(0x04, encoded[2]);
    ck_assert_int_eq(0x02, encoded[3]);
    ck_assert_int_eq(0x10, encoded[4]);
    ck_assert_int_eq(0x11, encoded[5]);


    //Test a sequence with a two children
    asn1_tree child2;
    list_init(&child2);
    child2.type = 0x04;
    child2.length = 0x03;
    uint8_t data2[] = {0x20, 0x21, 0x22};
    child2.data = data2;
    child1.next = &child2;
    child2.prev = &child1;
    ck_assert_int_eq(11, der_encode(&asn1, encoded, sizeof(encoded)));
    ck_assert_int_eq(0x30, encoded[0]);
    ck_assert_int_eq(0x09, encoded[1]);
    ck_assert_int_eq(0x04, encoded[2]);
    ck_assert_int_eq(0x02, encoded[3]);
    ck_assert_int_eq(0x10, encoded[4]);
    ck_assert_int_eq(0x11, encoded[5]);
    ck_assert_int_eq(0x04, encoded[6]);
    ck_assert_int_eq(0x03, encoded[7]);
    ck_assert_int_eq(0x20, encoded[8]);
    ck_assert_int_eq(0x21, encoded[9]);
    ck_assert_int_eq(0x22, encoded[10]);

    //Test a sequence with a two children and one grandchild
    asn1_tree grandchild;
    list_init(&grandchild);
    grandchild.type = 0x04;
    grandchild.length = 0x03;
    grandchild.data = data2;
    child2.type = 0x30;
    child2.child = &grandchild;

    ck_assert_int_eq(13, der_encode(&asn1, encoded, sizeof(encoded)));
    ck_assert_int_eq(0x30, encoded[0]);
    ck_assert_int_eq(0x0b, encoded[1]);
    ck_assert_int_eq(0x04, encoded[2]);
    ck_assert_int_eq(0x02, encoded[3]);
    ck_assert_int_eq(0x10, encoded[4]);
    ck_assert_int_eq(0x11, encoded[5]);
    ck_assert_int_eq(0x30, encoded[6]);
    ck_assert_int_eq(0x05, encoded[7]);
    ck_assert_int_eq(0x04, encoded[8]);
    ck_assert_int_eq(0x03, encoded[9]);
    ck_assert_int_eq(0x20, encoded[10]);
    ck_assert_int_eq(0x21, encoded[11]);
    ck_assert_int_eq(0x22, encoded[12]);

    //An element with too much data should yield an error
    ck_assert_int_ge(0, der_encode(&asn1, encoded, 12));

#test der_decode_cms_test
/* Created with echo "1234567890"|openssl cms -EncryptedData_encrypt -aes128 -secretkey 39904F36D98779D00F9A2B8139D2957F -outform der|xxd --i

Parsed with openssl:
   0:d=0  hl=2 l=  80 cons: SEQUENCE
    2:d=1  hl=2 l=   9 prim:  OBJECT            :pkcs7-encryptedData
   13:d=1  hl=2 l=  67 cons:  cont [ 0 ]
   15:d=2  hl=2 l=  65 cons:   SEQUENCE
   17:d=3  hl=2 l=   1 prim:    INTEGER           :00
   20:d=3  hl=2 l=  60 cons:    SEQUENCE
   22:d=4  hl=2 l=   9 prim:     OBJECT            :pkcs7-data
   33:d=4  hl=2 l=  29 cons:     SEQUENCE
   35:d=5  hl=2 l=   9 prim:      OBJECT            :aes-128-cbc
   46:d=5  hl=2 l=  16 prim:      OCTET STRING      [HEX DUMP]:1795ED7DA1E2FBA6A0BF8C548C1A9766
   64:d=4  hl=2 l=  16 prim:     cont [ 0 ]
*/
  uint8_t cms_data[] = {
    0x30, 0x50, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07,
    0x06, 0xa0, 0x43, 0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x3c, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0x30, 0x1d, 0x06,
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02, 0x04, 0x10,
    0xd4, 0xf2, 0xd5, 0x7a, 0x90, 0xc0, 0x49, 0x2d, 0x77, 0xa8, 0x30, 0xd8,
    0x82, 0x8d, 0x02, 0x3e, 0x80, 0x10, 0xad, 0xad, 0x62, 0x8d, 0x35, 0xaf,
    0x9e, 0x0a, 0x9f, 0x93, 0xd0, 0xc7, 0xb0, 0xa4, 0x05, 0xa9
  };
  printf("-------------------\n");
  asn1_tree cms;
  asn1_tree cms_objects[10];
  ck_assert_int_le(0, der_decode(cms_data, sizeof(cms_data), &cms, cms_objects, 10));
  ck_assert_int_eq(0x30, cms.type);
  asn1_tree* d1 = cms.child;
  ck_assert_int_eq(0x06, d1->type);
  d1 = d1->next;
  ck_assert_int_eq(0xa0, d1->type);
  asn1_tree* d2 = d1->child;
  ck_assert_int_eq(0x30, d2->type);
  asn1_tree* d3 = d2->child;
  ck_assert_int_eq(0x02, d3->type);
  d3 = d3->next;
  ck_assert_int_eq(0x30, d3->type);
  asn1_tree* d4 = d3->child;
  ck_assert_int_eq(0x06, d4->type);
  d4 = d4->next;
  ck_assert_int_eq(0x30, d4->type);
  asn1_tree* d5 = d4->child;
  ck_assert_int_eq(0x06, d5->type);
  d5 = d5->next;
  ck_assert_int_eq(0x04, d5->type);
  d4 = d4->next;
  ck_assert_int_eq(0x80, d4->type);


#test add_child_test
  asn1_tree root;
  asn1_tree child1;
  asn1_tree child2;
  asn1_tree grandchild;

  list_init(&root);
  list_init(&child1);
  list_init(&child2);
  list_init(&grandchild);

  add_child(&root, &child1);
  ck_assert_ptr_eq(&child1, root.child);
  ck_assert_ptr_eq(NULL, child1.next);
  ck_assert_ptr_eq(NULL, child1.prev);
  ck_assert_ptr_eq(&root, child1.parent);

  add_child(&root, &child2);
  ck_assert_ptr_eq(&child1, root.child);
  ck_assert_ptr_eq(&child2, child1.next);
  ck_assert_ptr_eq(NULL, child1.prev);
  ck_assert_ptr_eq(&root, child1.parent);
  ck_assert_ptr_eq(NULL, child2.next);
  ck_assert_ptr_eq(&child1, child2.prev);
  ck_assert_ptr_eq(&root, child2.parent);

  add_child(&child1, &grandchild);
  ck_assert_ptr_eq(&child1, root.child);
  ck_assert_ptr_eq(&child2, child1.next);
  ck_assert_ptr_eq(NULL, child1.prev);
  ck_assert_ptr_eq(&root, child1.parent);
  ck_assert_ptr_eq(NULL, child2.next);
  ck_assert_ptr_eq(&child1, child2.prev);
  ck_assert_ptr_eq(&root, child2.parent);
  ck_assert_ptr_eq(NULL, child2.child);
  ck_assert_ptr_eq(&grandchild, child1.child);
  ck_assert_ptr_eq(NULL, grandchild.next);
  ck_assert_ptr_eq(NULL, grandchild.prev);
  ck_assert_ptr_eq(&child1, grandchild.parent);
    

#test encode_integer_test_0
  uint8_t encoded[1];
  uint32_t value = 0;
  ck_assert_int_eq(1, encode_integer(value, encoded, sizeof(encoded)));
  ck_assert_int_eq(0x00, encoded[0]);

#test encode_integer_test_1
  uint8_t encoded[1];
  uint32_t value = 1;
  ck_assert_int_eq(1, encode_integer(value, encoded, sizeof(encoded)));
  ck_assert_int_eq(0x01, encoded[0]);

#test encode_integer_test_128
  uint8_t encoded[2];
  uint32_t value = 128;
  ck_assert_int_eq(2, encode_integer(value, encoded, sizeof(encoded)));
  ck_assert_int_eq(0x00, encoded[0]);
  ck_assert_int_eq(0x80, encoded[1]);

#test encode_integer_test_128_not_enough_mem
  uint8_t encoded[1];
  uint32_t value = 128;
  ck_assert_int_ge(0, encode_integer(value, encoded, sizeof(encoded)));

#test encode_integer_test_256
  uint8_t encoded[2];
  uint32_t value = 256;
  ck_assert_int_eq(2, encode_integer(value, encoded, sizeof(encoded)));
  ck_assert_int_eq(0x01, encoded[0]);
  ck_assert_int_eq(0x00, encoded[1]);

#test encode_integer_test_256_remaining_mem_untouched
  uint8_t encoded[3];
  memset(encoded, 0x42, 3);
  uint32_t value = 256;
  ck_assert_int_eq(2, encode_integer(value, encoded, sizeof(encoded)));
  ck_assert_int_eq(0x01, encoded[0]);
  ck_assert_int_eq(0x00, encoded[1]);
  // Check if the additional byte not needed for encoding remained unaltered
  ck_assert_int_eq(0x42, encoded[2]);

#test encode_integer_test_49468
  uint8_t encoded[3];
  uint32_t value = 49468;
  ck_assert_int_eq(3, encode_integer(value, encoded, sizeof(encoded)));
  ck_assert_int_eq(0x00, encoded[0]);
  ck_assert_int_eq(0xc1, encoded[1]);
  ck_assert_int_eq(0x3c, encoded[2]);


#test encode_integer_test_0x41027a3f
  uint8_t encoded[4];
  uint32_t value = 0x41027a3f;
  ck_assert_int_eq(4, encode_integer(value, encoded, sizeof(encoded)));
  ck_assert_int_eq(0x41, encoded[0]);
  ck_assert_int_eq(0x02, encoded[1]);
  ck_assert_int_eq(0x7a, encoded[2]);
  ck_assert_int_eq(0x3f, encoded[3]);

#test encode_integer_test_0xf0f1f2f3
  uint8_t encoded[5];
  uint32_t value = 0xf0f1f2f3;
  ck_assert_int_eq(5, encode_integer(value, encoded, sizeof(encoded)));
  ck_assert_int_eq(0x00, encoded[0]);	    
  ck_assert_int_eq(0xf0, encoded[1]);
  ck_assert_int_eq(0xf1, encoded[2]);
  ck_assert_int_eq(0xf2, encoded[3]);
  ck_assert_int_eq(0xf3, encoded[4]);

#test decode_integer_test_0
  uint8_t encoded[] = {0x00};
  uint32_t value;
  ck_assert_int_le(0, decode_unsigned_integer(encoded, sizeof(encoded), &value));
  ck_assert_int_eq(0, value);

#test decode_integer_test_1
  uint8_t encoded[] = {0x01};
  uint32_t value;
  ck_assert_int_le(0, decode_unsigned_integer(encoded, sizeof(encoded), &value));
  ck_assert_int_eq(1, value);

#test decode_integer_test_128
  uint8_t encoded[] = {0x00, 0x80};
  uint32_t value;
  ck_assert_int_le(0, decode_unsigned_integer(encoded, sizeof(encoded), &value));
  ck_assert_int_eq(128, value);

#test decode_integer_test_256
  uint8_t encoded[] = {0x01, 0x00};
  uint32_t value;
  ck_assert_int_le(0, decode_unsigned_integer(encoded, sizeof(encoded), &value));
  ck_assert_int_eq(256, value);

#test decode_integer_test_49468
  uint8_t encoded[] = {0x00, 0xc1, 0x3c};
  uint32_t value;
  ck_assert_int_le(0, decode_unsigned_integer(encoded, sizeof(encoded), &value));
  ck_assert_int_eq(49468, value);


#test decode_integer_test_uint32_t_max_value
  uint8_t encoded[] = {0x00, 0xff, 0xff, 0xff, 0xff};
  uint32_t value;
  ck_assert_int_le(0, decode_unsigned_integer(encoded, sizeof(encoded), &value));
  ck_assert_int_eq(4294967295, value);

#test decode_integer_test_error_too_many_bytes
  uint8_t encoded[] = {0x01, 0xff, 0xff, 0xff, 0xff};
  uint32_t value;
  ck_assert_int_gt(0, decode_unsigned_integer(encoded, sizeof(encoded), &value));



/**
 *      @file    2048_DH_PARAMS.h
 *      @version $Format:%h%d$
 *
 *      Summary.
 */
/******************************************************************************/
/*
    In-Memory version of the PEM file 2048_DH_PARAMS.pem

        PKCS#3 DH Parameters: (2048 bit)
        prime:
            00:b9:bc:28:91:c7:08:c9:12:9b:7b:25:61:a9:4c:
            a3:a1:45:10:76:ed:80:db:a9:bf:c5:7e:86:ff:8b:
            f3:89:ff:79:ef:9d:d1:76:9b:ce:29:2f:c0:e4:a2:
            f5:c2:c5:25:99:35:0c:a8:8b:9c:ec:e2:11:7b:17:
            cd:ad:4f:fc:88:17:17:d8:65:12:ef:08:5a:62:a6:
            6f:06:b3:97:88:61:6d:32:55:97:ff:b6:80:9f:55:
            23:10:7d:2f:8a:2b:f9:9a:35:1f:cd:ab:98:2c:09:
            13:a1:1f:31:25:b8:09:a2:66:99:ff:5c:3b:15:58:
            85:d3:75:eb:ba:0c:c4:43:ef:58:f1:92:7c:c4:d7:
            37:00:8c:02:97:3f:49:c1:bc:9f:31:34:e0:d4:7a:
            3b:96:10:dc:4c:65:f6:7b:3a:15:f5:c0:8a:31:bc:
            c6:6a:f4:61:02:1f:5f:a2:70:8d:aa:a7:0c:e4:f1:
            aa:38:be:d2:87:d8:e4:a6:ff:a7:26:d6:28:36:87:
            01:13:7e:0c:52:2a:8f:9f:3b:3b:9e:66:28:c3:80:
            d1:0e:4e:fb:f7:be:2e:6b:11:15:5d:85:a3:36:11:
            46:dc:7c:41:84:6c:fc:75:88:39:00:ea:b6:c8:5e:
            fe:78:a9:92:f3:25:4a:08:e3:9c:93:fa:a9:3f:5f:
            7d:47
        generator: 5 (0x5)
   -----BEGIN DH PARAMETERS-----
   MIIBCAKCAQEAubwokccIyRKbeyVhqUyjoUUQdu2A26m/xX6G/4vzif95753RdpvO
   KS/A5KL1wsUlmTUMqIuc7OIRexfNrU/8iBcX2GUS7whaYqZvBrOXiGFtMlWX/7aA
   n1UjEH0viiv5mjUfzauYLAkToR8xJbgJomaZ/1w7FViF03XrugzEQ+9Y8ZJ8xNc3
   AIwClz9JwbyfMTTg1Ho7lhDcTGX2ezoV9cCKMbzGavRhAh9fonCNqqcM5PGqOL7S
   h9jkpv+nJtYoNocBE34MUiqPnzs7nmYow4DRDk77974uaxEVXYWjNhFG3HxBhGz8
   dYg5AOq2yF7+eKmS8yVKCOOck/qpP199RwIBBQ==
   -----END DH PARAMETERS-----
 */
#define DHPARAM2048_SIZE    268
static const unsigned char DHPARAM2048[DHPARAM2048_SIZE] =
    "\x30\x82\x01\x08\x02\x82\x01\x01\x00\xb9\xbc\x28\x91\xc7\x08\xc9"
    "\x12\x9b\x7b\x25\x61\xa9\x4c\xa3\xa1\x45\x10\x76\xed\x80\xdb\xa9"
    "\xbf\xc5\x7e\x86\xff\x8b\xf3\x89\xff\x79\xef\x9d\xd1\x76\x9b\xce"
    "\x29\x2f\xc0\xe4\xa2\xf5\xc2\xc5\x25\x99\x35\x0c\xa8\x8b\x9c\xec"
    "\xe2\x11\x7b\x17\xcd\xad\x4f\xfc\x88\x17\x17\xd8\x65\x12\xef\x08"
    "\x5a\x62\xa6\x6f\x06\xb3\x97\x88\x61\x6d\x32\x55\x97\xff\xb6\x80"
    "\x9f\x55\x23\x10\x7d\x2f\x8a\x2b\xf9\x9a\x35\x1f\xcd\xab\x98\x2c"
    "\x09\x13\xa1\x1f\x31\x25\xb8\x09\xa2\x66\x99\xff\x5c\x3b\x15\x58"
    "\x85\xd3\x75\xeb\xba\x0c\xc4\x43\xef\x58\xf1\x92\x7c\xc4\xd7\x37"
    "\x00\x8c\x02\x97\x3f\x49\xc1\xbc\x9f\x31\x34\xe0\xd4\x7a\x3b\x96"
    "\x10\xdc\x4c\x65\xf6\x7b\x3a\x15\xf5\xc0\x8a\x31\xbc\xc6\x6a\xf4"
    "\x61\x02\x1f\x5f\xa2\x70\x8d\xaa\xa7\x0c\xe4\xf1\xaa\x38\xbe\xd2"
    "\x87\xd8\xe4\xa6\xff\xa7\x26\xd6\x28\x36\x87\x01\x13\x7e\x0c\x52"
    "\x2a\x8f\x9f\x3b\x3b\x9e\x66\x28\xc3\x80\xd1\x0e\x4e\xfb\xf7\xbe"
    "\x2e\x6b\x11\x15\x5d\x85\xa3\x36\x11\x46\xdc\x7c\x41\x84\x6c\xfc"
    "\x75\x88\x39\x00\xea\xb6\xc8\x5e\xfe\x78\xa9\x92\xf3\x25\x4a\x08"
    "\xe3\x9c\x93\xfa\xa9\x3f\x5f\x7d\x47\x02\x01\x05";


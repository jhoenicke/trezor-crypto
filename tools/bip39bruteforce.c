#include <stdio.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include "bip39.h"
#include "bip32.h"
#include "ecdsa.h"
#include "curves.h"

char iter[256];
uint8_t seed[512 / 8];
uint8_t addr[21], pubkeyhash[20];
int count = 0, found = 0;
HDNode node;
HDNode childnode;
clock_t start;

int hexdecode(const char *address, uint8_t *decoded_addr) {
	const char* hex = "0123456789abcdef";
	if (address[0] == '0' && tolower(address[1]) == 'x') {
		address += 2;
	}
	if (strlen(address) != 40) {
		return 0;
	}
	for (int i = 0; i < 20; i++) {
		char *high = strchr(hex, tolower(address[2*i]));
		char *low  = strchr(hex, tolower(address[2*i+1]));
		if (high == NULL || low == NULL) {
			return 0;
		}
		decoded_addr[i] = ((high - hex) << 4) | (low - hex);
	}
	return 1;
}

// around 280 tries per second

// testing data:
//
// mnemonic:   "all all all all all all all all all all all all"
// address:    "0x574BbB36871bA6b78E27f4B4dCFb76eA0091880B"
// passphrase: ""
// path:       44'/60'/0'/0/2
//
// mnemonic:   "all all all all all all all all all all all all"
// address:    "0x74eC221471b48c9Afef4115Ea8954D37d10238b7"
// passphrase: "testing"
// path:       44'/61'/0'/0/0

int main(int argc, char **argv)
{
	uint32_t prime = 0x80000000;
	uint32_t paths[][5] = {
		{ 44 | prime, 60 |prime, 0 | prime, 0, 0 },
		{ 44 | prime, 60 |prime, 0 | prime, 0, 1 },
		{ 44 | prime, 60 |prime, 0 | prime, 0, 2 },
		{ 44 | prime, 60 |prime, 0 | prime, 0, 3 },
		{ 44 | prime, 60 |prime, 0 | prime, 0, 4 },
		{ 44 | prime, 61 |prime, 0 | prime, 0, 0 },
		{ 44 | prime, 61 |prime, 0 | prime, 0, 1 },
		{ 44 | prime, 61 |prime, 0 | prime, 0, 2 },
		{ 44 | prime, 61 |prime, 0 | prime, 0, 3 },
		{ 44 | prime, 61 |prime, 0 | prime, 0, 4 },
	};

	if (argc != 2 && argc != 3) {
		fprintf(stderr, "Usage: bip39bruteforce address [mnemonic]\n");
		return 1;
	}
	const char *address = argv[1];
	const char *mnemonic, *item;
	if (argc == 3) {
		mnemonic = argv[2];
		item = "passphrase";
	} else {
		mnemonic = NULL;
		item = "mnemonic";
	}
	if (mnemonic && !mnemonic_check(mnemonic)) {
		fprintf(stderr, "\"%s\" is not a valid mnemonic\n", mnemonic);
		return 2;
	}
	if (!hexdecode(address, addr)) {
		fprintf(stderr, "\"%s\" is not a valid address\n", address);
		return 3;
	}
	printf("Reading %ss from stdin ...\n", item);
	start = clock();
	while (!found) {
		if (fgets(iter, 256, stdin) == NULL) break;
		int len = strlen(iter);
		if (len <= 0) {
			continue;
		}
		count++;
		iter[len - 1] = 0;
		if (mnemonic) {
			mnemonic_to_seed(mnemonic, iter, seed, NULL);
		} else {
			mnemonic_to_seed(iter, "", seed, NULL);
		}
		hdnode_from_seed(seed, 512 / 8, SECP256K1_NAME, &node);
		for (size_t j = 0; j < sizeof(paths)/sizeof(paths[0]); j++) {
			childnode = node;
			for (int k = 0; k < 5; k++) {
				hdnode_private_ckd(&childnode, paths[j][k]);
			}
			hdnode_get_ethereum_pubkeyhash(&childnode, pubkeyhash);

			if (memcmp(addr, pubkeyhash, 20) == 0) {
				found = 1;
				break;
			}
		}
	}
	float dur = (float)(clock() - start) / CLOCKS_PER_SEC;
	printf("Tried %d %ss in %f seconds = %f tries/second\n", count, item, dur, (float)count/dur);
	if (found) {
		printf("Correct %s found! :-)\n\"%s\"\n", item, iter);
		return 0;
	}
	printf("Correct %s not found. :-(\n", item);
	return 4;
}

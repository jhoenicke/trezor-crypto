#include <stdio.h>
#include <time.h>
#include <string.h>
#include "bip39.h"
#include "bip32.h"
#include "ecdsa.h"
#include "curves.h"
#include "base58.h"

char iter[256];
uint8_t seed[512 / 8];
uint8_t addr[21], pubkeyhash[20];
char addrstr[80];
int count = 0, found = 0;
HDNode node, node2;
clock_t start;

// around 280 tries per second

// testing data:
//
// mnemonic:   "all all all all all all all all all all all all"
// address:    "1JAd7XCBzGudGpJQSDSfpmJhiygtLQWaGL"
// passphrase: ""
//
// mnemonic:   "all all all all all all all all all all all all"
// address:    "1N3uJ5AU3FTYQ1ZQgTMtYmgSvMBmQiGVBS"
// passphrase: "testing"

int main(int argc, char **argv)
{
	if (argc != 2 && argc != 3) {
		fprintf(stderr, "Usage: bip39bruteforce password\n");
		return 1;
	}
	const char *mnemonic, *item;
	mnemonic = NULL;
	item = "mnemonic";
	const char *password = argv[1];
	if (mnemonic && !mnemonic_check(mnemonic)) {
		fprintf(stderr, "\"%s\" is not a valid mnemonic\n", mnemonic);
		return 2;
	}
	printf("Reading %ss from stdin ...\n", item);
	start = clock();
	for (;;) {
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
			if (!mnemonic_check(iter)) {
				continue;
			}
			mnemonic_to_seed(iter, password, seed, NULL);
		}
		hdnode_from_seed(seed, 512 / 8, SECP256K1_NAME, &node);
		hdnode_private_ckd_prime(&node, 44);
		hdnode_private_ckd_prime(&node, 0);
		hdnode_private_ckd_prime(&node, 0);
		hdnode_private_ckd(&node, 0);
		for (int idx = 0; idx < 3; idx++) {
			node2 = node;
			hdnode_private_ckd(&node2, idx);
			hdnode_fill_public_key(&node2);
			ecdsa_get_pubkeyhash(node2.public_key, addr+1);
			addr[0] = 0;
			base58_encode_check(addr, 21, addrstr, sizeof(addrstr));
			printf("%d: %s: %s\n", idx, addrstr, iter);
		}
	}
	float dur = (float)(clock() - start) / CLOCKS_PER_SEC;
	printf("Tried %d %ss in %f seconds = %f tries/second\n", count, item, dur, (float)count/dur);
	return 0;
}

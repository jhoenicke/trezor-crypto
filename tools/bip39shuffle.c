#include <stdio.h>
#include <time.h>
#include <string.h>
#include "bip39.h"
#include "bip32.h"
#include "ecdsa.h"
#include "curves.h"
#include "sha2.h"

extern const char * const wordlist[];
uint8_t seed[512 / 8];
uint8_t addr[21], pubkeyhash[20];
int count = 0, found = 0;
HDNode node;
clock_t start;

const char* mnemonic_words[24];
int mnemonic_idxs[24];


void shuffle_int(int* array, int perm, int len) {
	for (int i = 0; i < len; i++) {
		int pos = perm % (len - i);
		perm = perm / (len - i);
		int t = array[i + pos];
		array[i + pos] = array[i];
		array[i] = t;
	}
}

void shuffle_ptr(const char** array, int perm, int len) {
	for (int i = 0; i < len; i++) {
		int pos = perm % (len - i);
		perm = perm / (len - i);
		const char *t = array[i + pos];
		array[i + pos] = array[i];
		array[i] = t;
	}
}

int check_shuffle(int *idxs)
{
	uint32_t bits = 0;
	uint8_t raw[33];
	int nbits = 0;
	for (int i = 0; i < 16; i++) {
		if (nbits < 8) {
			bits <<= 11;
			bits |= *idxs++;
			nbits += 11;
		}
		raw[i] = bits >> (nbits - 8);
		nbits -= 8;
		//		printf("%02x", raw[i]);
	}
	//	printf("%01x\n", bits & 0xF);
	sha256_Raw(raw, 16, raw);
	return (raw[0] & 0xF0) >> 4 == (bits & 0xF);
}

int mnemonic_parse(const char *mnemonic, const char **words, int* idxs)
{
	if (!mnemonic) {
		return 0;
	}

	uint32_t i, n;

	i = 0; n = 0;
	while (mnemonic[i]) {
		if (mnemonic[i] == ' ') {
			n++;
		}
		i++;
	}
	n++;
	// check number of words
	if (n != 12 && n != 18 && n != 24) {
		return 0;
	}

	char current_word[10];
	uint32_t j, k, bi;
	uint8_t bits[32 + 1];
	memset(bits, 0, sizeof(bits));
	i = 0; bi = 0;
	while (mnemonic[i]) {
		j = 0;
		while (mnemonic[i] != ' ' && mnemonic[i] != 0) {
			if (j >= sizeof(current_word) - 1) {
				return 0;
			}
			current_word[j] = mnemonic[i];
			i++; j++;
		}
		current_word[j] = 0;
		if (mnemonic[i] != 0) i++;
		k = 0;
		for (;;) {
			if (!wordlist[k]) { // word not found
				return 0;
			}
			if (strcmp(current_word, wordlist[k]) == 0) { // word found on index k
				words[bi] = wordlist[k];
				idxs[bi] = k;
				bi++;
				break;
			}
			k++;
		}
	}
	if (bi != n) {
		return 0;
	}
	return n;
}


// around 280 tries per second

// testing data:
//
// shuffled:   "give aunt summer fatigue champion matrix pumpkin baby guitar novel recipe hard"
// mnemonic:   "baby pumpkin champion fatigue summer matrix aunt give guitar novel recipe hard"
// address:    "17fqr3QVPugw8JExgNDKVqnUYUH8KUSxsh" (44'/0'/0'/0/4)
// passphrase: ""
//

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "Usage: bip39bruteforce address mnemonic\n");
		return 1;
	}
	const char *address = argv[1];
	const char *mnemonic, *item;
	char joined[24*11];
	item = "permutation";
	mnemonic = argv[2];
	if (mnemonic_parse(mnemonic, mnemonic_words, mnemonic_idxs) != 12) {
		fprintf(stderr, "\"%s\" is not a valid mnemonic\n", mnemonic);
		return 2;
	}
	if (!ecdsa_address_decode(address, 0, addr)) {
		fprintf(stderr, "\"%s\" is not a valid address\n", address);
		return 3;
	}
	start = clock();
	for (int perm = 0; !found && perm < 479001600; perm++) {
		int shuffled[12];
		if ((perm % 10000) == 0) {
			printf(".. %8d of 479001600 permutations\n", perm);
		}
		memcpy (shuffled, mnemonic_idxs, sizeof(shuffled));
		shuffle_int(shuffled, perm, 12);
		if (!check_shuffle(shuffled))
			continue;
		const char *shuffledwords[12];
		memcpy (shuffledwords, mnemonic_words, sizeof(shuffledwords));
		shuffle_ptr(shuffledwords, perm, 12);
		char *p = joined;
		for (int i = 0; i < 12; i++) {
			strcpy(p, shuffledwords[i]);
			p += strlen(p);
			*p++ = ' ';
		}
		*(p-1) = 0;
		count++;
		mnemonic_to_seed(joined, "", seed, NULL);
		hdnode_from_seed(seed, 512 / 8, SECP256K1_NAME, &node);
		hdnode_private_ckd_prime(&node, 44);
		hdnode_private_ckd_prime(&node, 0);
		hdnode_private_ckd_prime(&node, 0);
		hdnode_private_ckd(&node, 0);
		for (int j = 0; j < 5; j++) {
			HDNode child = node;
			hdnode_private_ckd(&child, j);
			hdnode_fill_public_key(&child);
			ecdsa_get_pubkeyhash(child.public_key, pubkeyhash);
			if (memcmp(addr + 1, pubkeyhash, 20) == 0) {
				found = 1;
				break;
			}
		}
	}
	float dur = (float)(clock() - start) / CLOCKS_PER_SEC;
	printf("Tried %d %ss in %f seconds = %f tries/second\n", count, item, dur, (float)count/dur);
	if (found) {
		printf("Correct %s found! :-)\n\"%s\"\n", item, joined);
		return 0;
	}
	printf("Correct %s not found. :-(\n", item);
	return 4;
}

#include <stdio.h>
#include <string.h>
#include "bip39.h"

static const char* words[24];
static char mnem[1024];

static const char * const * wordlist;

int main(int argc, char ** argv) {
	if (argc != 13 && argc != 19 && argc != 25) {
		fprintf(stderr, "Usage: mnemonicgen mnemonic\n");
	}

	int numwords = argc - 1;
	for (int i = 0; i < numwords; i++) {
		words[i] = argv[1+i];
	}
	wordlist = mnemonic_wordlist();

	for (int i = 0; i < numwords; i++) {
		for (int j = 0; j < 2048; j++) {
			char *p = mnem;
			for (int k = 0;  k < numwords; k++) {
				if (k > 0) {
					*p++ = ' ';
				}
				if (k != i) {
					strcpy(p, words[k]);
				} else {
					strcpy(p, wordlist[j]);
				}
				p += strlen(p);
			}
			*p++ = 0;
			if (mnemonic_check(mnem)) {
				printf("%s\n", mnem);
			}
		}
	}
}


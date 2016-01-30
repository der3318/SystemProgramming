#include "file_merger.h"
#include <stdio.h>

#define MAX_FILENAME_LEN 10000

int main(int argc, char** argv) {
	if(argc < 4) {
		fprintf(stderr, "Filenames lost\n");
	}
	merge(argv[1], argv[2], argv[3]);
	return 0;
}

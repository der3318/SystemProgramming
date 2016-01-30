#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {

	if(argc < 3) {
		fprintf(stderr, "Parameters Lost\n");
		return 0;
	}

	FILE *fin = fopen(argv[1], "r"), *fout = fopen(argv[2], "w");
	int tmp, res = 0;

	if(fin == NULL) {
		fprintf(stderr, "Fail to Access Input File\n");
		return 0;
	}

	while( ( tmp = getc(fin) ) != EOF ) {
		if(tmp == 'a' || tmp == 'e' || tmp == 'i' || tmp == 'o' || tmp == 'u')	res++;
		if(tmp == 'A' || tmp == 'E' || tmp == 'I' || tmp == 'O' || tmp == 'U')	res++;
	}

	fprintf(fout, "%d", res);

	fclose(fin);
	fclose(fout);

	return 0;

}

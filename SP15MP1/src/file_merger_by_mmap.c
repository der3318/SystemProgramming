#include "file_merger_by_mmap.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>

#define MAX_FORMAT_LEN 100

void hello_world() {
	printf("Hello World!\n");
}

int isMatched(int num1, int num2, char **data1_line, char **data2_line, int lines1, int lines2) {
	if(num1 == 0 && num2 == 0)	return 1;
	if(num1 == 0 || num2 == 0)	return 0;
	if(num1 == lines1 + 1 && num2 == lines2 + 1)	return 1;
	if(num1 == lines1 + 1 || num2 == lines2 + 1)	return 0;
	char *now1 = data1_line[num1], *now2 = data2_line[num2];
	while(now1 != data1_line[num1 + 1] && now2 != data2_line[num2 + 1])	if(*now1++ != *now2++)	return 0;
	if(now1 == data1_line[num1 + 1] && now2 == data2_line[num2 + 1])	return 1;
	return 0;
}

int isSameLine(int num1, int num2, char **data1_line, char **data2_line, int lines1, int lines2) {
	int flag = isMatched(num1, num2, data1_line, data2_line, lines1, lines2);
	if(flag == 0)	return 0;
	flag += isMatched(num1 - 1, num2 - 1, data1_line, data2_line, lines1, lines2);
	flag += isMatched(num1 + 1, num2 + 1, data1_line, data2_line, lines1, lines2);
	if(flag > 1)	return 1;
	return 0;
}

void merge(char *filename1, char *filename2, char *outputfile) {
	
	// get the references to the files
	umask(0);
	int fin1 = open(filename1, O_RDONLY);	
	int fin2 = open(filename2, O_RDONLY);
	int fout = open(outputfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if(fin1 < 0) {
		fprintf(stderr, "Fail to open %s\n", filename1);
		return;
	}
	if(fin2 < 0) {
		fprintf(stderr, "Fail to open %s\n", filename2);
		return;
	}
	if(fout < 0) {
		fprintf(stderr, "Fail to open %s\n", outputfile);
		return;
	}

	// stat the files
	struct stat stat_buf1;
	struct stat stat_buf2;
	if( fstat(fin1, &stat_buf1) ) {
		fprintf(stderr, "Fail to stat %s\n", filename1);
		return;
	}
	if( fstat(fin2, &stat_buf2) ) {
		fprintf(stderr, "Fail to stat %s\n", filename2);
		return;
	}

	// mmap the files
	char *data1_start = (char*)mmap(NULL, stat_buf1.st_size, PROT_READ, MAP_SHARED, fin1, 0);
	char *data2_start = (char*)mmap(NULL, stat_buf2.st_size, PROT_READ, MAP_SHARED, fin2, 0);
	if(data1_start == MAP_FAILED) {
		fprintf(stderr, "Fail to map the %s\n", filename1);
		return;
	}
	if(data2_start == MAP_FAILED) {
		fprintf(stderr, "Fail to map the %s\n", filename2);
		return;
	}
	char *data1_now = data1_start;
	char *data2_now = data2_start;
	char *data1_end = data1_start + stat_buf1.st_size;
	char *data2_end = data2_start + stat_buf2.st_size;

	// count the lines
	int lines1 = 0, lines2 = 0;
	while(data1_now != data1_end) if(*data1_now++ == '\n')	lines1++;
	while(data2_now != data2_end) if(*data2_now++ == '\n')	lines2++;
	
	// record the address of every end lines
	data1_now = data1_start;
	data2_now = data2_start;
	char **data1_line = (char**)malloc( (lines1 + 2) * sizeof(*data1_line) );
	char **data2_line = (char**)malloc( (lines2 + 2) * sizeof(*data2_line) );
	data1_line[0] = NULL;
	data2_line[0] = NULL;
	data1_line[1] = data1_start;
	data2_line[1] = data2_start;
	int line_count = 1;
	while(data1_now != data1_end) if(*data1_now++ == '\n')	data1_line[++line_count] = data1_now;
	line_count = 1;
	while(data2_now != data2_end) if(*data2_now++ == '\n')	data2_line[++line_count] = data2_now;

	// allocate memory for DP spaces (lines1 * lines2)
	int **LCSlen;
	LCSlen = (int**)malloc( (lines1 + 1) * sizeof(*LCSlen) );
	for(int i = 0 ; i <= lines1 ; i++) LCSlen[i] = (int*)malloc( (lines2 + 1) * sizeof(**LCSlen) );

	// finish the LCSlen table
	for(int i = 0 ; i <= lines1 ; i++)
		for(int j = 0 ; j <= lines2 ; j++) {
			LCSlen[i][j] = 0;
			if(i == 0 || j == 0)	continue;
			if( isSameLine(i, j, data1_line, data2_line, lines1, lines2) )	LCSlen[i][j] = 1 + LCSlen[i - 1][j - 1];
			if(LCSlen[i - 1][j] > LCSlen[i][j])	LCSlen[i][j] = LCSlen[i - 1][j];
			if(LCSlen[i][j - 1] > LCSlen[i][j])	LCSlen[i][j] = LCSlen[i][j - 1];
		}
	
	// print LCSlen table
	printf("\nLCS Table:\n");
	for(int i = 0 ; i <= lines1 ; i++) {
		for(int j = 0 ; j <= lines2 ; j++)
			printf("%d ", LCSlen[i][j]);
		printf("\n");
	}

	// tranverse the table to get the path
	int *path_line = (int*)malloc( (lines1 + lines2 + 1) * sizeof(int) );
	char *path_dir = (char*)malloc( (lines1 + lines2 + 1) * sizeof(char) );
	int line1_now = lines1, line2_now = lines2, step = 0;
	while(1) {
		if(line1_now == 0 && line2_now == 0) {
			path_dir[step] = 's';
			break;
		}
		else if(line1_now == 0) {
			path_line[step] = line2_now--;
			path_dir[step] = '2';
		}
		else if(line2_now == 0) {
			path_line[step] = line1_now--;
			path_dir[step] = '1';
		}
		else if( isSameLine(line1_now, line2_now, data1_line, data2_line, lines1, lines2) ) {
			path_line[step] = line1_now--;
			path_dir[step] = 's';
			line2_now--;
		}
		else if( LCSlen[line1_now - 1][line2_now] > LCSlen[line1_now][line2_now - 1]) {
			path_line[step] = line1_now--;
			path_dir[step] = '1';
		}
		else {
			path_line[step] = line2_now--;
			path_dir[step] = '2';
		}
		step++;
	}

	// print merged file
	printf("\nMerged file:\n");
	char format0[MAX_FORMAT_LEN], format1[MAX_FORMAT_LEN], format2[MAX_FORMAT_LEN], format2s[MAX_FORMAT_LEN], format3[MAX_FORMAT_LEN];
	sprintf(format0, "<<<<<<<<<<\n");
	sprintf(format1, ">>>>>>>>>> %s\n", basename(filename1) );
	sprintf(format2, "========== %s\n<<<<<<<<<<\n", basename(filename2) );
	sprintf(format2s, "========== %s\n", basename(filename2) );
	sprintf(format3, ">>>>>>>>>> %s\n========== %s\n", basename(filename1), basename(filename2) );
	for(int i = step - 1 ; i >= 0 ; i--) {
		if(path_dir[i] == 's') {
			if(path_dir[i + 1] == '1') {
				write(fout, format2, strlen(format2) );
				fputs(format2, stdout);
			}
			if(path_dir[i + 1] == '2') {
				write(fout, format0, strlen(format0) );
				fputs(format0, stdout);
			}
			write(fout, data1_line[ path_line[i] ], (int)(data1_line[path_line[i] + 1] - data1_line[ path_line[i] ]) );
			char *outc = data1_line[ path_line[i] ];
			while(outc != data1_line[path_line[i] + 1])	putc(*outc++, stdout);
		}
		else if(path_dir[i] == '1') {
			if(path_dir[i + 1] == 's') {
				write(fout, format1, strlen(format1) );
				fputs(format1, stdout);
			}
			write(fout, data1_line[ path_line[i] ], (int)(data1_line[path_line[i] + 1] - data1_line[ path_line[i] ]) );
			char *outc = data1_line[ path_line[i] ];
			while(outc != data1_line[path_line[i] + 1])	putc(*outc++, stdout);
		}
		else if(path_dir[i] == '2') {
			if(path_dir[i + 1] == 's') {
				write(fout, format3, strlen(format3) );
				fputs(format3, stdout);
			}
			if(path_dir[i + 1] == '1') {
				write(fout, format2s, strlen(format2s) );
				fputs(format2s, stdout);
			}
			write(fout, data2_line[ path_line[i] ], (int)(data2_line[path_line[i] + 1] - data2_line[ path_line[i] ]) );
			char *outc = data2_line[ path_line[i] ];
			while(outc != data2_line[path_line[i] + 1])	putc(*outc++, stdout);
		}
	}
	if( path_dir[0] == '1') {
		write(fout, format2, strlen(format2) );
		fputs(format2, stdout);
	}
	if( path_dir[0] == '2') {
		write(fout, format0, strlen(format0) );
		fputs(format0, stdout);
	}
	
	// unmap the file
	munmap(data1_start, stat_buf1.st_size);
	munmap(data2_start, stat_buf2.st_size);
	if( close(fin1) )
	{
		printf("Fail to close %s\n", filename1);
		return;
	}
	if( close(fin2) )
	{
		printf("Fail to close %s\n", filename2);
		return;
	}

	printf("\nTask Completed\n");

	return;
}

#include "file_merger.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>

#define MAX_FORMAT_LEN 100
#define MAX_STR_LEN 100000001

off_t *data1_line, *data2_line;
int lines1 = 0, lines2 = 0;
int fin1 = -1, fin2 = -1;
int **match_table;
char *tmp1, *tmp2;

void hello_world() {
	printf("Hello World!\n");
}

int isMatched(int num1, int num2) {
	if(num1 == 0 && num2 == 0)	return 1;
	if(num1 == 0 || num2 == 0)	return 0;
	if(num1 == lines1 + 1 && num2 == lines2 + 1)	return 1;
	if(num1 == lines1 + 1 || num2 == lines2 + 1)	return 0;
	int len1 = data1_line[num1 + 1] - data1_line[num1], len2 = data2_line[num2 + 1] - data2_line[num2];
	if(len1 != len2)	return 0;
	lseek(fin1, data1_line[num1], SEEK_SET);
	lseek(fin2, data2_line[num2], SEEK_SET);
	read(fin1, tmp1, len1);
	read(fin2, tmp2, len2);
	if( strcmp(tmp1, tmp2) == 0 )	return 1;
	return 0;
}

int isSameLine(int num1, int num2) {
	if(match_table[num1][num2] == -1)	match_table[num1][num2] = isMatched(num1, num2);
	int flag = match_table[num1][num2];
	if(flag == 0)	return 0;
	if(match_table[num1 - 1][num2 - 1] == -1)	match_table[num1 - 1][num2 - 1] = isMatched(num1 - 1, num2 - 1);
	if(match_table[num1 + 1][num2 + 1] == -1)	match_table[num1 + 1][num2 + 1] = isMatched(num1 + 1, num2 + 1);
	flag += match_table[num1 - 1][num2 - 1];
	flag += match_table[num1 + 1][num2 + 1];
	if(flag > 1)	return 1;
	return 0;
}

void merge(char *filename1, char *filename2, char *outputfile) {
	
	// get the descriptors of the files
	umask(0);
	fin1 = open(filename1, O_RDONLY);	
	fin2 = open(filename2, O_RDONLY);
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
	
	// count the lines
	char *tmp = (char *)malloc( sizeof(char) );
	lines1 = 0;
	lines2 = 0;
	while( read(fin1, tmp, 1) ) if(*tmp == '\n')	lines1++;
	while( read(fin2, tmp, 1) ) if(*tmp == '\n')	lines2++;
	
	// record the offsets of every lines
	data1_line = (off_t *)malloc( (lines1 + 2) * sizeof(data1_line) );
	data2_line = (off_t *)malloc( (lines2 + 2) * sizeof(data2_line) );
	data1_line[0] = -1;
	data2_line[0] = -1;
	data1_line[lines1 + 1] = lseek(fin1, 0, SEEK_END);
	data2_line[lines2 + 1] = lseek(fin2, 0, SEEK_END);
	data1_line[1] = lseek(fin1, 0, SEEK_SET);
	data2_line[1] = lseek(fin2, 0, SEEK_SET);
	int line_count = 1;
	while( read(fin1, tmp, 1) ) if(*tmp == '\n')	data1_line[++line_count] = lseek(fin1, 0, SEEK_CUR);
	line_count = 1;
	while( read(fin2, tmp, 1) ) if(*tmp == '\n')	data2_line[++line_count] = lseek(fin2, 0, SEEK_CUR);

	// allocate memory for DP spaces and match_table(lines1 * lines2)
	tmp1 = (char *)malloc( MAX_STR_LEN * sizeof(char) );
	tmp2 = (char *)malloc( MAX_STR_LEN * sizeof(char) );
	int **LCSlen;
	LCSlen = (int **)malloc( (lines1 + 1) * sizeof(*LCSlen) );
	for(int i = 0 ; i <= lines1 ; i++) LCSlen[i] = (int *)malloc( (lines2 + 1) * sizeof(**LCSlen) );
	match_table = (int **)malloc( (lines1 + 2 ) * sizeof(*match_table) );
	for(int i = 0 ; i <= lines1 + 1 ; i++) match_table[i] = (int *)malloc( (lines2 + 2) * sizeof(**match_table) );
	for(int i = 0 ; i <= lines1 + 1 ; i++)
		for(int j = 0 ; j <= lines2 + 1 ; j++)	match_table[i][j] = -1;

	// finish the LCSlen table
	for(int i = 0 ; i <= lines1 ; i++)
		for(int j = 0 ; j <= lines2 ; j++) {
			LCSlen[i][j] = 0;
			if(i == 0 || j == 0)	continue;
			if( isSameLine(i, j) )	LCSlen[i][j] = 1 + LCSlen[i - 1][j - 1];
			if(LCSlen[i - 1][j] > LCSlen[i][j])	LCSlen[i][j] = LCSlen[i - 1][j];
			if(LCSlen[i][j - 1] > LCSlen[i][j])	LCSlen[i][j] = LCSlen[i][j - 1];
		}

	// tranverse the table to get the path
	int *path_line = (int *)malloc( (lines1 + lines2 + 1) * sizeof(int) );
	char *path_dir = (char *)malloc( (lines1 + lines2 + 1) * sizeof(char) );
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
		else if( isSameLine(line1_now, line2_now) ) {
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
	char format0[MAX_FORMAT_LEN], format1[MAX_FORMAT_LEN], format2[MAX_FORMAT_LEN], format2s[MAX_FORMAT_LEN], format3[MAX_FORMAT_LEN];
	sprintf(format0, "<<<<<<<<<<\n");
	sprintf(format1, ">>>>>>>>>> %s\n", basename(filename1) );
	sprintf(format2, "========== %s\n<<<<<<<<<<\n", basename(filename2) );
	sprintf(format2s, "========== %s\n", basename(filename2) );
	sprintf(format3, ">>>>>>>>>> %s\n========== %s\n", basename(filename1), basename(filename2) );
	for(int i = step - 1 ; i >= 0 ; i--) {
		if(path_dir[i] == 's') {
			if(path_dir[i + 1] == '1')	write(fout, format2, strlen(format2) );
			if(path_dir[i + 1] == '2') 	write(fout, format0, strlen(format0) );
			lseek(fin1, data1_line[ path_line[i] ], SEEK_SET);
			read(fin1, tmp1, data1_line[ path_line[i] + 1 ] - data1_line[ path_line[i] ]);
			write(fout, tmp1, data1_line[ path_line[i] + 1 ] - data1_line[ path_line[i] ]);
		}
		else if(path_dir[i] == '1') {
			if(path_dir[i + 1] == 's')	write(fout, format1, strlen(format1) );
			lseek(fin1, data1_line[ path_line[i] ], SEEK_SET);
			read(fin1, tmp1, data1_line[ path_line[i] + 1 ] - data1_line[ path_line[i] ]);
			write(fout, tmp1, data1_line[ path_line[i] + 1 ] - data1_line[ path_line[i] ]);
		}
		else if(path_dir[i] == '2') {
			if(path_dir[i + 1] == 's')	write(fout, format3, strlen(format3) );
			if(path_dir[i + 1] == '1')	write(fout, format2s, strlen(format2s) );
			lseek(fin2, data2_line[ path_line[i] ], SEEK_SET);
			read(fin2, tmp2, data2_line[ path_line[i] + 1 ] - data2_line[ path_line[i] ]);
			write(fout, tmp2, data2_line[ path_line[i] + 1 ] - data2_line[ path_line[i] ]);
		}
	}
	if( path_dir[0] == '1')	write(fout, format2, strlen(format2) );
	if( path_dir[0] == '2')	write(fout, format0, strlen(format0) );
	
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
	if( close(fout) )
	{
		printf("Fail to close %s\n", outputfile);
		return;
	}

}

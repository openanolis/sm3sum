#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include "unit_test.h"
#include "file_handler.h"
#include "sm3.h"
#include <unistd.h>

#define VERSION "0.1"

sm3_arguments sm3_args;

void print_help() {
	printf("Usage: sm3sum [OPTION] [FILE1] [FILE2]\n");
	printf("Print or check SM3 (256-bit) checksums.\n\n");
	printf("With no FILE, or when FILE is -, read standard input.\n");
	printf("  -b, --binary          read in binary mode\n");
	printf("  -c, --check           read checksums from the FILEs and check them\n");
	printf("      --tag             create a BSD-style checksum\n");
	printf("  -t, --text            read in text mode (default)\n");
	printf("  -z, --zero            end each output line with NUL, not newline,\n");
	printf("                          and disable file name escaping\n\n");
	printf("The following five options are useful only when verifying checksums:\n");
	printf("      --ignore-missing  don't fail or report status for missing files\n");
	printf("      --quiet           don't print OK for each successfully verified file\n");
	printf("      --status          don't output anything, status code shows success\n");
	printf("      --strict          exit non-zero for improperly formatted checksum lines\n");
	printf("  -w, --warn            warn about improperly formatted checksum lines\n\n");
	printf("      --help        display this help and exit\n");
	printf("      --version     output version information and exit\n\n");
	printf("The sums are computed as described in GM/T 0004-2012.\n");
	printf("When checking, the input should be a former output of this program.\n");
	printf("The default mode is to print a line with: checksum, a space,\n");
	printf("a character indicating input mode ('*' for binary, ' ' for text\n");
	printf("or where binary is insignificant), and name for each FILE.\n\n");
	printf("Note: There is no difference between binary mode and text mode.\n");
}

void parse_arguments(int argc, char *argv[]) {
	sm3_args.tail = &(sm3_args.head);
	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			// is an option
			if (strncmp(argv[i], "-b", 3) == 0 || strncmp(argv[i], "--binary", 9) == 0) {
				// no difference, ignoring
			} else if (strncmp(argv[i], "-c", 3) == 0 || strncmp(argv[i], "--check", 8) == 0) {
				sm3_args.check_mode = true;
			} else if (strncmp(argv[i], "--tag", 6) == 0) {
				sm3_args.bsd_tag = true;
			} else if (strncmp(argv[i], "-t", 3) == 0 || strncmp(argv[i], "--text", 7) == 0) {
				// no difference, ignoring
			} else if (strncmp(argv[i], "-z", 3) == 0 || strncmp(argv[i], "--zero", 7) == 0) {
				sm3_args.zero = true;
			} else if (strncmp(argv[i], "--ignore-missing", 17) == 0) {
				sm3_args.ignore_missing = true;
			} else if (strncmp(argv[i], "--quite", 8) == 0) {
				sm3_args.quiet = true;
			} else if (strncmp(argv[i], "--status", 9) == 0) {
				sm3_args.status = true;
			} else if (strncmp(argv[i], "--strict", 9) == 0) {
				sm3_args.strict = true;
			} else if (strncmp(argv[i], "-w", 3) == 0 || strncmp(argv[i], "--warn", 7) == 0) {
				sm3_args.warn = true;
			} else if (strncmp(argv[i], "--help", 7) == 0) {
				print_help();
				exit(0);
			} else if (strncmp(argv[i], "--version", 10) == 0) {
				printf("sm3sum version %s\n", VERSION);
				exit(0);
			} else if (strncmp(argv[i], "-", 2) == 0) {
				// still read from stdin, ignoring
			}
		} else {
			// is a file
			file_list *file_node = (file_list *)malloc(sizeof(file_list));
			file_node->file_name = argv[i];
			file_node->next = NULL;
			sm3_args.tail->next = file_node;
			sm3_args.tail = file_node;
		}
	}
}

/*
 * calculate hash for every file specified
 * only read from the list with head hash_pair_head
 */
void check() {
	FILE *target_file;
	size_t file_size;
	file_sm3_pair *file_ptr = hash_pair_head.next;
	int fail_count = 0;
	while (file_ptr != NULL) {
		if (1/*access(file_ptr->file_name, R_OK)*/) {
			// we are able to read from this file
			target_file = fopen(file_ptr->file_name, "r");
			// todo: handle read data
			file_size = get_file_size(file_ptr->file_name) * 8;
			read_and_calc(target_file, file_size);
			fclose(target_file);
			if (memcmp(file_ptr->expected_sm3, V, 256/8) == 0) {
				printf("%s: OK\n", file_ptr->file_name);
			} else {
				printf("%s: FAILED\n", file_ptr->file_name);
				++fail_count;
			}
		} else {
			// cannot read file
			printf("Cannot access file %s, either non-existing or not readable\n", file_ptr->file_name);
		}
		file_ptr = file_ptr->next;
	}
	if (fail_count > 0) {
		printf("sm3sum: WARNING: %d computed checksums did NOT match\n", fail_count);
	}
}

void output() {
	FILE *target_file;
	size_t file_size;
	file_list *file_ptr = sm3_args.head.next;
	if (file_ptr == NULL) {
		// read from stdin
		stdin_read_and_calc();
		sm3_print("-");
	} else {
		while (file_ptr != NULL) {
			if (1 /*access(file_ptr->file_name, F_OK)*/) {
				// we are able to read from this file
				target_file = fopen(file_ptr->file_name, "r");
				if (target_file == NULL) continue;
				// file size in bits
				file_size = get_file_size(file_ptr->file_name) * 8;
				// todo: output results
				read_and_calc(target_file, file_size);
				fclose(target_file);
				sm3_print(file_ptr->file_name);
				file_ptr = file_ptr->next;
			}
		}
	}
	
}

int main(int argc, char *argv[]) {
	parse_arguments(argc, argv);
	parse_filelist();
	if (sm3_args.check_mode) {
		check();
	} else {
		output();
	}
	/*
	printf("sm3 of 'abc':\n");
    sm3_padding_test();
	printf("sm3 of second example of SM3:\n");
	sm3_block_ext_test();
	printf("sm3 argument chceklist parse test\n");
	sm3_parse_checklist_test();
	printf("sm3 argument filelist parse test\n");
	sm3_parse_filelist_test();
	*/
	return 0;
}

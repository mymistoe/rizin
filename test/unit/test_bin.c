// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"
#include <rz_bin.h>

//TODO test rz_str_chop_path

bool test_rz_bin(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	RzBinFile *bf = rz_bin_open(bin, "bins/elf/ioli/crackme0x00", &opt);
	mu_assert_notnull(bf, "crackme0x00 binary could not be opened");
	mu_assert_notnull(bf->o, "bin object");

	RzList *sections = bf->o->sections;
	mu_assert_eq(rz_list_length(sections), 39, "rz_bin_get_sections");

	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_bin);
	return tests_passed != tests_run;
}

mu_main(all_tests)

/*
 * ecgen, tool for generating Elliptic curve domain parameters
 * Copyright (C) 2017-2018 J08nY
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */
/**
 * @file ecgen.c
 * @author J08nY <johny@neuromancer.sk>
 * @version 0.7.6
 * @copyright GPL v2.0
 */
//#include "../pari-2.15.2/src/headers/pari.h"
#include <pari/pari.h>
#include "cm/cm.h"
#include "exhaustive/exhaustive.h"
#include "invalid/invalid.h"
#include "io/input.h"
#include "io/output.h"
#include "util/timeout.h"

#ifdef GIT_COMMIT
#define GIT_VERSION "(git " GIT_COMMIT ")"
#else
#define GIT_VERSION ""
#endif

const char *argp_program_version =
    "ecgen 0.7.6" GIT_VERSION
    "\n"
    "Compiled with: " PARIVERSION
    "\n\n"
    "Copyright (C) 2017-2018,2021 J08nY\n"
    "License GPLv2: GNU GPL version 2 (or later) "
    "<http://gnu.org/licenses/gpl.html>\n"
    "This is free software: you are free to change and redistribute it.\n"
    "There is NO WARRANTY, to the extent permitted by law.";
const char *argp_program_bug_address = "<johny+ecgen@neuromancer.sk>";

static struct argp argp = {cli_options, cli_parse, cli_args_doc,
                           cli_doc,     0,         cli_filter};

bool init(void) {
	// init PARI, 1GB stack, 1M primes
	pari_init(cfg->memory, 1000000);

	// init PARI PRNG
	if (!random_init()) return false;

	// init the signal handlers, etc. for timeout handling
	if (!timeout_init()) return false;

	// set datadir if specified
	if (cfg->datadir) {
		default0("datadir", cfg->datadir);
	}

#ifdef PARI_DEBUG
	default0("debug", "2");
#endif

	// init the modular polynomial db from seadata
	pari_sp ltop = avma;
	pari_CATCH(e_FILE) {
		fprintf(
		    stderr,
		    "seadata not found, this will probably take quite some time.\n");
	}
	pari_TRY { ellmodulareqn(2, -1, -1); }
	pari_ENDCATCH avma = ltop;

	// Fix the mysterious isprime bug.
	isprime(stoi(1));

	// open outfile
	if (!output_init()) return false;

	// open infile
	if (!input_init()) return false;

	return true;
}

int quit(int status) {
	pari_close();

	timeout_quit();

	output_quit();
	input_quit();

	return status;
}

/**
 * @mainpage
 *
 * Three fundamentally different Elliptic curve generation approaches can be
 * taken.
 *
 * [Baier] -
 * https://www.cdc.informatik.tu-darmstadt.de/reports/reports/harald_baier.diss.pdf
 *
 * [Baier, Buchmann] -
 * https://www.ipa.go.jp/security/enc/CRYPTREC/fy15/doc/1030_Buchmann.evaluation.pdf
 *
 *   - Complex Multiplication:
 *     - Capable of generating a curve of a given (prime) order.
 *     - Generates a subset of all Elliptic Curves over a given field.
 *     - Used with the -n / --order option
 *
 *     - [Broker, Stevenhagen] - https://arxiv.org/abs/0712.2022
 *     - [Savas, Schmidt, Koc] -
 * http://people.oregonstate.edu/~schmidtt/ourPapers/SavasKoc/ches01curve.pdf
 *
 *   - Invalid curve generation:
 *     - Generates *invalid* curves for a given curve.
 *     - These curves have the same field, and *A* parameter in the short
 * Weierstrass equation.
 *     - Multiplication using some(most?) scalar multiplication algorithm
 * proceeds the same way
 *       multiplication on the input curve would.
 *
 *     - [Antipa, Brown, Menezes, Struik, Vanstone] -
 * https://www.iacr.org/archive/pkc2003/25670211/25670211.pdf
 *     - [Biehl, Mayer, Muller] -
 * http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.107.3920&rep=rep1&type=pdf
 *     - [Jager, Schwenk, Somorovksy] -
 * http://euklid.org/pdf/ECC_Invalid_Curve.pdf
 *
 *   - Exhaustive/Random approach:
 *     - Generates field and equation parameters:
 *       - randomly
 *       - using ANSI X9.62 verifiably random method(from seed)
 *       - given input
 *     , until a curve with requested properties appears.
 *     - Can generate curves repeatedly until one satisfies requested
 * properties:
 *       - -p / --prime generates curves until a prime order curve is found.
 *       - -K / --koblitz generates a curve with fixed A = 0 parameter.
 *
 */
int main(int argc, char *argv[]) {
	memset(cfg, 0, sizeof(config_t));
	if (!cli_init()) {
		return quit(EXIT_FAILURE);
	}
	argp_parse(&argp, argc, argv, 0, 0, cfg);
	cli_quit();

	if (!init()) {
		return quit(EXIT_FAILURE);
	}

	int status;
	if (cfg->method == METHOD_CM || cfg->method == METHOD_ANOMALOUS ||
	    cfg->method == METHOD_SUPERSINGULAR) {
		status = cm_do();
	} else if (cfg->method == METHOD_INVALID) {
		status = invalid_do();
	} else {
		status = exhaustive_do();
	}

	return quit(status);
}

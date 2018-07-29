// Copyright (c) 2018 Evan Klitzke <evan@eklitzke.org>
//
// This file is part of scanasm.
//
// scanasm is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// scanasm is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// scanasm. If not, see <http://www.gnu.org/licenses/>.

#include <getopt.h>

#include <iostream>
#include <stdexcept>

#include <elfio/elfio.hpp>

#include "./config.h"
#include "./reader.h"
#include "./util.h"

static void usage() {
  std::cout << "Usage: " PACKAGE_NAME " [options] FILE...\n\n";
  std::cout << "Options:\n";
  std::cout << "  -g, --groups        Collect group information\n";
  std::cout << "  -h, --help          Show help\n";
  std::cout << "  -v, --version       Show the package version\n";
}

int main(int argc, char **argv) {
  bool enable_groups = false;
  for (;;) {
    static struct option long_options[] = {
        {"groups", no_argument, 0, 'g'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {0, 0, 0, 0},
    };
    int option_index = 0;
    int c = getopt_long(argc, argv, "ghv", long_options, &option_index);
    if (c == -1) {
      break;
    }
    switch (c) {
      case 'g':
        enable_groups = true;
        break;
      case 'h':
        usage();
        return 0;
      case 'v':
        std::cout << PACKAGE_STRING "\n";
        return 0;
      case '?':
        // getopt_long should already have printed an error message
        break;
      default:
        std::cerr << "unrecognized command line flag: " << optarg << "\n";
        abort();
    }
  }

  // if no file arguments were specified, print help
  if (optind == argc) {
    usage();
    return 0;
  }

  Counter<std::string> insn_counts;
  Counter<std::string> group_counts;
  auto group_ptr = enable_groups ? &group_counts : nullptr;

  // process each file
  for (int i = optind; i < argc; i++) {
    try {
      Reader reader(argv[i]);
      reader.Process(&insn_counts, group_ptr);
    } catch (std::exception &exc) {
      std::cerr << exc.what() << "\n";
      return 1;
    }
  }

  insn_counts.Print();

  if (enable_groups) {
    std::cout << "\n";
    group_counts.Print();
  }

  return 0;
}

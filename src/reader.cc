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

#include "./reader.h"

#include <capstone/capstone.h>

#include <cinttypes>
#include <functional>
#include <set>
#include <sstream>

Reader::Reader(const std::string &filename) {
  std::ostringstream os;
  os << "Failed to load or process ELF file " << filename;
  if (!elf_.load(filename)) {
    throw std::runtime_error(os.str());
  }
  if (elf_.get_class() != ELFCLASS64) {
    os << "; cannot parse ELF class " << elf_.get_class()
       << ", only ELFCLASS64 is supported";
    throw std::runtime_error(os.str());
  }
  if (elf_.get_machine() != EM_X86_64) {
    os << "; cannot parse ELF architecture " << elf_.get_machine()
       << ", only EM_X86_64 is supported";
    throw std::runtime_error(os.str());
  }
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle_) != CS_ERR_OK) {
    os << "; cs_open failed";
    throw std::runtime_error(os.str());
  }
  cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
}

void Reader::Process(Counter<std::string> *insn_counts,
                     Counter<std::string> *group_counts) {
  for (const auto &sec : elf_.sections) {
    if (sec->get_name() != ".text") {
      continue;
    }
#ifdef USE_ITER_API
    cs_insn *insn = cs_malloc(handle_);
    const uint8_t *code = (const uint8_t *)sec->get_data();
    size_t code_size = sec->get_size();
    size_t addr = sec->get_address();
    while (cs_disasm_iter(handle_, &code, &code_size, &addr, insn)) {
      HandleInstruction(*insn, insn_counts, group_counts);
    }
    cs_free(insn, 1);
#else
    cs_insn *all_insn;
    size_t count = cs_disasm(handle_, (const uint8_t *)sec->get_data(),
                             sec->get_size(), sec->get_address(), 0, &all_insn);
    for (size_t i = 0; i < count; i++) {
      HandleInstruction(all_insn[i], insn_counts, group_counts);
      auto insn = all_insn[i];
    }
    cs_free(all_insn, count);
#endif
  }
}

Reader::~Reader() { cs_close(&handle_); }

void Reader::HandleInstruction(const cs_insn &insn,
                               Counter<std::string> *insn_counts,
                               Counter<std::string> *group_counts) {
  insn_counts->Inc(insn.mnemonic);
  const cs_detail &detail = *insn.detail;
  for (auto i = 0; i < detail.groups_count; i++) {
    group_counts->Inc(cs_group_name(handle_, detail.groups[i]));
  }
}

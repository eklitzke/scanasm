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

#pragma once

#include <stdexcept>
#include <string>
#include <unordered_map>

#include <capstone/capstone.h>
#include <elfio/elfio.hpp>

#include "./util.h"

class Reader {
 public:
  Reader() = delete;
  Reader(const Reader &other) = delete;
  Reader(const Reader &&other) = delete;
  explicit Reader(const std::string &filename);
  ~Reader();

  void Process();

 private:
  ELFIO::elfio elf_;
  csh handle_;
  Counter<std::string> insn_counts_;
  Counter<std::string> group_counts_;

  void HandleInstruction(const cs_insn &insn);
};

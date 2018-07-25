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

#include <capstone/capstone.h>

class CapstoneCtx {
 public:
  CapstoneCtx() {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle_) != CS_ERR_OK) {
      throw std::runtime_error("failed to cs_open");
    }
  }
  CapstoneCtx(const CapstoneCtx &other) = delete;
  CapstoneCtx(const CapstoneCtx &&other) = delete;

  ~CapstoneCtx() { cs_close(&handle_); }

 private:
  csh handle_;
};

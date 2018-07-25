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

#pragma once
#include <string>

class KreyviumHandler {
public:
    KreyviumHandler();
    std::string processMessage(const std::string& ciphertext);
};
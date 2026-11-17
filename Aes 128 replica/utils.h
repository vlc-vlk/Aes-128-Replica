#pragma once
#include <string>
#include<vector>
#include<map>
#include<sstream>
#include<algorithm>
#include<numeric>
std::vector<bool> hex_to_bin(std::string plaintext);
std::string bin_to_text(std::vector<bool>);
std::string bin_to_hex(std::vector<bool>);
int bin_to_dec(std::vector<bool>);
int hex_to_dec(std::string);
std::vector<bool> dec_to_bin(int);
std::vector<bool> dec_to_bin_in_8_biti(int);
std::vector<bool> dec_to_bin_in_4_biti(int);
int ret(char x);
std::vector<bool> xor_bin_bin(std::vector<bool>, std::vector<bool>);
std::vector<bool> repeat_xor_bin_bin(std::vector<bool>, std::vector<bool>);
void binar_plaintext(int x, std::vector<bool>& biti_plaintext);
std::vector<bool> text_to_bin(std::string text);
std::string base64_encode(std::vector<bool>);
std::vector<bool> VECHI_base64_decode(std::string);
std::vector<bool> base64_decode(std::string);
std::vector<std::vector<bool>> transpozare(int, std::vector<bool>);
std::vector<bool> base64_decode(std::string);

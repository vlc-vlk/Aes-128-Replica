#pragma once
#include <string>
#include<vector>
#include<map>
#include<sstream>
#include<algorithm>
#include<numeric>
using namespace::std;
vector<bool> hex_to_bin(string plaintext);
string bin_to_text(vector<bool>);
string bin_to_hex(vector<bool>);
int bin_to_dec(vector<bool>);
int hex_to_dec(string);
vector<bool> dec_to_bin(int);
vector<bool> dec_to_bin_in_8_biti(int);
vector<bool> dec_to_bin_in_4_biti(int);
int ret(char x);
vector<bool> xor_bin_bin(vector<bool>, vector<bool>);
vector<bool> repeat_xor_bin_bin(vector<bool>, vector<bool>);
void binar_plaintext(int x, vector<bool>& biti_plaintext);
vector<bool> text_to_bin(string text);
vector<double> frecventa_caractere(string text);
double scor_text(vector<bool>);
bool verificare_valabil(vector<bool>);
int hamming_distance_text(string, string);
int hamming_distance_bin(vector<bool>, vector<bool>);
string base64_encode(vector<bool>);
vector<bool> VECHI_base64_decode(string);
vector<bool> base64_decode(string);
int best_keysize(vector<bool>);
int best_keysize_2(vector<bool>);
vector<vector<bool>> transpozare(int, vector<bool>);
int best_repeat_chr_xor_candid(vector<bool>);
pair<vector<int>, int> aparitii_caractere_spec(vector<bool>);
double medie_coincidente_bin_raw(int, vector<bool>);
void scor_sparg_dim_cheie(int, vector<bool>);
double scor_text_alternativ(vector<bool>);
double scor_vectori(vector<bool>);
vector<bool> base64_decode(string);
int gaseste_keysize(vector<bool>);

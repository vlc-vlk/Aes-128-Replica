#pragma once
#include <string>
#include<vector>
#include<map>
#include<sstream>
#include<algorithm>
#include<numeric>
using namespace std;

void testare();
void testaree();


extern vector<vector<vector<bool>>> invers_tabela_substitutii_rijndael;
extern vector<vector<vector<bool>>> tabela_substitutii_rijndael;
extern vector<vector<bool>> constante_runda;

vector<bool> rotire_date_90_grade_ca_aes_e_cretin(vector<bool>);
vector<bool> rotire_cuvant(vector<bool>);
vector<vector<bool>> inv_substitutire_rijndael(vector<vector<bool>>);
vector<bool> xor_constanta_runda(vector<bool>, int);
vector<vector<bool>> calc_toate_10_chei_runda(vector<vector<bool>>);
vector<vector<bool>> schimbare_format_linear_chei_runda(vector<vector<vector<bool>>>);
vector<bool> inmultire_GF_2_8(vector<bool>, vector<bool>);
vector<bool> padding(vector<bool>);
vector<bool> unpadding(vector<bool>);

/// A la cart

vector<vector<bool>> impartire_piesa_in_cuvinte(vector<bool>);
vector<vector<bool>> shift_rows(vector<vector<bool>>);
vector<vector<bool>> inv_shift_rows(vector<vector<bool>>);
vector<vector<bool>> mix_columns(vector<vector<bool>>);
vector<vector<bool>> inv_mix_columns(vector<vector<bool>>);
vector<vector<bool>> add_round_key(vector<vector<bool>>, vector<bool>);
vector<vector<bool>> substituire_rijndael(vector<vector<bool>>);
vector<bool> substituire_rijndael_pt_cheitza(vector<bool>);
vector<bool> AES_128_CIFRUL(vector<bool>, vector<vector<bool>>);
vector<bool> AES_128_CIFRUL_PLUS(vector<bool>, vector<vector<bool>>);
vector<bool> AES_128_ECB_MODE(vector<bool>, vector<bool>);
vector<bool> AES_128_ECB_MODE_PLUS(vector<bool>, vector<bool>);
vector<bool> INV_AES_128_CIFRUL(vector<bool>, vector<vector<bool>>);
vector<bool> DECRIPTARE_AES_128_ECB_MODE_PLUS(vector<bool>, vector<vector<bool>>);
vector<bool> DECRIPTARE_AES_128_ECB_MODE(vector<bool>, vector<bool>);
vector<vector<vector<bool>>> impartire_state_in_baiti_individuali(vector<bool>);
vector<vector<vector<bool>>> shift_rows_mix_columns_plus(vector<vector<vector<bool>>>);
vector<vector<vector<bool>>> inv_mix_columns_shift_rows_plus(vector<vector<vector<bool>>>);
vector<vector<vector<bool>>> add_round_key_plus(vector<vector<vector<bool>>>, vector<bool>);
vector<vector<vector<bool>>> sub_bytes_plus(vector<vector<vector<bool>>>);
vector<vector<vector<bool>>> shift_rows_plus(vector<vector<vector<bool>>>);
#include "utils_AES_128.h"
#include "utils.h"
#include<cstring>
#include <sstream>
#include<vector>
#include <iostream>
#include<algorithm>
#include <fstream>
using namespace std;

#include <chrono>
using namespace std::chrono;
using namespace std::chrono;

vector<bool> AES_128_CIFRUL_PLUS(vector<bool> plaintext, vector<vector<bool>> cheile_runda) {
	vector<vector<vector<bool>>> statee = impartire_state_in_baiti_individuali(plaintext);
	vector<bool> returnare(128);
	statee = add_round_key_plus(statee, cheile_runda[0]);
	for (int runda = 1; runda <= 9; runda++) {
		statee = sub_bytes_plus(statee);
		statee = shift_rows_mix_columns_plus(statee);
		statee = add_round_key_plus(statee, cheile_runda[runda]);
	}
	statee = sub_bytes_plus(statee);
	statee = shift_rows_plus(statee);
	statee = add_round_key_plus(statee, cheile_runda[10]);


	for (int coloana = 0; coloana < 4; coloana++) {
		for (int linie = 0; linie < 4; linie++)
			returnare.insert(returnare.begin() + coloana * 32 + linie * 8, statee[linie][coloana].begin(), statee[linie][coloana].end());
	}
	return returnare;
}

vector<bool> AES_128_ECB_MODE_PLUS(vector<bool> plaintext, vector<bool> cheie) {
	plaintext = padding(plaintext);

	int indice_start = 0;
	vector<bool> bloc(128, 0);
	vector<bool> ciphertext;
	vector<bool> rezultat_criptare_bloc;
	vector<vector<bool>> cheile_runda = calc_toate_10_chei_runda(impartire_piesa_in_cuvinte(cheie));
	while (indice_start < plaintext.size() - 1) {
		bloc.assign(plaintext.begin() + indice_start, plaintext.begin() + indice_start + 128);
		rezultat_criptare_bloc = AES_128_CIFRUL_PLUS(bloc, cheile_runda);

		ciphertext.insert(ciphertext.end(), rezultat_criptare_bloc.begin(), rezultat_criptare_bloc.begin() + 128);
		indice_start += 128;
	}
	return { ciphertext };
}

vector<bool> DECRIPTARE_AES_128_ECB_MODE(vector<bool>ciphertext, vector<bool>cheie) {
	int indice_start = 0;
	vector<bool> bloc(128, 0);
	vector<bool> plaintext;
	vector<bool> rezultat_decriptare_bloc;
	vector<vector<bool>> cheile_runda = calc_toate_10_chei_runda(impartire_piesa_in_cuvinte(cheie));
	while (indice_start < ciphertext.size() - 1) {
		bloc.assign(ciphertext.begin() + indice_start, ciphertext.begin() + indice_start + 128);
		rezultat_decriptare_bloc = INV_AES_128_CIFRUL(bloc, cheile_runda);
		plaintext.insert(plaintext.end(), rezultat_decriptare_bloc.begin(), rezultat_decriptare_bloc.begin() + 128);
		indice_start += 128;
	}
	return unpadding(plaintext);
}

vector<bool> AES_128_CIFRUL(vector<bool> plaintext, vector<vector<bool>> cheile_runda) {
	vector<vector<bool>> state = impartire_piesa_in_cuvinte(plaintext);
	vector<bool> ciphertext;

	state = add_round_key(state, cheile_runda[0]);
	for (int runda = 1; runda <= 9; runda++) {
		state = substituire_rijndael(state);

		//cout << "inainte de shift si mix: " << endl << bin_to_hex(state[0]) << endl << bin_to_hex(state[1]) << endl << bin_to_hex(state[2]) << endl << bin_to_hex(state[3]) << endl;

		state = shift_rows(state);
		state = mix_columns(state);

		//cout << "dupa shift si mix: " << endl << bin_to_hex(state[0]) << endl << bin_to_hex(state[1]) << endl << bin_to_hex(state[2]) << endl << bin_to_hex(state[3]) << endl << endl;

		state = add_round_key(state, cheile_runda[runda]);
	}
	state = substituire_rijndael(state);
	state = shift_rows(state);
	state = add_round_key(state, cheile_runda[10]);

	ciphertext.insert(ciphertext.begin(), state[0].begin(), state[0].begin() + 32);
	ciphertext.insert(ciphertext.begin() + 32, state[1].begin(), state[1].begin() + 32);
	ciphertext.insert(ciphertext.begin() + 64, state[2].begin(), state[2].begin() + 32);
	ciphertext.insert(ciphertext.begin() + 96, state[3].begin(), state[3].begin() + 32);
	return ciphertext;
}

vector<bool> AES_128_ECB_MODE(vector<bool> plaintext, vector<bool> cheie) {
	plaintext = padding(plaintext);

	int indice_start = 0;
	vector<bool> bloc(128, 0);
	vector<bool> ciphertext;
	vector<bool> rezultat_criptare_bloc;
	vector<vector<bool>> cheile_runda = calc_toate_10_chei_runda(impartire_piesa_in_cuvinte(cheie));
	while (indice_start < plaintext.size() - 1) {
		bloc.assign(plaintext.begin() + indice_start, plaintext.begin() + indice_start + 128);
		rezultat_criptare_bloc = AES_128_CIFRUL(bloc, cheile_runda);
		ciphertext.insert(ciphertext.end(), rezultat_criptare_bloc.begin(), rezultat_criptare_bloc.begin() + 128);
		indice_start += 128;
	}
	return { ciphertext };
}

vector<bool> INV_AES_128_CIFRUL(vector<bool> ciphertext, vector<vector<bool>> cheile_runda) {
	vector<vector<bool>> state = impartire_piesa_in_cuvinte(ciphertext);
	vector<bool> plaintext;
	state = add_round_key(state, cheile_runda[10]);
	state = inv_shift_rows(state);
	state = inv_substitutire_rijndael(state);
	for (int runda = 9; runda >= 1; runda--) {
		state = add_round_key(state, cheile_runda[runda]);
		state = inv_mix_columns(state);
		state = inv_shift_rows(state);
		state = inv_substitutire_rijndael(state);
	}
	state = add_round_key(state, cheile_runda[0]);

	plaintext.insert(plaintext.begin(), state[0].begin(), state[0].end());
	plaintext.insert(plaintext.begin() + 32, state[1].begin(), state[1].end());
	plaintext.insert(plaintext.begin() + 64, state[2].begin(), state[2].end());
	plaintext.insert(plaintext.begin() + 96, state[3].begin(), state[3].end());

	return plaintext;
}

vector<bool> DECRIPTARE_AES_128_ECB_MODE_PLUS(vector<bool>, vector<vector<bool>>);
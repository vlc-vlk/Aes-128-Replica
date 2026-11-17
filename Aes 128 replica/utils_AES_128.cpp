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

vector<float> durate_la_asignari;

vector<bool> rotire_date_90_grade_ca_aes_e_cretin(vector<bool> intrare) {
	vector<bool> iesire(128, 0);
	if (intrare.size() != 128) {
		return { 0 };
	}
	int coloana, indice_start, bait = 0;
	while (bait < 16) {
		coloana = bait / 4;
		indice_start = coloana * 8 + (bait % 4) * 32;
		for (int i = 0; i < 8; i++)
			iesire[indice_start + i] = intrare[bait * 8 + i];
		bait++;
	}
	return iesire;
}

vector<bool> rotire_cuvant(vector<bool> cuvant) {
	vector<bool> aux;
	for (size_t i = 0; i < 8; i++)
		aux.push_back(cuvant[i]);
	for (size_t i = 0; i < 24; i++)
		cuvant[i] = cuvant[i + 8];
	for (size_t i = 24; i < 32; i++)
		cuvant[i] = aux[i - 24];
	return cuvant;
}

vector<vector<bool>> inv_substitutire_rijndael(vector<vector<bool>> state) {
	unsigned int x, y;
	if (state[0].size() % 2 != 0) {
		std::cout << "state nu are dimensiunea care trebuie la inv_sub_bytes " << state[0].size();
		return { {0} };
	}
	for (int coloana = 0; coloana < 4; coloana++) {
		vector<bool> cuv_substituit;
		for (int i = 0; i < 4; i++) {
			x = bin_to_dec({ state[coloana][i * 8], state[coloana][i * 8 + 1], state[coloana][i * 8 + 2], state[coloana][i * 8 + 3] });
			y = bin_to_dec({ state[coloana][i * 8 + 4], state[coloana][i * 8 + 5], state[coloana][i * 8 + 6], state[coloana][i * 8 + 7] });
			for (size_t j = 0; j < 8; j++)
				cuv_substituit.push_back(invers_tabela_substitutii_rijndael[x][y][j]);
		}
		state[coloana] = cuv_substituit;
	}
	return state;
}

vector<bool> xor_constanta_runda(vector<bool> cuvant, int runda_incepand_de_la_1) {
	if (cuvant.size() != 32) {
		std::cout << "cuvantul nu are 128 biti";
		return { 0 };
	}
	return xor_bin_bin(cuvant, constante_runda[runda_incepand_de_la_1 - 1]);
}

vector<vector<bool>> calc_toate_10_chei_runda(vector<vector<bool>> cheie_actuala) {
	vector<bool> rezultat_prelucrare_cuvant_3;
	vector<vector<vector<bool>>> cele_10_chei_runda_pe_coloane(11, vector<vector<bool>>(4, vector<bool>(32, 0)));
	vector<vector<bool>> altfel(11, vector<bool>(128, 0));

	for (int i = 0; i < cheie_actuala.size(); i++)
		for (int j = 0; j < cheie_actuala[i].size(); j++)
			altfel[0][i * 32 + j] = cheie_actuala[i][j];

	for (int i = 1; i <= 10; i++) {
		rezultat_prelucrare_cuvant_3 = xor_constanta_runda(substituire_rijndael_pt_cheitza(rotire_cuvant(cheie_actuala[3])), i);
		cheie_actuala[0] = xor_bin_bin(cheie_actuala[0], rezultat_prelucrare_cuvant_3);
		cheie_actuala[1] = xor_bin_bin(cheie_actuala[0], cheie_actuala[1]);
		cheie_actuala[2] = xor_bin_bin(cheie_actuala[1], cheie_actuala[2]);
		cheie_actuala[3] = xor_bin_bin(cheie_actuala[2], cheie_actuala[3]);
		for (size_t j = 0; j < 32; j++) {
			cele_10_chei_runda_pe_coloane[i][0][j] = cheie_actuala[0][j];
			cele_10_chei_runda_pe_coloane[i][1][j] = cheie_actuala[1][j];
			cele_10_chei_runda_pe_coloane[i][2][j] = cheie_actuala[2][j];
			cele_10_chei_runda_pe_coloane[i][3][j] = cheie_actuala[3][j];
		}

		for (int coloana = 0; coloana < 4; coloana++)
			for (int cnt = 0; cnt < 4; cnt++)
				for (int j = 0; j < 8; j++)
					altfel[i][coloana * 32 + cnt * 8 + j] = cele_10_chei_runda_pe_coloane[i][coloana][cnt * 8 + j];
	}
	return altfel;
}

vector<vector<bool>> schimbare_format_linear_chei_runda(vector<vector<vector<bool>>> cele_10_chei_runda_pe_coloane) {
	vector<vector<bool>> cele_10_chei_runda_linear(11, vector<bool>(128, 0));
	for (int cheia_nr = 0; cheia_nr < 10; cheia_nr++) {
		for (int linia = 0; linia < 4; linia++)
			for (int coloana = 0; coloana < 4; coloana++)
				cele_10_chei_runda_linear[cheia_nr].push_back(cele_10_chei_runda_pe_coloane[cheia_nr][coloana][linia]);
	}
	return cele_10_chei_runda_linear;
}


vector<bool> inmultire_GF_2_8(vector<bool> a, vector<bool> b) {
	if (a.size() > 8) {
		cout << "a are mai mult de 8 biti" << endl;
		return { 0 };
	}
	if (b.size() > 8) {
		cout << "b are mai mult de 8 biti" << endl;
		return { 0 };
	}
	vector<bool> rezultat = { 0,0,0,0,0,0,0,0 };
	bool carry;
	for (int i = 7; i >= 0; i--) {
		if (b[i] == 1) {
			rezultat = xor_bin_bin(rezultat, a);
		}
		if (a[0] == 1)
			carry = 1;
		else
			carry = 0;
		for (int j = 0; j < 7; j++)
			a[j] = a[j + 1];
		a[7] = 0;
		if (carry == 1)
			a = xor_bin_bin(a, { 0,0,0,1,1,0,1,1 });
	}
	return rezultat;
}

vector<vector<bool>> inv_mix_columns(vector<vector<bool>> stare_actuala) {

	vector<bool> stare_noua(128, 0);
	vector<bool> extras_din_stare1(8, 0), extras_din_stare2(8, 0), extras_din_stare3(8, 0), extras_din_stare4(8, 0);
	vector<vector<bool>> dupa_mix(4, vector<bool>(8, 0));

	for (int coloana = 0; coloana < 4; coloana++) {
		for (size_t bit_in_bait = 0; bit_in_bait < 8; bit_in_bait++) {
			extras_din_stare1[bit_in_bait] = stare_actuala[coloana][bit_in_bait];
			extras_din_stare2[bit_in_bait] = stare_actuala[coloana][bit_in_bait + 8];
			extras_din_stare3[bit_in_bait] = stare_actuala[coloana][bit_in_bait + 16];
			extras_din_stare4[bit_in_bait] = stare_actuala[coloana][bit_in_bait + 24];
		}

		dupa_mix[0] = xor_bin_bin(inmultire_GF_2_8(hex_to_bin("0e"), extras_din_stare1), inmultire_GF_2_8(hex_to_bin("0b"), extras_din_stare2));
		dupa_mix[0] = xor_bin_bin(dupa_mix[0], xor_bin_bin(inmultire_GF_2_8(hex_to_bin("0d"), extras_din_stare3), inmultire_GF_2_8(hex_to_bin("09"), extras_din_stare4)));
		dupa_mix[1] = xor_bin_bin(inmultire_GF_2_8(hex_to_bin("09"), extras_din_stare1), inmultire_GF_2_8(hex_to_bin("0e"), extras_din_stare2));
		dupa_mix[1] = xor_bin_bin(dupa_mix[1], xor_bin_bin(inmultire_GF_2_8(hex_to_bin("0b"), extras_din_stare3), inmultire_GF_2_8(hex_to_bin("0d"), extras_din_stare4)));
		dupa_mix[2] = xor_bin_bin(inmultire_GF_2_8(hex_to_bin("0d"), extras_din_stare1), inmultire_GF_2_8(hex_to_bin("09"), extras_din_stare2));
		dupa_mix[2] = xor_bin_bin(dupa_mix[2], xor_bin_bin(inmultire_GF_2_8(hex_to_bin("0e"), extras_din_stare3), inmultire_GF_2_8(hex_to_bin("0b"), extras_din_stare4)));
		dupa_mix[3] = xor_bin_bin(inmultire_GF_2_8(hex_to_bin("0b"), extras_din_stare1), inmultire_GF_2_8(hex_to_bin("0d"), extras_din_stare2));
		dupa_mix[3] = xor_bin_bin(dupa_mix[3], xor_bin_bin(inmultire_GF_2_8(hex_to_bin("09"), extras_din_stare3), inmultire_GF_2_8(hex_to_bin("0e"), extras_din_stare4)));

		for (int j = 0; j < 8; j++) {
			stare_actuala[coloana][j] = dupa_mix[0][j];
			stare_actuala[coloana][j + 8] = dupa_mix[1][j];
			stare_actuala[coloana][j + 16] = dupa_mix[2][j];
			stare_actuala[coloana][j + 24] = dupa_mix[3][j];
		}

	}
	return stare_actuala;
}

vector<bool> padding(vector<bool> plaintext) {
	int diferenta_in_baiti = 16 - ((plaintext.size() / 8) % 16);
	if (plaintext.size() % 128 != 0) {
		vector<bool> diferenta_in_biti, auxiliar;
		auxiliar = dec_to_bin_in_4_biti(diferenta_in_baiti / 16);
		for (size_t i = 0; i < auxiliar.size(); i++)
			diferenta_in_biti.push_back(auxiliar[i]);
		auxiliar = dec_to_bin_in_4_biti(diferenta_in_baiti % 16);
		for (size_t i = 0; i < auxiliar.size(); i++)
			diferenta_in_biti.push_back(auxiliar[i]);
		for (int i = 0; i < diferenta_in_baiti; i++)
			for (int j = 0; j < 8; j++)
				plaintext.push_back(diferenta_in_biti[j]);
	}
	else {
		for (int i = 0; i < 16; i++)
			plaintext.insert(plaintext.end(), { 0,0,0,1,0,0,0,0 });
	}
	return plaintext;
}

vector<bool> unpadding(vector<bool> plaintext) {
	int lungaa = plaintext.size();
	vector<bool> impingator;
	bool nu_e = 0;
	int ultim_bait = bin_to_dec({ plaintext[lungaa - 8], plaintext[lungaa - 7], plaintext[lungaa - 6], plaintext[lungaa - 5], plaintext[lungaa - 4], plaintext[lungaa - 3], plaintext[lungaa - 2], plaintext[lungaa - 1] });
	if (ultim_bait >= 1 || ultim_bait <= 16) {
		vector<bool> ultimii_baiti;
		vector<bool> ultim_baitt = dec_to_bin_in_8_biti(ultim_bait);

		for (int i = ultim_bait - 1; i > 10; i--)
			for (int k = plaintext.size() - i * 8; k < plaintext.size() - (i - 1) * 8; k++)
				if (plaintext[k] != ultim_baitt[k - (plaintext.size() - i * 8)])
					nu_e = 1;

		if (nu_e == 0)
			plaintext.erase(plaintext.end() - ultim_bait * 8, plaintext.end());
	}
	return plaintext;
}

//// A LA CARTE

vector<vector<bool>> impartire_piesa_in_cuvinte(vector<bool> piesa) {
	vector<vector<bool>> state(4, vector<bool>(32, 0));
	for (int coloana = 0; coloana < 4; coloana++) {
		int start = coloana * 32, finis = (coloana + 1) * 32;
		for (int j = start; j < finis; j++)
			state[coloana][j - start] = piesa[j];
	}
	return state;
}

vector<vector<bool>> shift_rows(vector<vector<bool>> state) {
	vector<bool> aux(24, 0);
	for (int rand = 1; rand < 4; rand++) {
		for (int coloana_din_care_iau = 0; coloana_din_care_iau < rand; coloana_din_care_iau++)
			for (int j = 0; j < 8; j++)
				aux[coloana_din_care_iau * 8 + j] = state[coloana_din_care_iau][rand * 8 + j];
		for (int coloana_in_care_bag = 0; coloana_in_care_bag < 4 - rand; coloana_in_care_bag++)
			for (int j = 0; j < 8; j++)
				state[coloana_in_care_bag][rand * 8 + j] = state[coloana_in_care_bag + rand][rand * 8 + j];
		for (int coloana_in_care_intra_aux = 4 - rand, start = 0; coloana_in_care_intra_aux < 4; coloana_in_care_intra_aux++, start++)
			for (int j = 0; j < 8; j++)
				state[coloana_in_care_intra_aux][rand * 8 + j] = aux[start * 8 + j];
	}
	return state;
}

vector<vector<bool>> mix_columns(vector<vector<bool>> state) {
	vector<vector<bool>> dupa_mix(4, vector<bool>(32, 0));
	for (int coloana = 0; coloana < 4; coloana++) {
		vector<bool> buffer, aux, extras_0(8, 0), extras_1(8, 0), extras_2(8, 0), extras_3(8, 0);

		for (int j = 0; j < 8; j++)
			extras_0[j] = state[coloana][j], extras_1[j] = state[coloana][8 + j], extras_2[j] = state[coloana][16 + j], extras_3[j] = state[coloana][24 + j];

		aux = xor_bin_bin(inmultire_GF_2_8(hex_to_bin("02"), extras_0), inmultire_GF_2_8(hex_to_bin("03"), extras_1));
		aux = xor_bin_bin(xor_bin_bin(aux, extras_2), extras_3);
		buffer.insert(buffer.end(), aux.begin(), aux.end());
		aux = xor_bin_bin(inmultire_GF_2_8(hex_to_bin("02"), extras_1), inmultire_GF_2_8(hex_to_bin("03"), extras_2));
		aux = xor_bin_bin(xor_bin_bin(aux, extras_0), extras_3);
		buffer.insert(buffer.end(), aux.begin(), aux.end());
		aux = xor_bin_bin(inmultire_GF_2_8(hex_to_bin("02"), extras_2), inmultire_GF_2_8(hex_to_bin("03"), extras_3));
		aux = xor_bin_bin(xor_bin_bin(aux, extras_0), extras_1);
		buffer.insert(buffer.end(), aux.begin(), aux.end());
		aux = xor_bin_bin(inmultire_GF_2_8(hex_to_bin("03"), extras_0), inmultire_GF_2_8(hex_to_bin("02"), extras_3));
		aux = xor_bin_bin(xor_bin_bin(aux, extras_1), extras_2);
		buffer.insert(buffer.end(), aux.begin(), aux.end());

		state[coloana] = buffer;
	}
	return state;
}


vector<vector<bool>> add_round_key(vector<vector<bool>> state, vector<bool> cheie) {
	vector<vector<bool>> cheia_impartita = impartire_piesa_in_cuvinte(cheie);
	state[0] = xor_bin_bin(state[0], cheia_impartita[0]);
	state[1] = xor_bin_bin(state[1], cheia_impartita[1]);
	state[2] = xor_bin_bin(state[2], cheia_impartita[2]);
	state[3] = xor_bin_bin(state[3], cheia_impartita[3]);

	return state;
}

vector<vector<bool>> substituire_rijndael(vector<vector<bool>> state) {
	unsigned int x, y;
	if (state[0].size() % 2 != 0) {
		std::cout << "stadiul nu are dimensiunea care trebi la sub_bytes " << state[0].size();
		return { {0} };
	}
	for (int coloana = 0; coloana < state.size(); coloana++) {
		vector<bool> cuv_substituit;
		for (int i = 0; i < state[coloana].size() / 8; i++) {
			x = bin_to_dec({ state[coloana][i * 8], state[coloana][i * 8 + 1], state[coloana][i * 8 + 2], state[coloana][i * 8 + 3] });
			y = bin_to_dec({ state[coloana][i * 8 + 4], state[coloana][i * 8 + 5], state[coloana][i * 8 + 6], state[coloana][i * 8 + 7] });
			for (size_t j = 0; j < 8; j++)
				cuv_substituit.push_back(tabela_substitutii_rijndael[x][y][j]);
		}
		state[coloana] = cuv_substituit;
	}
	return state;
}

vector<bool> substituire_rijndael_pt_cheitza(vector<bool> cuv_cheitza) {
	unsigned int x, y;
	if (cuv_cheitza.size() % 2 != 0) {
		std::cout << "stadiul nu are dimensiunea care trebi la sub_bytes " << cuv_cheitza.size();
		return { {0} };
	}
	vector<bool> cuv_substituit;
	for (int i = 0; i < cuv_cheitza.size() / 8; i++) {
		x = bin_to_dec({ cuv_cheitza[i * 8], cuv_cheitza[i * 8 + 1], cuv_cheitza[i * 8 + 2], cuv_cheitza[i * 8 + 3] });
		y = bin_to_dec({ cuv_cheitza[i * 8 + 4], cuv_cheitza[i * 8 + 5], cuv_cheitza[i * 8 + 6], cuv_cheitza[i * 8 + 7] });

		for (size_t j = 0; j < 8; j++)
			cuv_substituit.push_back(tabela_substitutii_rijndael[x][y][j]);
	}
	cuv_cheitza = cuv_substituit;
	return cuv_cheitza;
}

vector<vector<bool>> inv_shift_rows(vector<vector<bool>> state) {
	vector<bool> auxiliar(24, 0);
	for (int rand = 1; rand < 4; rand++) {
		for (int coloana_din_care_iau_pt_aux = 4 - rand, start = 0; coloana_din_care_iau_pt_aux < 4; coloana_din_care_iau_pt_aux++, start++)
			for (int j = 0; j < 8; j++)
				auxiliar[start * 8 + j] = state[coloana_din_care_iau_pt_aux][rand * 8 + j];
		for (int coloana_in_care_bag = 3; coloana_in_care_bag > rand - 1; coloana_in_care_bag--)
			for (int j = 0; j < 8; j++)
				state[coloana_in_care_bag][rand * 8 + j] = state[coloana_in_care_bag - rand][rand * 8 + j];
		for (int coloana_in_care_bag_aux = 0, start = 0; coloana_in_care_bag_aux < rand; coloana_in_care_bag_aux++, start++)
			for (int j = 0; j < 8; j++)
				state[coloana_in_care_bag_aux][rand * 8 + j] = auxiliar[start * 8 + j];
	}
	return state;
}

vector<vector<vector<bool>>> impartire_state_in_baiti_individuali(vector<bool> state) {
	vector<vector<vector<bool>>> statee(4, vector<vector<bool>>(4, vector<bool>(8, 0)));
	for (int linie = 0; linie < 4; linie++) {
		for (int coloana = 0; coloana < 4; coloana++) {
			for (int k = 0; k < 8; k++)
				statee[linie][coloana][k] = state[coloana * 32 + linie * 8 + k];
		}
	}
	return statee;
}

vector<vector<vector<bool>>> shift_rows_mix_columns_plus(vector<vector<vector<bool>>> statee) {
	vector<vector<vector<bool>>> nou_statee(4, vector<vector<bool>>(4, vector<bool>(8, 0)));
	vector<bool> zerodoi = { 0,0,0,0,0,0,1,0 }, zerotrei = { 0,0,0,0,0,0,1,1 };
	nou_statee[0][0] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zerodoi, statee[0][0]), inmultire_GF_2_8(zerotrei, statee[1][1])), statee[2][2]), statee[3][3]);
	nou_statee[1][0] = xor_bin_bin(xor_bin_bin(xor_bin_bin(statee[0][0], inmultire_GF_2_8(zerodoi, statee[1][1])), inmultire_GF_2_8(zerotrei, statee[2][2])), statee[3][3]);
	nou_statee[2][0] = xor_bin_bin(xor_bin_bin(xor_bin_bin(statee[0][0], statee[1][1]), inmultire_GF_2_8(zerodoi, statee[2][2])), inmultire_GF_2_8(zerotrei, statee[3][3]));
	nou_statee[3][0] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zerotrei, statee[0][0]), statee[1][1]), statee[2][2]), inmultire_GF_2_8(zerodoi, statee[3][3]));

	nou_statee[0][1] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zerodoi, statee[0][1]), inmultire_GF_2_8(zerotrei, statee[1][2])), statee[2][3]), statee[3][0]);
	nou_statee[1][1] = xor_bin_bin(xor_bin_bin(xor_bin_bin(statee[0][1], inmultire_GF_2_8(zerodoi, statee[1][2])), inmultire_GF_2_8(zerotrei, statee[2][3])), statee[3][0]);
	nou_statee[2][1] = xor_bin_bin(xor_bin_bin(xor_bin_bin(statee[0][1], statee[1][2]), inmultire_GF_2_8(zerodoi, statee[2][3])), inmultire_GF_2_8(zerotrei, statee[3][0]));
	nou_statee[3][1] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zerotrei, statee[0][1]), statee[1][2]), statee[2][3]), inmultire_GF_2_8(zerodoi, statee[3][0]));

	nou_statee[0][2] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zerodoi, statee[0][2]), inmultire_GF_2_8(zerotrei, statee[1][3])), statee[2][0]), statee[3][1]);
	nou_statee[1][2] = xor_bin_bin(xor_bin_bin(xor_bin_bin(statee[0][2], inmultire_GF_2_8(zerodoi, statee[1][3])), inmultire_GF_2_8(zerotrei, statee[2][0])), statee[3][1]);
	nou_statee[2][2] = xor_bin_bin(xor_bin_bin(xor_bin_bin(statee[0][2], statee[1][3]), inmultire_GF_2_8(zerodoi, statee[2][0])), inmultire_GF_2_8(zerotrei, statee[3][1]));
	nou_statee[3][2] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zerotrei, statee[0][2]), statee[1][3]), statee[2][0]), inmultire_GF_2_8(zerodoi, statee[3][1]));

	nou_statee[0][3] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zerodoi, statee[0][3]), inmultire_GF_2_8(zerotrei, statee[1][0])), statee[2][1]), statee[3][2]);
	nou_statee[1][3] = xor_bin_bin(xor_bin_bin(xor_bin_bin(statee[0][3], inmultire_GF_2_8(zerodoi, statee[1][0])), inmultire_GF_2_8(zerotrei, statee[2][1])), statee[3][2]);
	nou_statee[2][3] = xor_bin_bin(xor_bin_bin(xor_bin_bin(statee[0][3], statee[1][0]), inmultire_GF_2_8(zerodoi, statee[2][1])), inmultire_GF_2_8(zerotrei, statee[3][2]));
	nou_statee[3][3] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zerotrei, statee[0][3]), statee[1][0]), statee[2][1]), inmultire_GF_2_8(zerodoi, statee[3][2]));
	return nou_statee;
}

vector<vector<vector<bool>>> add_round_key_plus(vector<vector<vector<bool>>> statee, vector<bool> cheie) {
	vector<vector<bool>> cheie_impartita = impartire_piesa_in_cuvinte(cheie);
	for (int linie = 0; linie < 4; linie++)
		for (int coloana = 0; coloana < 4; coloana++) {
			statee[linie][coloana] = xor_bin_bin(statee[linie][coloana], { cheie_impartita[coloana][linie * 8], cheie_impartita[coloana][linie * 8 + 1], cheie_impartita[coloana][linie * 8 + 2], cheie_impartita[coloana][linie * 8 + 3], cheie_impartita[coloana][linie * 8 + 4], cheie_impartita[coloana][linie * 8 + 5], cheie_impartita[coloana][linie * 8 + 6], cheie_impartita[coloana][linie * 8 + 7] });
		}
	return statee;
}

vector<vector<vector<bool>>> sub_bytes_plus(vector<vector<vector<bool>>> statee) {
	for (int linie = 0; linie < 4; linie++)
		for (int coloana = 0; coloana < 4; coloana++)
			statee[linie][coloana] = substituire_rijndael_pt_cheitza(statee[linie][coloana]);
	return statee;
}

vector<vector<vector<bool>>> shift_rows_plus(vector<vector<vector<bool>>> statee) {
	vector<bool> aux1, aux2, aux3;
	aux1 = statee[1][0];
	statee[1][0] = statee[1][1], statee[1][1] = statee[1][2], statee[1][2] = statee[1][3], statee[1][3] = aux1;
	aux1 = statee[2][0], aux2 = statee[2][1];
	statee[2][0] = statee[2][2], statee[2][1] = statee[2][3], statee[2][2] = aux1, statee[2][3] = aux2;
	aux1 = statee[3][0], aux2 = statee[3][1], aux3 = statee[3][2];
	statee[3][0] = statee[3][3], statee[3][1] = aux1, statee[3][2] = aux2, statee[3][3] = aux3;
	return statee;
}

vector<vector<vector<bool>>> inv_mix_columns_shift_rows_plus(vector<vector<vector<bool>>> statee) {
	vector<vector<vector<bool>>> nou_statee(4, vector<vector<bool>>(4, vector<bool>(8, 0)));

	vector<bool> zeronoua = { 0,0,0,0,1,0,0,1 }, zeroe = { 0,0,0,0,1,1,1,0 }, zerobe = { 0,0,0,0,1,0,1,1 }, zerode = { 0,0,0,0,1,1,0,1 };
	
	nou_statee[0][0] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zeroe, statee[0][0]), inmultire_GF_2_8(zerobe, statee[1][0])), inmultire_GF_2_8(zerode, statee[2][0])), inmultire_GF_2_8(zeronoua, statee[3][0]));
	nou_statee[1][0] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zeronoua, statee[0][3]), inmultire_GF_2_8(zeroe, statee[1][3])), inmultire_GF_2_8(zerobe, statee[2][3])), inmultire_GF_2_8(zerode, statee[3][3]));
	nou_statee[2][0] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zerode, statee[0][2]), inmultire_GF_2_8(zeronoua, statee[1][2])), inmultire_GF_2_8(zeroe, statee[2][2])), inmultire_GF_2_8(zerobe, statee[3][2]));
	nou_statee[3][0] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zerobe, statee[0][1]), inmultire_GF_2_8(zerode, statee[1][1])), inmultire_GF_2_8(zeronoua, statee[2][1])), inmultire_GF_2_8(zeroe, statee[3][1]));

	nou_statee[0][1] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zeroe, statee[0][1]), inmultire_GF_2_8(zerobe, statee[1][1])), inmultire_GF_2_8(zerode, statee[2][1])), inmultire_GF_2_8(zeronoua, statee[3][1]));
	nou_statee[1][1] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zeronoua, statee[0][0]), inmultire_GF_2_8(zeroe, statee[1][0])), inmultire_GF_2_8(zerobe, statee[2][0])), inmultire_GF_2_8(zerode, statee[3][0]));
	nou_statee[2][1] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zerode, statee[0][3]), inmultire_GF_2_8(zeronoua, statee[1][3])), inmultire_GF_2_8(zeroe, statee[2][3])), inmultire_GF_2_8(zerobe, statee[3][3]));
	nou_statee[3][1] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zerobe, statee[0][2]), inmultire_GF_2_8(zerode, statee[1][2])), inmultire_GF_2_8(zeronoua, statee[2][2])), inmultire_GF_2_8(zeroe, statee[3][2]));

	nou_statee[0][2] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zeroe, statee[0][2]), inmultire_GF_2_8(zerobe, statee[1][2])), inmultire_GF_2_8(zerode, statee[2][2])), inmultire_GF_2_8(zeronoua, statee[3][2]));
	nou_statee[1][2] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zeronoua, statee[0][1]), inmultire_GF_2_8(zeroe, statee[1][1])), inmultire_GF_2_8(zerobe, statee[2][1])), inmultire_GF_2_8(zerode, statee[3][1]));
	nou_statee[2][2] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zerode, statee[0][0]), inmultire_GF_2_8(zeronoua, statee[1][0])), inmultire_GF_2_8(zeroe, statee[2][0])), inmultire_GF_2_8(zerobe, statee[3][0]));
	nou_statee[3][2] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zerobe, statee[0][3]), inmultire_GF_2_8(zerode, statee[1][3])), inmultire_GF_2_8(zeronoua, statee[2][3])), inmultire_GF_2_8(zeroe, statee[3][3]));

	nou_statee[0][3] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zeroe, statee[0][3]), inmultire_GF_2_8(zerobe, statee[1][3])), inmultire_GF_2_8(zerode, statee[2][3])), inmultire_GF_2_8(zeronoua, statee[3][3]));
	nou_statee[1][3] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zeronoua, statee[0][2]), inmultire_GF_2_8(zeroe, statee[1][2])), inmultire_GF_2_8(zerobe, statee[2][2])), inmultire_GF_2_8(zerode, statee[3][2]));
	nou_statee[2][3] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zerode, statee[0][1]), inmultire_GF_2_8(zeronoua, statee[1][1])), inmultire_GF_2_8(zeroe, statee[2][1])), inmultire_GF_2_8(zerobe, statee[3][1]));
	nou_statee[3][3] = xor_bin_bin(xor_bin_bin(xor_bin_bin(inmultire_GF_2_8(zerobe, statee[0][0]), inmultire_GF_2_8(zerode, statee[1][0])), inmultire_GF_2_8(zeronoua, statee[2][0])), inmultire_GF_2_8(zeroe, statee[3][0]));
	return nou_statee;
}



void testare() {

	

}
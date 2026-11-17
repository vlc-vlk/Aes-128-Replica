#include <iostream>
#include<fstream>
#include "utils_AES_128.h"
#include "utils.h"
#include <vector>
#include <chrono>
using namespace std;

int main()
{

	ifstream fin_plaintext("plaintext.txt");
	ostringstream buffer_plaintext;
	buffer_plaintext << fin_plaintext.rdbuf();
	string plaintext_str = buffer_plaintext.str();

	ifstream fin_cheie("key.txt");
	ostringstream buffer_cheie;
	buffer_cheie << fin_cheie.rdbuf();
	string cheie_str = buffer_cheie.str();
	vector<bool> plaintext = text_to_bin(plaintext_str);
	vector<bool> cheie = text_to_bin(cheie_str);
	
	if (cheie.size() != 128) {
		cout << "key is not the size of 128 bits";
		return 0;
	}

	bool choice;
	vector<bool> ciphertextt;
	cout << " CHOOSE: FAST(0) OR SLOW(1) AES METHOD   ";
	cin >> choice;
	auto start = chrono::high_resolution_clock::now();
	if (choice == 0) {
		ciphertextt = AES_128_ECB_MODE_PLUS(plaintext, cheie);
	}
	else if (choice == 1) {
		ciphertextt = AES_128_ECB_MODE(plaintext, cheie);
	}

	std::ofstream fout_ciphertext("ciphertext.txt");
	if (fout_ciphertext.is_open()) {
		for (bool valoare : ciphertextt) {
			fout_ciphertext << valoare;
		}
		fout_ciphertext.close();
	}

	vector<bool> decriptaj = DECRIPTARE_AES_128_ECB_MODE(ciphertextt, cheie);

	cout << "The plaintext was encrypted in ciphertext.txt and decrypted in deciphered_plaintext.txt\n";

	auto stop = chrono::high_resolution_clock::now();
	auto durata = chrono::duration_cast<chrono::milliseconds>(stop - start);

	cout << "The process took " << durata;

	ofstream fout_plaintext("deciphered_plaintext.txt");
	if (fout_plaintext.is_open()) {
		fout_plaintext << bin_to_text(decriptaj);
		fout_plaintext.close();
	}
	system("pause");
    return 0;
}


///MERGE
///parte din fisier multipla de 128 biti
/*CRIwqt4+szDbqkNY+I0qbDe3LQz0wiw0SuxBQtAM5TDdMbjCMD/venUDW9BL
PEXODbk6a48oMbAY6DDZsuLbc0uR9cp9hQ0QQGATyyCESq2NSsvhx5zKlLtz
dsnfK5ED5srKjK7Fz4Q38/ttd+stL/9WnDzlJvAo7WBsjI5YJc2gmAYayNfm
CW2lhZE/ZLG0CBD2aPw0W417QYb4cAIOW92jYRiJ4PTsBBHDe8o4JwqaUac6
rqdi833kbyAOV/Y2RMbN0oDb9Rq8uRHvbrqQJaJieaswEtMkgUt3P5Ttgeh7
J+hE6TR0uHot8WzHyAKNbUWHoi/sCa2nQz/iEwyor6*/
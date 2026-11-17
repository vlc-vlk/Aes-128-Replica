#include<string>
#include<iostream>
#include<vector>
#include<cstddef>
#include<map>
#include <sstream>
#include<unordered_map>
#include<algorithm>
#include<numeric>
#include"utils.h"
using namespace std;

bool exista[26];

void binar_plaintext(int x, vector<bool>& biti_plaintext)
{
    bool auxiliar[8];
    auxiliar[7] = x % 2, x /= 2;
    auxiliar[6] = x % 2, x /= 2;
    auxiliar[5] = x % 2, x /= 2;
    auxiliar[4] = x % 2, x /= 2;
    auxiliar[3] = x % 2, x /= 2;
    auxiliar[2] = x % 2, x /= 2;
    auxiliar[1] = x % 2, x /= 2;
    auxiliar[0] = x % 2, x /= 2;

    for (size_t i = 0; i < 8; i++)
        biti_plaintext.push_back(auxiliar[i]);
}

int ret(char x) {
    if (x >= 65 && x <= 90)
        return int(x) - 65 + 10;
    if (x >= 97 && x <= 122)
        return int(x) - 97 + 10;
    if (x >= 48 && x <= 90)
        return int(x) - 48;
}

vector<bool> hex_to_bin(string plaintext) {
    vector<bool>biti_plaintext;
    int v1, v2;
    for (size_t i = 0; i < plaintext.size(); i += 2) {
        v1 = ret(plaintext[i]);
        v2 = ret(plaintext[i + 1]);
        binar_plaintext(v1 * 16 + v2, biti_plaintext);
    }
    return biti_plaintext;
}

int hex_to_dec(string hecs) {
    int rezultat = 0;
    for (size_t i = 0; i < hecs.size(); i++) {
        if (hecs[i] <= 57 && hecs[i] >= 48)
            rezultat += (hecs[i] - 48) * pow(16, hecs.size() - i - 1);
        if (hecs[i] <= 70 && hecs[i] >= 65)
            rezultat += (hecs[i] - 65 + 10) * pow(16, hecs.size() - i - 1);
        if (hecs[i] <= 102 && hecs[i] >= 97)
            rezultat += (hecs[i] - 97 + 10) * pow(16, hecs.size() - i - 1);
    }
    return rezultat;
}

string bin_to_text(vector<bool> ciphertext) {
    string plaintext;
    int x;
    size_t cnt = 0;
    int limita = ciphertext.size();
    while (cnt < limita) {
        x = 0;
        if (cnt + 8 < limita) {
            for (size_t i = cnt; i < cnt + 8; i++)
                if (ciphertext[i] == 1)
                    x = x * 2 + 1;
                else
                    x = x * 2;
            plaintext += char(x);
        }
        else
            break;
        cnt += 8;
    }
    return plaintext;
}

int bin_to_dec(vector<bool> sirag) {
    int rezultat = 0;
    for (size_t i = 0; i < sirag.size(); i++)
        if (sirag[i] == 0)
            rezultat *= 2;
        else
            rezultat *= 2, rezultat++;
    return rezultat;
}

vector<bool> dec_to_bin(int dec) {
    vector<bool> rezultat;
    if (dec == 0)
        rezultat.push_back(0);
    while (dec > 0)
        if (dec % 2 == 0)
            rezultat.push_back(0), dec /= 2;
        else
            rezultat.push_back(1), dec /= 2;
    int dim = rezultat.size();
    for (size_t i = 0; i < dim / 2; i++)
        swap(rezultat[i], rezultat[dim - 1 - i]);
    return rezultat;
}

vector<bool> dec_to_bin_in_8_biti(int dec) {
    vector<bool> rezultat, rezultat_final;
    if (dec == 0)
        rezultat.push_back(0);
    while (dec > 0)
        if (dec % 2 == 0)
            rezultat.push_back(0), dec /= 2;
        else
            rezultat.push_back(1), dec /= 2;
    int dim = rezultat.size();
    for (size_t i = 0; i < dim / 2; i++)
        swap(rezultat[i], rezultat[dim - 1 - i]);
    if (rezultat.size() < 8)
        for (int i = 0; i < 8 - rezultat.size(); i++)
            rezultat_final.push_back(0);
    for (int i = 0; i < rezultat.size(); i++)
        rezultat_final.push_back(rezultat[i]);
    return rezultat_final;
}

vector<bool> dec_to_bin_in_4_biti(int dec) {
    vector<bool> rezultat, rezultat_final;
    if (dec == 0)
        rezultat.push_back(0);
    while (dec > 0)
        if (dec % 2 == 0)
            rezultat.push_back(0), dec /= 2;
        else
            rezultat.push_back(1), dec /= 2;
    int dim = rezultat.size();
    for (size_t i = 0; i < dim / 2; i++)
        swap(rezultat[i], rezultat[dim - 1 - i]);
    if (rezultat.size() < 4)
        for (int i = 0; i < 4 - rezultat.size(); i++)
            rezultat_final.push_back(0);
    for (int i = 0; i < rezultat.size(); i++)
        rezultat_final.push_back(rezultat[i]);
    return rezultat_final;
}

string bin_to_hex(vector<bool> sirag) {
    string rezultat = "";
    for (size_t i = 0; i < sirag.size(); i += 8) {
        int de_bagat = bin_to_dec({ sirag[i], sirag[i + 1], sirag[i + 2], sirag[i + 3], sirag[i + 4], sirag[i + 5], sirag[i + 6], sirag[i + 7] });
        int hex = de_bagat / 16;
        char auxiliar;
        if (hex <= 9)
            auxiliar = hex + '0';
        else
            auxiliar = hex - 10 + 'a';
        rezultat += auxiliar;
        hex = de_bagat % 16;
        if (hex <= 9)
            auxiliar = hex + '0';
        else
            auxiliar = hex - 10 + 'a';
        rezultat += auxiliar;
    }
    return rezultat;
}

vector<bool> xor_bin_bin(vector<bool> v1, vector<bool> v2) {
    vector<bool> fin;
    for (size_t i = 0; i < v1.size() && i < v2.size(); i++)
        if (v1[i] == v2[i])
            fin.push_back(0);
        else
            fin.push_back(1);
    if (v1.size() > v2.size())
        for (size_t i = v2.size() + 1; i < v1.size(); i++)
            fin.push_back(v1[i]);
    if (v2.size() > v1.size())
        for (size_t i = v1.size() + 1; i < v2.size(); i++)
            fin.push_back(v2[i]);
    return fin;
}

vector<bool> repeat_xor_bin_bin(vector<bool> mare, vector<bool> mic) {
    if (mic.size() > mare.size())
        swap(mic, mare);
    vector<bool> fin;
    size_t cnt = 0;
    bool terminat = 0;
    while (terminat == false) {
        for (size_t i_mare = cnt, i_mic = 0; i_mic < mic.size() && i_mare < mare.size(); i_mare++, i_mic++) {
            fin.push_back(mare[i_mare] != mic[i_mic]);
            cnt = i_mare;
        }
        cnt++;
        if (cnt >= mare.size())
            return fin;
    }
    return fin;
}

vector<bool> text_to_bin(string text) {
    bool auxiliar[8];
    int x;
    vector<bool> fin;
    for (size_t i = 0; i < text.size(); i++) {
        x = int(text[i]);
        auxiliar[7] = x % 2, x /= 2;
        auxiliar[6] = x % 2, x /= 2;
        auxiliar[5] = x % 2, x /= 2;
        auxiliar[4] = x % 2, x /= 2;
        auxiliar[3] = x % 2, x /= 2;
        auxiliar[2] = x % 2, x /= 2;
        auxiliar[1] = x % 2, x /= 2;
        auxiliar[0] = x % 2, x /= 2;
        for (size_t j = 0; j < 8; j++)
            fin.push_back(auxiliar[j]);
    }
    return fin;
}

vector<double> frecventa_caractere(string text) {
    vector<double> frecventa_caractere;
    map<int, double> mapa;
    double caractere_considerate = 0;
    for (size_t i = 0; i < text.size(); i++) {
        if ((text[i] >= 65 && text[i] <= 90) || (text[i] >= 97 && text[i] <= 122)) {
            caractere_considerate++;
            if (text[i] >= 65 && text[i] <= 90)
                mapa[int(text[i])]++, exista[int(text[i]) - 65] = true;
            else
                mapa[int(text[i] - 32)]++, exista[int(text[i]) - 97] = true;
        }
    }
    for (int i = 65; i <= 90; i++)
        if (mapa[i] != 0.0)
            frecventa_caractere.push_back(mapa[i] / caractere_considerate);
        else
            frecventa_caractere.push_back(0.0);
    return frecventa_caractere;
}

double scor_text(vector<bool> candidat) {

    vector<double> frecvente_candidat;
    string text = bin_to_text(candidat);
    double frecventa_altele = 0.0;
    vector<double> frecventa_caractere;
    map<int, double> mapa;
    double caractere_considerate = 0;
    for (size_t i = 0; i < text.size(); i++) {
        if ((text[i] >= 65 && text[i] <= 90) || (text[i] >= 97 && text[i] <= 122)) {
            caractere_considerate++;
            if (text[i] >= 65 && text[i] <= 90)
                mapa[int(text[i])]++, exista[int(text[i]) - 65] = true;
            else
                mapa[int(text[i] - 32)]++, exista[int(text[i]) - 97] = true;
        }
        else if ((text[i] >= 32 && text[i] <= 64) || (text[i] >= 91 && text[i] <= 96) || (text[i] >= 123 && text[i] <= 126))
            frecventa_altele++;
        else {
            return static_cast<double>(candidat.size() / 8);
        }
    }
    for (int i = 65; i <= 90; i++)
        if (mapa[i] != 0.0)
            frecvente_candidat.push_back(mapa[i] / caractere_considerate);
        else
            frecvente_candidat.push_back(0.0);
    frecventa_altele /= text.size();

    double standard[26];
    standard[0] = 0.0831174, standard[1] = 0.0131433, standard[2] = 0.0286931, standard[3] = 0.0427619, standard[4] = 0.133469, standard[5] = 0.0257312, standard[6] = 0.0257312, standard[7] = 0.0533136;
    standard[8] = 0.0775639, standard[9] = 0.00129582, standard[10] = 0.00351722, standard[11] = 0.0360977, standard[12] = 0.0309145, standard[13] = 0.0708997, standard[14] = 0.0677527, standard[15] = 0.0166605;
    standard[16] = 0.00166605, standard[17] = 0.0620141, standard[18] = 0.0620141, standard[19] = 0.0845983, standard[20] = 0.0249907, standard[21] = 0.0148093, standard[22] = 0.017401;
    standard[23] = 0.00203628, standard[24] = 0.0262866, standard[25] = 0.0007474;
    bool exista[26];
    double scor_text = 0, acu;

    for (int i = 0; i < 26; i++) {
        if (frecvente_candidat[i] != 0.0) {
            acu = standard[i] - frecvente_candidat[i];
            if (acu < 0)
                acu *= (-1);
            scor_text += acu;
        }
    }
    scor_text += frecventa_altele;
    return scor_text;
}

int hamming_distance_text(string x, string y) {
    int edit_distance = 0;
    vector<bool> bx = text_to_bin(x);
    vector<bool> by = text_to_bin(y);
    for (size_t i = 0; i < bx.size() && i < by.size(); i++)
        if (bx[i] != by[i])
            edit_distance++;
    if (bx.size() > by.size())
        edit_distance += bx.size() - by.size();
    if (by.size() > bx.size())
        edit_distance += by.size() - bx.size();
    return edit_distance;
}

int hamming_distance_bin(vector<bool> bx, vector<bool> by) {
    int edit_distance = 0;
    for (size_t i = 0; i < bx.size() && i < by.size(); i++)
        if (bx[i] != by[i])
            edit_distance++;
    if (bx.size() > by.size())
        edit_distance += bx.size() - by.size();
    if (by.size() > bx.size())
        edit_distance += by.size() - bx.size();
    return edit_distance;
}

int hamming_distance_bytes(vector<bool> bx, vector<bool> by) {
    int hamming_distance_bytes = 0;
    for (size_t i = 0; i < bx.size() && i < by.size(); i += 8) {
        vector<bool> BX, BY;
        for (int j = i; j < i + 8; j++)
            BX.push_back(bx[j]), BY.push_back(by[j]);
        if (hamming_distance_bin(BX, BY) != 0)
            hamming_distance_bytes++;
    }
    return hamming_distance_bytes;
}

string base64_encode(vector<bool> binary_data) {
    string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    vector<unsigned char> bytes;
    for (size_t k = 0; k < binary_data.size(); k += 8) {
        unsigned char byte = 0;
        for (int b = 0; b < 8 && (k + b) < binary_data.size(); b++) {
            if (binary_data[k + b]) {
                byte |= (1 << (7 - b));
            }
        }
        bytes.push_back(byte);
    }

    for (size_t n = 0; n < bytes.size(); n++) {
        char_array_3[i++] = bytes[n];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++) {
                ret += base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i > 0) {
        for (j = i; j < 3; j++) {
            char_array_3[j] = 0;
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0)) >> 4;
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0)) >> 6;
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; j < i + 1; j++) {
            ret += base64_chars[char_array_4[j]];
        }

        while (i++ < 3) {
            ret += '=';
        }
    }

    return ret;

}

vector<bool> VECHI_base64_decode(string base_64) {
    vector<bool> rezultat;
    vector<bool> aux;
    for (size_t i = 0; i < base_64.size(); i++) {
        vector<bool> aux;
        if (base_64[i] != '=') {
            if (int(base_64[i]) >= 65 && int(base_64[i]) <= 90) {
                aux = dec_to_bin(int(base_64[i]) - 65);
            }
            else if (int(base_64[i]) >= 97 && int(base_64[i]) <= 122) {
                aux = dec_to_bin(int(base_64[i]) - 97 + 26);
            }
            else if (int(base_64[i]) >= 48 && int(base_64[i]) <= 57)
                aux = dec_to_bin(int(base_64[i]) - 48 + 52);
            else if (base_64[i] == '+')
                aux = dec_to_bin(62);
            else if (base_64[i] == '/')
                aux = dec_to_bin(63);

            if (aux.size() < 6)
                for (size_t j = 0; j < 6 - aux.size(); j++)
                    rezultat.push_back(0);
            for (size_t j = 0; j < aux.size(); j++)
                rezultat.push_back(aux[j]);
        }
    }
    return rezultat;
}

vector<bool> base64_decode(string input) {
    string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::vector<int> decodeTable(256, -1);
    for (size_t i = 0; i < 64; i++) {
        decodeTable[static_cast<unsigned char>(base64_chars[i])] = i;
    }

    std::string output;
    output.reserve(((input.size() + 3) / 4) * 3);

    int bitsCollected = 0;
    unsigned int accumulator = 0;

    for (unsigned char c : input) {
        if (c == '=') { break; }

        if (c == '\n') { continue; }

        int decodedValue = (c < 256) ? decodeTable[c] : -1;
        if (decodedValue == -1) { continue; }

        accumulator = (accumulator << 6) | decodedValue;
        bitsCollected += 6;

        if (bitsCollected >= 8) {
            bitsCollected -= 8;
            unsigned char byte = static_cast<unsigned char>((accumulator >> bitsCollected) & 0xFF);
            output.push_back(byte);
        }
    }
    return text_to_bin(output);
}

int best_keysize(vector<bool> binar) {
    double min_dist;
    int dim_cheie;
    for (size_t i = 1; i <= binar.size() / 16; i++) {
        vector<bool> bl1, bl2;
        for (int j = 0; j < i * 8; j++)
            bl1.push_back(binar[j]), bl2.push_back(binar[j + i * 8]);
        int dist = hamming_distance_bin(bl1, bl2);
        double dist_normal = double(dist) / i;
        if (i == 1)
            min_dist = dist_normal, dim_cheie = i;
        else if (dist_normal < min_dist)
            min_dist = dist_normal, dim_cheie = i;
    }
    return dim_cheie;
}

int best_keysize_2(vector<bool> binar) {
    int best_keysize_2, min_dist;
    bool luat = false;
    for (int i = 1; i <= 40 && i <= binar.size() / 8 / 6; i++) {
        vector<bool> b1, b2, b3, b4, b5, b6;
        for (int j = 0; j < i * 8; j++) {
            b1.push_back(binar[j]);
            b2.push_back(binar[j + i * 8]);
            b3.push_back(binar[j + (2 * i) * 8]);
            b4.push_back(binar[j + (3 * i) * 8]);
            b5.push_back(binar[j + (4 * i) * 8]);
            b6.push_back(binar[j + (5 * i) * 8]);
        }

        double dist_normal = 0;
        dist_normal += hamming_distance_bin(b1, b2);
        dist_normal += hamming_distance_bin(b1, b3);
        dist_normal += hamming_distance_bin(b1, b4);
        dist_normal += hamming_distance_bin(b1, b5);
        dist_normal += hamming_distance_bin(b1, b6);
        dist_normal += hamming_distance_bin(b2, b3);
        dist_normal += hamming_distance_bin(b2, b4);
        dist_normal += hamming_distance_bin(b2, b5);
        dist_normal += hamming_distance_bin(b2, b6);
        dist_normal += hamming_distance_bin(b3, b4);
        dist_normal += hamming_distance_bin(b3, b5);
        dist_normal += hamming_distance_bin(b3, b6);
        dist_normal += hamming_distance_bin(b4, b5);
        dist_normal += hamming_distance_bin(b4, b6);
        dist_normal += hamming_distance_bin(b6, b5);
        dist_normal /= (14 * i);
        if (luat == false)
            luat = true, min_dist = dist_normal, best_keysize_2 = i;
        else if (dist_normal < min_dist)
            best_keysize_2 = i, min_dist = dist_normal;
        cout << "KEYSIZE: " << i << " SCOR: " << dist_normal << endl;
    }
    return best_keysize_2;
}

vector<vector<bool>> transpozare(int keysize, vector<bool> binar) {
    vector<vector<bool>> T(keysize);
    for (int k = 0; k < keysize; k++)
        for (int i = k * 8; i + 7 < binar.size(); i += keysize * 8)
            for (int j = i; j < i + 8 && j < binar.size(); j++)
                T[k].push_back(binar[j]);
    return T;
}

int best_repeat_chr_xor_candid(vector<bool> binar) {
    double scor_minim;
    char cheie;
    bool luat = false;
    vector<bool> bin_cel_mai_bun_candidat;
    for (int i = 0; i <= 127; i++) {
        char hasmocar = i;
        string candidat_chr(1, hasmocar);
        vector<bool> candidat = repeat_xor_bin_bin(text_to_bin(candidat_chr), binar);
        double scor_candidat = scor_text(candidat);
        if (luat == false)
            luat = true, scor_minim = scor_candidat, cheie = i, bin_cel_mai_bun_candidat = candidat;
        else
            if (scor_candidat < scor_minim)
                scor_minim = scor_candidat, cheie = i, bin_cel_mai_bun_candidat = candidat;
    }
    return int(cheie);
}

pair<vector<int>, int> aparitii_caractere_spec(vector<bool> x) {
    vector<int> v(26, 0);
    int nr_litere = 0;
    for (size_t i = 0; i + 7 < x.size(); i += 8) {
        int dec = bin_to_dec({ x[i],  x[i + 1], x[i + 2],  x[i + 3], x[i + 4],  x[i + 5], x[i + 6],  x[i + 7] });
        if (dec >= 65 && dec <= 90)
            v[dec - 65]++, nr_litere++;
        if (dec >= 97 && dec <= 122)
            v[dec - 97]++, nr_litere++;
    }
    return (make_pair(v, nr_litere));
}

double medie_coincidente_bin_raw(int keysize, vector<bool> binar) {
    double coeficient_coincidenta_bloc;
    double medie_coeficienti_blocuri = 0;
    int cnt, caracter;
    double nr_litere;
    vector<bool> bait(8);

    for (int k = 0; k < keysize; k++) {
        nr_litere = 0;
        vector<double> C(26, 0);
        for (int i = k * 8; i + 7 < binar.size(); i += keysize * 8) {
            cnt = 0;
            for (int j = i; j < i + 8 && j < binar.size(); j++) {
                bait[cnt] = binar[j], cnt++;
            }
            caracter = bin_to_dec(bait);
            if (caracter >= 65 && caracter <= 90)
                nr_litere++, C[caracter - 65]++;
            else if (caracter >= 97 && caracter <= 122)
                nr_litere++, C[caracter - 97]++;
        }
        coeficient_coincidenta_bloc = 0;
        for (size_t i = 0; i < C.size(); i++) {
            if (C[i] != 0 && C[i] > 1)
                coeficient_coincidenta_bloc += (C[i] / nr_litere) * ((C[i] - 1) / (nr_litere - 1));
            else if (C[i] == 1)
                coeficient_coincidenta_bloc += (C[i] / nr_litere) * (C[i] / (nr_litere - 1));
        }
        medie_coeficienti_blocuri += coeficient_coincidenta_bloc;
    }
    medie_coeficienti_blocuri /= keysize;
    return medie_coeficienti_blocuri;
}

void scor_sparg_dim_cheie(int keysize, vector<bool> binar) {
    double scor_maxim = 0;
    vector<vector<bool>> T(keysize);
    vector<bool> cheie;
    for (int k = 0; k < keysize; k++)
        for (int i = k * 8; i + 7 < binar.size(); i += keysize * 8)
            for (int j = i; j < i + 8; j++)
                T[k].push_back(binar[j]);
    for (size_t i = 0; i < T.size(); i++) {
        int bait_cheie = best_repeat_chr_xor_candid(T[i]);
        cout << "BAIT CHEIE: " << bait_cheie << endl;
        vector<bool> aux = dec_to_bin(bait_cheie);
        for (size_t j = 0; j < aux.size(); j++)
            cheie.push_back(aux[j]);
    }
    cout << cheie.size();
    cout << bin_to_text(cheie);
}

double scor_text_alternativ(vector<bool> candidat) {

    vector<double> frecvente_candidat(26, 0.0);
    string text = bin_to_text(candidat);
    double frecventa_altele = 0.0;
    map<int, double> mapa;
    mapa[25] = 0.0;
    double caractere_considerate = 0;
    for (size_t i = 0; i < text.size(); i++) {
        if ((text[i] >= 65 && text[i] <= 90) || (text[i] >= 97 && text[i] <= 122)) {
            caractere_considerate++;
            if (text[i] >= 65 && text[i] <= 90)
                mapa[int(text[i]) - 65]++;
            else
                mapa[int(text[i] - 97)]++;
        }
        else if ((text[i] >= 33 && text[i] <= 64) || (text[i] >= 91 && text[i] <= 96) || (text[i] >= 123 && text[i] <= 126) || text[i] == 10 || text[i] == 13 || text[i] == 9 || text[i] == 11)
            frecventa_altele++;
        else if (text[i] == 32)
            mapa[25]++;
        else
            return candidat.size() / 8;
    }
    for (int i = 0; i < 26; i++)
        if (mapa[i] != 0.0)
            frecvente_candidat[i] = mapa[i] / caractere_considerate;
        else
            frecvente_candidat[i] = 0.0;
    frecventa_altele /= text.size();
    ////////////////////////////////////]
    double standard[27];
    standard[0] = 0.0831174, standard[1] = 0.0131433, standard[2] = 0.0286931, standard[3] = 0.0427619, standard[4] = 0.133469, standard[5] = 0.0257312, standard[6] = 0.0257312, standard[7] = 0.0533136;
    standard[8] = 0.0775639, standard[9] = 0.00129582, standard[10] = 0.00351722, standard[11] = 0.0360977, standard[12] = 0.0309145, standard[13] = 0.0708997, standard[14] = 0.0677527, standard[15] = 0.0166605;
    standard[16] = 0.00166605, standard[17] = 0.0620141, standard[18] = 0.0620141, standard[19] = 0.0845983, standard[20] = 0.0249907, standard[21] = 0.0148093, standard[22] = 0.017401;
    standard[23] = 0.00203628, standard[24] = 0.0262866, standard[25] = 0.18;

    double scor_text = 0, acu;
    for (int i = 0; i < 26; i++) {
        if (frecvente_candidat[i] != 0.0) {
            acu = standard[i] - frecvente_candidat[i];
            if (acu < 0)
                acu *= (-1);
            scor_text += acu;
        }
    }
    scor_text += frecventa_altele;
    return scor_text;
}

double scor_vectori(vector<bool> candidat) {

    vector<double> frecvente_candidat(26, 0.0);
    string text = bin_to_text(candidat);
    double frecventa_altele = 0.0;
    map<int, double> mapa;
    mapa[25] = 0.0;
    double caractere_considerate = 0;
    for (size_t i = 0; i < text.size(); i++) {
        if ((text[i] >= 65 && text[i] <= 90) || (text[i] >= 97 && text[i] <= 122)) {
            caractere_considerate++;
            if (text[i] >= 65 && text[i] <= 90)
                mapa[int(text[i]) - 65]++;
            else
                mapa[int(text[i] - 97)]++;
        }
        else if ((text[i] >= 33 && text[i] <= 64) || (text[i] >= 91 && text[i] <= 96) || (text[i] >= 123 && text[i] <= 126) || text[i] == 10 || text[i] == 13 || text[i] == 9 || text[i] == 11)
            frecventa_altele++;
        else if (text[i] == 32)
            mapa[25]++;
    }
    for (int i = 0; i < 26; i++)
        if (mapa[i] != 0.0)
            frecvente_candidat[i] = mapa[i] / caractere_considerate;
        else
            frecvente_candidat[i] = 0.0;
    frecventa_altele /= text.size();
    ////////////////////////////////////]
    double standard[27];
    standard[0] = 0.0831174, standard[1] = 0.0131433, standard[2] = 0.0286931, standard[3] = 0.0427619, standard[4] = 0.133469, standard[5] = 0.0257312, standard[6] = 0.0257312, standard[7] = 0.0533136;
    standard[8] = 0.0775639, standard[9] = 0.00129582, standard[10] = 0.00351722, standard[11] = 0.0360977, standard[12] = 0.0309145, standard[13] = 0.0708997, standard[14] = 0.0677527, standard[15] = 0.0166605;
    standard[16] = 0.00166605, standard[17] = 0.0620141, standard[18] = 0.0620141, standard[19] = 0.0845983, standard[20] = 0.0249907, standard[21] = 0.0148093, standard[22] = 0.017401;
    standard[23] = 0.00203628, standard[24] = 0.0262866, standard[25] = 0.18;

    double scor_text = 0, acu;
    for (int i = 0; i < 26; i++) {
        scor_text *= standard[i] * frecvente_candidat[i];
    }
    scor_text += frecventa_altele;
    return scor_text;
}

int gaseste_keysize(vector<bool> binar) {
    int coinc = 0, prim, doi, keysize = 1;
    bool gresit = false;
    double medie = 0;
    int cei_mai_mari[2], cele_mai_mari_coinc[2];
    cei_mai_mari[0] = 0, cei_mai_mari[1] = 0, cele_mai_mari_coinc[0] = 0, cele_mai_mari_coinc[1] = 0;
    while (keysize < binar.size() / 8) {
        keysize++;
        prim = 0, doi = keysize * 8;
        gresit = false;
        coinc = 0;
        while (doi + 8 < binar.size()) {
            gresit = false;
            for (size_t i = 0; i < 8; i++) {
                if (binar[prim + i] != binar[doi + i]) {
                    gresit = true;
                    break;
                }
            }
            prim += 8, doi += 8;
            if (gresit == false)
                coinc++;
        }
        if (keysize == 40)
            break;
        if (cele_mai_mari_coinc[1] < coinc) {
            cele_mai_mari_coinc[0] = cele_mai_mari_coinc[1], cele_mai_mari_coinc[1] = coinc;
            cei_mai_mari[0] = cei_mai_mari[1], cei_mai_mari[1] = keysize;
        }
    }
    if (cele_mai_mari_coinc[1] > 2 * cele_mai_mari_coinc[0])
        return cei_mai_mari[1];
    if (cei_mai_mari[0] < cei_mai_mari[1])
        return cei_mai_mari[0];
    else
        return cei_mai_mari[1];
}
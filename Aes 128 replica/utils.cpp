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

vector<vector<bool>> transpozare(int keysize, vector<bool> binar) {
    vector<vector<bool>> T(keysize);
    for (int k = 0; k < keysize; k++)
        for (int i = k * 8; i + 7 < binar.size(); i += keysize * 8)
            for (int j = i; j < i + 8 && j < binar.size(); j++)
                T[k].push_back(binar[j]);
    return T;
}



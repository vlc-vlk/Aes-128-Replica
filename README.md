# Aes 128 replica
# Welcome!
This is a replica of the famous AES-128 cipher. It is entirely home-made, from the conversion functions between datatypes to the assembled cipher, and pads using the PKCS7 standard.  
It is made in C++, and implements 2 methods as follows:  
The slow method has the mix rows and shift columns as separate steps.  
The fast method combines mix rows and shift columns in one single step.  

## Structure:
utils has elementary data-manipulation and datatype-conversion functions  
utils_AES has the functions AES needs for data manipulation and the 4 steps for each round  
cipher_methods has the cipher put altogether, the fast and the slow method  
main has the CLI logic and file manipulation  
plaintext.txt has the plaintext, key.txt has the key, ciphertext.txt is where the ciphertext will be written and deciphered_plaintext.txt is where the program writes the deciphered text (delete it's contents before executing to see that the program works as intended)

## Performance:
For a large file (size of 1,23 MB) the program executes the fast method in 5388403ms and the slow method in 641139ms. This gives a 16,0239.% increase in time-efficiency :)
Keep in mind that it is designed to work only with 128-bit keys (16 characters), from the name "AES-128".

## To run the program quickly from the exe:
1. Go to the [Releases](https://github.com/vlc-vlk/Aes-128-Replica/releases/tag/v1.00) page.
2. Download the `.zip` archive.
3. Extract the files and double-click the `.exe` file to launch the CLI menu.  
The plaintext.txt and key.txt files have by default a key and some text to encipher, but I encourage you to enter any text and any 128-bit key (16 characters).

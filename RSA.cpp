/* Integer arithmatics*/
#include <cryptopp/integer.h>
using CryptoPP::Integer;

#include <cryptopp/nbtheory.h>
using CryptoPP::ModularSquareRoot;
using CryptoPP::PrimeAndGenerator;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/modarith.h>
using CryptoPP::ModularArithmetic;;

#include <iostream>
using namespace std;

#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

// integer to string, wstring
#include <sstream>
using std::ostringstream;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

// byte delete in stdin after wcin on window
#define DISCARD 2

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

//Funtion

//Support Vietnamese
void setUpVietnamese()
{
#ifdef _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
	_setmode(_fileno(stdout), _O_U16TEXT);
#elif __linux__
	setlocale(LC_ALL, "");
#endif
}

//integer to wstring
wstring integer_to_wstring (const CryptoPP::Integer& t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;
    std::string encoded(oss.str());
    std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(encoded);
}

//integer to string
string integer_to_string (const CryptoPP::Integer& t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;
    std::string encoded(oss.str());
    return encoded;
}

//string to wstring
wstring s2ws(const std::string &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}
// wstring to string
string ws2s(const std::wstring &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}

// plain text from screen and save in var plain(string)
void InputPlainFromScreen(string &plain)
{
    //plaintext from keyboard
    wstring wplain;
    wplain.clear();
    // check plaintext
    int tmp = 0;
    do
    {
        if (tmp)
            wcout << "Input too long! Please input again: ";
        else
            wcout << "Please input plaintext: ";
        // delete '\n' in stdin
        wcin.ignore(DISCARD - tmp);
        // input
        getline(wcin, wplain);
        tmp = 1;
    } while (wplain.length() > 342);

    // convert wplain(wstring) to plain(string)
    plain = ws2s(wplain);
}

// cipher text from screen and save in var cipher(string)
void InputCipherFromScreen(string &cipher)
{
    //ciphertext from keyboard
    wstring wcipher;
    wcipher.clear();
    // check ciphertext
    wcout << "Please input ciphertext (hex number): ";
    // delete'\n' in stdin
    wcin.ignore(DISCARD);
    // input
    getline(wcin, wcipher);
    // convert wcipher(wstring) to cipher(string)
    string hexCipher = ws2s(wcipher);
    // convert cipher from hex string to ascii string
    cipher.clear();
    StringSource(hexCipher, true, new HexDecoder(new StringSink(cipher)));
}

// Read key from file
template <typename T>
void ReadKeyFromFile(T &key, const string &filename)
{
    FileSource fs(filename.c_str(), true);
    key.BERDecode(fs);
}

// RSA encryption
void RSA_Encryption(const string &plain, string &cipher, RSA::PublicKey publicKey)
{
    AutoSeededRandomPool rng;
        RSAES_OAEP_SHA_Encryptor e(publicKey);
        cipher.clear();
        StringSource(plain, true,
                     new PK_EncryptorFilter(rng, e,
                                            new StringSink(cipher)));
}

// RSA decryption
void RSA_Decryption(const string &cipher, string &recovered, RSA::PrivateKey privateKey)
{
    AutoSeededRandomPool rng;
        RSAES_OAEP_SHA_Decryptor d(privateKey);
        recovered.clear();
        StringSource(cipher, true,
                     new PK_DecryptorFilter(rng, d,
                                            new StringSink(recovered)));
}

//Encrypt
void Encrypt()
{
    clock_t start, end;
        string plain, encoded, cipher;
        RSA::PublicKey publicKey;
        int choice;
        wcout << "---------------------" << endl;
        wcout << "Select plaintext: " << endl;
        wcout << "1. From file" << endl;
        wcout << "2. From console" << endl;
        wcout << "Your choice: ";
        wcin >> choice;
        switch (choice)
        {
        case 1:
            plain.clear();
            int choice_size;
            wcout << "---------------------" << endl;
            wcout << "Select size: " << endl;
            wcout << "1. 100 Bytes" << endl;
            wcout << "2. 200 Bytes" << endl;
            wcout << "3. 300 Bytes" << endl;
            wcout << "Your choice: " << endl;
            wcin >> choice_size;
            switch (choice_size)
            {
            case 1:
                plain.clear();
                FileSource("testcase_RSA_100B.txt", true, new StringSink(plain));
                break;
            case 2:
                plain.clear();
                FileSource("testcase_RSA_200B.txt", true, new StringSink(plain));
                break;
            case 3:
                plain.clear();
                FileSource("testcase_RSA_300B.txt", true, new StringSink(plain));
                break;
            default:
                break;
            }
            break;
        case 2:
            InputPlainFromScreen(plain);
            break;
        default:
            break;
        }
        ReadKeyFromFile<RSA::PublicKey>(publicKey, "rsa-public.bin");
        wcout << "---------------------" << endl;
        wcout << "Plain text size: " << plain.length() << endl;
        wcout << "Plain text: " << s2ws(plain) << endl;
        wcout << "RSA key size: " << integer_to_wstring(publicKey.GetModulus().BitCount()) << endl;
        wcout << "Public modulo n: " << integer_to_wstring(publicKey.GetModulus()) << endl;
        wcout << "Public key e: " << integer_to_wstring(publicKey.GetPublicExponent()) << endl;
        wcout << "---------------------" << endl;
        // encrypt time
        start = clock();
        for (int i = 0; i < 10000; ++i)
            RSA_Encryption(plain, cipher, publicKey);
        end = clock();
        // convert to hex
        encoded.clear();
        StringSource(cipher, true, new HexEncoder(new StringSink(encoded)));
        wcout << "cipher text:" << s2ws(encoded) << endl;
        // time encrypt 10000
        wcout << "Time for encryption (10 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
        // save cipher text to file ciphertext.txt
        StringSource(cipher, true, new FileSink("ciphertext.txt"));
}

//Decrypt
void Decrypt()
{
    clock_t start, end;
        string cipher, encoded, recovered;
        RSA::PrivateKey privateKey;
        RSA::PublicKey publicKey;
        int choice;
        wcout << "---------------------" << endl;
        wcout << "Select ciphertext: " << endl;
        wcout << "1. From file ciphertext.txt" << endl;
        wcout << "2. From console" << endl;
        wcout << "Your choice: ";
        wcin >> choice;
        switch (choice)
        {
        case 1:
            cipher.clear();
            FileSource("ciphertext.txt", true, new StringSink(cipher));
            break;
        case 2:
            InputCipherFromScreen(cipher);
            break;
        default:
            break;
        }
        ReadKeyFromFile<RSA::PrivateKey>(privateKey, "rsa-private.bin");
        ReadKeyFromFile<RSA::PublicKey>(publicKey, "rsa-public.bin");
        // convert cipher to hex 
        StringSource(cipher, true, new HexEncoder(new StringSink(encoded)));
        wcout << "---------------------" << endl;
        wcout << "cipher text size: " << cipher.length() << endl;
        wcout << "cipher text: " << s2ws(encoded) << endl;
        wcout << "RSA key size: " << integer_to_wstring(publicKey.GetModulus().BitCount()) << endl;
        wcout << "Public modulo n: " << integer_to_wstring(publicKey.GetModulus()) << endl;
        wcout << "Public key e: " << integer_to_wstring(publicKey.GetPublicExponent()) << endl;
        wcout << "Private prime number p: " << integer_to_wstring(privateKey.GetPrime1()) << endl;
        wcout << "Private prime number q: " << integer_to_wstring(privateKey.GetPrime2()) << endl;
        wcout << "Secret key d: " << integer_to_wstring(privateKey.GetPrivateExponent()) << endl;
        wcout << "---------------------" << endl;
        // decrypt time
        start = clock();
        for (int i = 0; i < 10000; ++i)
            RSA_Decryption(cipher, recovered, privateKey);
        end = clock();
        wcout << "recover text: " << s2ws(recovered) << endl;
        // time encrypt 10000 
        wcout << "Time for decryption (10 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
}

int main()
{
    setUpVietnamese();

    int choice;
    wcout << "RSA Cipher using Cryptopp" << endl;
    wcout << "--------------------------" << endl;
    while (true)
    {
        wcout << "Select: " << endl;
        wcout << "1. Encrypt" << endl;
        wcout << "2. Decrypt" << endl;
        wcout << "3. Exit" << endl;
        wcout << "Your choice: ";
        wcin >> choice;

        switch(choice)
        {
            case 1:
                Encrypt();
                break;
            case 2:
                Decrypt();
                break;
            case 3:
                wcout << "Exit";
                return 0;
            default:
                wcout << "Invalid";
                exit(1);
                break;
        }
    }
    return 0;
}
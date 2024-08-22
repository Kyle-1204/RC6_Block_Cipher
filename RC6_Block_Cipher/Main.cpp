#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <string>
#include "RC6.h"
using namespace std;

int main(int argc, char * argv[]){
    if (argc != 3){
        cout << "Input format is : ./main <input file> <output file>" << endl;
        return 0;
    }
    string mode, origText, text, userkey, result;
    int beforeInput;
    unsigned int keyLength;
    ifstream inputFile;
    inputFile.open(argv[1]);
    ofstream outputFile(argv[2]);
    getline(inputFile, mode);

    if (mode == "Encryption\r" || mode == "Encryption\n" || mode == "Encryption"){
        beforeInput = 11;
        getline(inputFile, origText);
        getline(inputFile, userkey);
        text = origText.substr(beforeInput, origText.length());
        text.erase(remove_if(text.begin(), text.end(), ::isspace), text.end());
        userkey = userkey.substr(9, userkey.length());
        userkey.erase(remove_if(userkey.begin(), userkey.end(), ::isspace), userkey.end());
        unsigned int keyLength = userkey.length()/2;
        RC6 *rc6 = new RC6(32, 20, keyLength);
        result = rc6->cipher(userkey, text, "Encryption");
        while (origText.length() - beforeInput > result.length()) result = "00 " + result;
        outputFile << "Ciphertext: " << result;
        outputFile.close();
    }
    else if (mode == "Decryption\r"|| mode == "Decryption\n" || mode == "Decryption"){
        beforeInput = 12;
        getline(inputFile, origText);
        getline(inputFile, userkey);
        text = origText.substr(beforeInput, origText.length());
        text.erase(remove_if(text.begin(), text.end(), ::isspace), text.end());
        userkey = userkey.substr(9, userkey.length());
        userkey.erase(remove_if(userkey.begin(), userkey.end(), ::isspace), userkey.end());
        keyLength = userkey.length()/2;
        RC6 *rc6 = new RC6(32, 20, keyLength);
        result = rc6->cipher(userkey, text, "Decryption");
        while (origText.length() - beforeInput > result.length()) result = "00 " + result;
        outputFile << "Plaintext: " << result;
        outputFile.close();
    }
    else{
        cout << "Check Input file for Encryption/Decryption Mode" << endl;
        return 0;
    }
    //cout << origText.length() << endl;
    //cout << result.length() << endl;
    //cout << result << endl;
    return 0;
}

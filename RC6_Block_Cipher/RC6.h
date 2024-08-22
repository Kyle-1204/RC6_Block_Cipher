#ifndef RC6_H
#define RC6_H

#include <iostream>
#include <sstream>
#include <iomanip>
using namespace std;

class RC6{
private:
	unsigned int w, r, b, log_w; //mod;  
	int64_t mod;
	string mode, text, key;
	unsigned int *S;
	unsigned int *L;
	void keyGen(string key);
	string encrypt(string input);
	string decrypt(string input);
	int rotl(unsigned int, unsigned int, unsigned int);
	int rotr(unsigned int, unsigned int, unsigned int);
	string little_endian(string input);
	string hex_to_string(unsigned int A, unsigned int B, unsigned int C, unsigned int D);

public:
	RC6(unsigned int W, unsigned int R, unsigned int B);
	string cipher(string userkey, string input, string mode);
	~RC6();
};

#endif
#include "RC6.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include "math.h"
using namespace std;

RC6::RC6(unsigned int W, unsigned int R, unsigned int B){
    w = W;
    r = R;
	b = B;
	log_w = (unsigned int) log2(w);
	mod = pow(2, w);
	S = new unsigned int[2 * r + 4];
}

RC6::~RC6(){
	delete S;
}

int RC6::rotl(unsigned int a, unsigned int b, unsigned int w){
	b <<= w - log_w;
	b >>= w - log_w;
	return (a << b) | (a >> (w - b));
}

int RC6::rotr(unsigned int a, unsigned int b, unsigned int w){
	b <<= w - log_w;
	b >>= w - log_w;
	return (a >> b) | (a << (w - b));
}

string RC6::little_endian(string str){
	string endian;
	if(str.length() % 2 == 0){
		for(reverse_iterator r_it = str.rbegin();r_it != str.rend();r_it = r_it + 2){
			endian.push_back(*(r_it+1));
			endian.push_back(*r_it);
		}
	 }
  else{
	str = "0" + str;
	for(std::string::reverse_iterator r_it = str.rbegin(); r_it != str.rend();r_it = r_it + 2){
		endian.push_back(*(r_it+1));
		endian.push_back(*r_it);
	}
  }
  return endian;
}

string RC6::hex_to_string(unsigned int A, unsigned int B, unsigned int C, unsigned int D){
	string strA, strB, strC, strD, result;
	stringstream ss;
	ss << setfill('0') << setw(4) << hex << A;
	strA = little_endian(ss.str());
	ss.str("");
	ss.clear();

	ss << setfill('0') << setw(4) << hex << B;
	strB = little_endian(ss.str());
	ss.str("");
	ss.clear();

	ss << setfill('0') << setw(4) << hex << C;
	strC = little_endian(ss.str());
	ss.str("");
	ss.clear();

	ss << setfill('0') << setw(4) << hex << D;
	strD = little_endian(ss.str());
	ss.str("");
	ss.clear();

	result = strA + strB + strC + strD;

	return result;

}

void RC6::keyGen(string key){
	//The constants P32 = B7E15163 and Q32 = 9E3779B9 (hexadecimal)
	const unsigned int w_bytes = ceil((float)w / 8);
	//cout << "w_bytes is " << w_bytes << endl;
	const unsigned int c = ceil((float)b / w_bytes);
	//cout << "C is " << c << endl;
	//static unsigned int S[(2 * r) + 4];
	unsigned int Pw, Qw;
	//stringstream ss, ss1;
	//ss << hex << "B7E15163";
	//ss >> Pw;
	//ss1 << hex << "9E3779B9";
	//ss1 >> Qw;
	//cout << Pw << endl;
	//cout << Qw << endl;
	Pw = (unsigned int) ceil(((M_E - 2) * pow(2, w)));
	Qw = (unsigned int)((1.618033988749895 - 1) * pow(2, w)); 
	S[0] = Pw;
	//cout << S[0] << endl; //FIX
	for (int m = 1; m <= 2 * r + 3; m++){
		S[m] = (S[m-1] + Qw) % mod;
		//cout << S[m] << endl;
	}
	L = new unsigned int[c];
	for(int n = 0; n < c; n++){
		L[n] = strtoul(little_endian(key.substr(w_bytes * 2 * n, w_bytes * 2)).c_str(), NULL, 16);
	}
	int v = 3 * max(c, (2 * r + 4));
	unsigned int A = 0, B = 0, i = 0, j = 0;
	for (int k = 1; k <= v; k++){
		A = S[i] = rotl((S[i] + A + B) % mod, 3, w);
		B = L[j] = rotl((L[j] + A + B) % mod, (A + B), w);
		i = (i + 1) % (2 * r + 4);
		j = (j + 1) % c;
	}
}

string RC6::encrypt(string input){
	unsigned int A, B, C, D, t, u, temp;
	A = strtoul(little_endian(input.substr(0, 8)).c_str(), NULL, 16);
	B = strtoul(little_endian(input.substr(8, 8)).c_str(), NULL, 16);
	C = strtoul(little_endian(input.substr(16, 8)).c_str(), NULL, 16);
	D = strtoul(little_endian(input.substr(24, 8)).c_str(), NULL, 16);
	//int32_t t, u, temp;
	B = B + S[0];
	D = D + S[1];
	for (int i = 1; i <= r; i++){
		t = rotl((B * (2 * B + 1)) % mod, log_w, w);
		u = rotl((D * (2 * D + 1)) % mod, log_w, w);
		A = rotl((A ^ t), u, w) + S[2 * i];
		C = rotl((C ^ u), t, w) + S[2 * i + 1];
		temp = A;
		A = B;
		B = C;
		C = D;
		D = temp;
	}
	A = A + S[2 * r + 2];
	C = C + S[2 * r + 3];
	//cout << A << endl;
	//cout << B << endl;
	//cout << C << endl;
	//cout << D << endl;

	return hex_to_string(A,B,C,D);
}
string RC6::decrypt(string input){
	unsigned int A, B, C, D, u, t, temp;
	A = strtoul(little_endian(input.substr(0, 8)).c_str(), NULL, 16);
	B = strtoul(little_endian(input.substr(8, 8)).c_str(), NULL, 16);
	C = strtoul(little_endian(input.substr(16, 8)).c_str(), NULL, 16);
	D = strtoul(little_endian(input.substr(24, 8)).c_str(), NULL, 16);
	
	C = C - S[2 * r + 3];
	A = A - S[2 * r + 2];
	for (int i = r; i >= 1; i--){
		temp = D;
		D = C;
		C = B;
		B = A;
		A = temp;
		u = rotl((D * (2 * D + 1)), log_w, w);
		t = rotl((B * (2 * B + 1)), log_w, w);
		C = rotr(C - S[2 * i + 1], t, w) ^ u;
		A = rotr(A - S[2 * i], u, w) ^ t;
	}
	D = D - S[1];
	B = B - S[0];
	//cout << A << endl;
	//cout << B << endl;
	//cout << C << endl;
	//cout << D << endl;

	return hex_to_string(A,B,C,D);
}

string RC6::cipher(string userkey, string input, string mode){
	keyGen(userkey);
	string result;
	if (mode == "Encryption"){
		string encryption = encrypt(input);
		for(std::string::iterator it = encryption.begin(); it != encryption.end();it = it + 2){
			result.push_back(*it);
			result.push_back(*(it+1));
			result = result + " ";
		}
	}
	else if (mode == "Decryption"){
		string decryption = decrypt(input);
		for(std::string::iterator it = decryption.begin(); it != decryption.end();it = it + 2){
			result.push_back(*it);
			result.push_back(*(it+1));
			result = result + " ";
		}
	}
	else cout << "Failed to receive crypto mode" << endl;
	return result;
}
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#pragma comment(lib, "crypt32.lib")
using namespace std;


//must take Phantasy Star Online private key created with openssl command: "openssl genpkey -out myKey.pem -algorithm rsa -pkeyopt rsa_keygen_bits:1024" 
//and run: "openssl rsa -in privkey.pem -out modifiedprivkey.pem"
const char* PemPrivKey =
"-----BEGIN RSA PRIVATE KEY-----"
"MIICXAIBAAKBgQCxNPr6gWDftz6MkKRCx81TuU3cL/FddnaPjoDy+pRxP17RdEwV"
"nlA/CWvqLUEYgOipKEr7kGpX6ebqGOYY1kn/9afHxl3/C1Dl6YTaIrlZHXpE3SH5"
"KmPZP5lgXRovtVQhsxY+CeB95zBxa3LZHB7cMufcFp2o0dHIcvdwXcrxFwIDAQAB"
"AoGAWm4S9es4KHI2tTzK1lln6qXRmd/NaEif0DqEi3pcbj5MgM68VPvpL4H7VBGr"
"+nkuQcSSHzZfTmXKtQPnyBzyvZZhoaW5UcuCL2JzjY7HbE8fEnudFxzC4hKBKD1Y"
"8VT3q1Od9CP0NDB86RycfzyuC+dxRrHp80idH+tStG6KL4ECQQDeqkMkS48qq+Ts"
"aO9onTw17uUoT9wfSb9hO5GoYG3gkIQgY2BTBrxYta9uVLTZ+3U4TgW7YxNfDH1w"
"neIuXCZnAkEAy7yD32C7WGx10s14/hsMWeDJaTJbTpHMDoj1U7+N225nBECZqmq7"
"nH6KzYZGmmayaT8hIe/dqEnV86nehK9R0QJBANoO2eQQjytV3cHb3iGQYmfbBdZd"
"pw+JFIAvayz/Cnvya0Kgr7N/lDI3847UK6ySArDaT+i8VTsvKyV/qQKHwh8CQC0m"
"riMHEP3bq5D4MGRAIlCY3IoPuuSCszJVb+kLfqiuou3yUxvNY56e/KvnoiX9tHRW"
"pUUcH4d4NY42izXklMECQBzdWaY0gJmxHcAAq3jKgErpbcphpB1AkOoFd8gi24wN"
"P6hya1jhJ6GDt53GXeiWXx1sK9RH3pJtaw7QTwX3Y8M="
"-----END RSA PRIVATE KEY-----";


int main()
{
	DWORD szPrivKey = 0, szKeyBlob = 0;
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	DWORD cryptLength;
	ifstream encData("new128.bin", std::ifstream::binary); //new128.bin or rsa128.bin
	ofstream decData("decrypted.bin", std::ofstream::binary); //Decrypted output file
	BYTE * pemBuffer = NULL;
	BYTE * KeyBlob = NULL;
	streampos length;


	//Make sure we can open the encrypted binary file
	if (!encData)
	{
		cout << "ERROR: Cannot open encrypted data!\n\n" << endl;
		goto CleanUp;
	}

	//Run once to determine size of provided private key and create dynamic BYTE array
	if (!CryptStringToBinaryA(PemPrivKey, 0, CRYPT_STRING_BASE64HEADER, NULL, &szPrivKey, NULL, NULL)){
		printf("CryptStringToBinaryA failed with error 0x%.8X\n\n", GetLastError());
		goto CleanUp;
	}
	pemBuffer = new BYTE[szPrivKey];

	//Run a second time with destination buffer to convert from base64
	if (!CryptStringToBinaryA(PemPrivKey, 0, CRYPT_STRING_BASE64HEADER, pemBuffer, &szPrivKey, NULL, NULL)){
		printf("CryptStringToBinaryA failed with error 0x%.8X\n\n", GetLastError());
		goto CleanUp;
	}

	//Run once with no destination buffer to determine output KeyBlob size and create dynamic BYTE array
	if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, pemBuffer, szPrivKey, 0, NULL, NULL, &szKeyBlob)){
		printf("CryptDecodeObjectEx failed with error 0x%.8X\n\n", GetLastError());
		goto CleanUp;
	}
	KeyBlob = new BYTE[szKeyBlob];

	//Run a second time with destination buffer to decode into blob
	if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, pemBuffer, szPrivKey, 0, NULL, KeyBlob, &szKeyBlob)){
		printf("CryptDecodeObjectEx failed with error 0x%.8X\n\n", GetLastError());
		goto CleanUp;
	}

	//Create a context in the Cryptographic Service Provider
	if (!CryptAcquireContextA(&hProv, NULL, MS_ENHANCED_PROV_A, PROV_RSA_FULL, 0)){
		printf("CryptAcquireContextA failed with error 0x%.8X\n\n", GetLastError());
		goto CleanUp;
	}

	//Import Private key into context
	if (!CryptImportKey(hProv, KeyBlob, szKeyBlob, NULL, 0, &hKey)){
		printf("CryptImportKey failed with error 0x%.8X\n\n", GetLastError());
		goto CleanUp;
	}

	//Obtain length of encrypted data
	encData.seekg(0, encData.end);
	length = encData.tellg();
	encData.seekg(0, encData.beg);

	//Create byte array for CryptDecrypt() to work in
	BYTE * cData = new BYTE[(unsigned int)length];

	//Move encrypted data into buffer
	encData.read((char*)cData, length);
	cryptLength = (DWORD)length;
	if (cryptLength < 0)
	{
		printf("Transfer of encrypted data failed with error 0x%.8X\n\n", GetLastError());
		goto CleanUp;
	}

	//Output encrypted data
	cout << "Encrypted Data: \n" << cData << endl << endl;

	if (!CryptDecrypt(hKey, NULL, TRUE, 0, cData, &cryptLength))
	{
		printf("CryptDecrypt failed with error 0x%.8X\n\n", GetLastError());
		goto CleanUp;
	}

	//Output decrypted data
	cout << "Decrypted Data: \n" << cData << endl << endl;

	//Dump decrypted data to file
	cout << "Writing..." << endl << endl;
	decData.write((const char*)cData, cryptLength);


	//Clean Shop
	CleanUp:
	encData.close();
	decData.close();
	if (pemBuffer) LocalFree(pemBuffer);
	if (KeyBlob) LocalFree(KeyBlob);
	if (hKey) CryptDestroyKey(hKey);
	if (hProv) CryptReleaseContext(hProv, 0);
	cout << "Kitchen is Clean!\n\n" << endl;
	return 0;
}
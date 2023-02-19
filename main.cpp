#include<iostream>
#include<chrono>
#include<algorithm>
#include"argon2.h"

void rfc9106_test_vector()
{
	argon2_option opt = { 3,32    ,4 };
	byte password[32], salt[16], secret[8], ad[12];
	std::fill(password, password + 32, 1);
	std::fill(salt, salt + 16, 2);
	std::fill(secret, secret + 8, 3);
	std::fill(ad, ad + 12, 4);
	argon2_input in = { password, 32, salt, 16, secret, 8, ad, 12 };
	byte out[32], ans[32] = 
		{ 0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
		0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59 };
	argon2id(in, opt, { out, 32 });
	if (std::equal(out, out + 32, ans))
		std::cout << "pass\n";
	else
		std::cout << "fail\n";
}

template<typename F>
void speed(F&& f)
{
	auto start = std::chrono::steady_clock::now();
	f();
	auto end = std::chrono::steady_clock::now();

	auto time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
	std::cout << time << " microseconds\n";
}

int main()
{
	rfc9106_test_vector();
	argon2_option opt = {1,(1 << 16) ,1};
	byte password[32], salt[16];
	std::fill(password, password + 32, 1);
	std::fill(salt, salt + 16, 2);
	argon2_input in = { password, 32, salt, 16, nullptr, 0, nullptr, 0 };

	auto f = [&]()
	{
		byte out[64] = {};
		for (int i = 0; i < 100; i++)
		{
			password[0]++;
			salt[0]++;
			argon2id(in, opt, { out, 64 });
		}

	};
	speed(f);

	return 0;
}
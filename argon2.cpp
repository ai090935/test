#include"argon2.h"
#include<vector>
#include<algorithm>
#include<iterator>
#include<mutex>
#include<condition_variable>
#include<future>
#include<functional>
#include<climits>

enum class endian
{
	big,
	little,
};

template<endian word_endian, typename word>
word byte_to_word(const byte* p) noexcept
{
	word n = 0;
	if constexpr (word_endian == endian::big)
		for (size_t i = 0; i < sizeof(word); i++)
			n |= static_cast<word>(p[i]) << (sizeof(word) - 1 - i) * CHAR_BIT;
	else if constexpr (word_endian == endian::little)
		for (size_t i = 0; i < sizeof(word); i++)
			n |= static_cast<word>(p[i]) << i * CHAR_BIT;

	return n;
}

template<endian word_endian, typename word>
void word_to_byte(word n, byte* p) noexcept
{
	if constexpr (word_endian == endian::big)
		for (size_t i = 0; i < sizeof(word); i++)
			p[i] = static_cast<byte>(n >> (sizeof(word) - 1 - i) * CHAR_BIT);
	else if constexpr (word_endian == endian::little)
		for (size_t i = 0; i < sizeof(word); i++)
			p[i] = static_cast<byte>(n >> i * CHAR_BIT);
}

template<typename T>
constexpr T rotr(T value, size_t shift) noexcept
{
	return (value >> shift) | (value << (sizeof(T) * CHAR_BIT - shift));
}

template<size_t bits, typename T>
constexpr T high_bits(T value) noexcept
{
	return value >> (sizeof(T) * CHAR_BIT - bits);
}

template<size_t bits, typename T>
constexpr T low_bits(T value) noexcept
{
	return value & high_bits<bits>(~T(0));
}

namespace
{
	enum class argon2_type
	{
		argon2d = 0,
		argon2i = 1,
		argon2id = 2,
	};

	class argon2_block
	{
	public:
		argon2_block() = default;

		argon2_block& operator^=(const argon2_block& other) noexcept
		{
			for (int i = 0; i < 128; i++)
				this->data[i] ^= other.data[i];
			return *this;
		}

		uint64_t data[128];
	};

	argon2_block operator^(const argon2_block& a, const argon2_block& b) noexcept
	{
		return argon2_block(a) ^= b;
	}

	static_assert(sizeof(argon2_block) == 1024);

	//-------------------------------------------------------------------------------------------------

	class matrix
	{
	public:
		matrix(size_t row, size_t col) : col(col), data(new argon2_block[row * col]) {}

		~matrix() noexcept
		{
			delete[] this->data;
		}

		matrix(const matrix&) = delete;
		matrix& operator=(const matrix&) = delete;

		argon2_block* operator[](size_t row) noexcept
		{
			return this->data + row * this->col;
		}

		const argon2_block* operator[](size_t row) const noexcept
		{
			return this->data + row * this->col;
		}

	private:
		size_t col;
		argon2_block* data;
	};

	//-------------------------------------------------------------------------------------------------

	class barrier
	{
	public:
		barrier(size_t expected) : arrive_count(0), expected(expected), phase(0) {}
		barrier(const barrier&) = delete;
		barrier& operator=(const barrier&) = delete;

		void arrive_and_wait() noexcept
		{
			std::unique_lock lock(this->mutex);
			this->arrive_count++;

			if (this->arrive_count < this->expected)
				this->condition_variable.wait(lock, [current_phase = this->phase, this]() { return current_phase != this->phase; });
			else
			{
				this->arrive_count = 0;
				this->phase++;

				lock.unlock();
				this->condition_variable.notify_all();
			}
		}

	private:
		size_t arrive_count;
		size_t expected;
		size_t phase;
		std::mutex mutex;
		std::condition_variable condition_variable;
	};

	//-------------------------------------------------------------------------------------------------

	class uint128_t
	{
	public:
		uint128_t() = default;
		uint128_t(const uint128_t&) = default;
		uint128_t& operator=(const uint128_t&) = default;
		constexpr uint128_t(uint64_t n) noexcept : high(0), low(n) {}

		constexpr uint128_t& operator+=(const uint128_t& other) noexcept
		{
			this->high += other.high + (static_cast<uint64_t>(this->low + other.low) < this->low);
			this->low += other.low;

			return *this;
		}

		constexpr uint128_t operator~() const noexcept
		{
			uint128_t temp = 0;
			temp.high = ~this->high;
			temp.low = ~this->low;
			return temp;
		}

		constexpr uint128_t operator&(const uint128_t& other) const noexcept
		{
			uint128_t temp = *this;
			temp.high &= other.high;
			temp.low &= other.low;

			return *this;
		}

		constexpr uint128_t operator>>(const uint128_t& other) const noexcept
		{
			uint128_t temp = *this;
			const uint64_t shift = other.low;

			if (!shift)
				return temp;
			else if (shift < 64)
			{
				temp.low = (temp.high << (64 - shift)) | (temp.low >> shift);
				temp.high >>= shift;
			}
			else
			{
				temp.low = temp.high >> (shift - 64);
				temp.high = 0;
			}

			return temp;
		}

		explicit constexpr operator uint64_t() const noexcept
		{
			return this->low;
		}

	private:
		uint64_t high;
		uint64_t low;
	};

	class blake2b_MAC
	{
		typedef uint64_t word;
	public:
		blake2b_MAC(size_t output_size = 64) noexcept : h{ 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 }, b_length(0), output_size(output_size), total_length(0) {}

		blake2b_MAC(const byte* key, size_t keylen, size_t output_size = 64) noexcept : blake2b_MAC(output_size)
		{
			this->init(key, keylen);
		}

		blake2b_MAC(const byte* key, size_t keylen, const byte* input, size_t length, byte* output, size_t output_size = 64) noexcept : blake2b_MAC(key, keylen, output_size)
		{
			this->update(input, length);
			this->final(output);
		}

		void init(const byte* key, size_t keylen) noexcept
		{
			this->h[0] ^= 0x01010000 ^ (keylen << 8) ^ output_size;
			if (keylen)
			{
				std::copy(key, key + keylen, b);
				std::fill(b + keylen, b + block_size, 0);
				b_length = block_size;
			}
		}

		void update(const byte* input, size_t length) noexcept
		{
			while (length)
			{
				if (b_length == block_size)
				{
					total_length += b_length;
					compress(false);
					b_length = 0;
				}

				size_t outlen = (b_length + length < block_size) ? length : block_size - b_length;
				std::copy(input, input + outlen, b + b_length);

				b_length += outlen;
				input += outlen;
				length -= outlen;
			}
		}

		void final(byte* output) noexcept
		{
			total_length += b_length;
			std::fill(b + b_length, b + block_size, 0);
			compress(true);

			byte temp[sizeof(h)];
			for (size_t i = 0; i < 8; i++)
				word_to_byte<endian::little>(h[i], temp + i * sizeof(word));
			std::copy(temp, temp + output_size, output);
		}

		//blake2 rfc 3.1
		void mixing(word* v, int a, int b, int c, int d, word x, word y) noexcept
		{
			v[a] = v[a] + v[b] + x;
			v[d] = rotr(static_cast<word>(v[d] ^ v[a]), 32);
			v[c] = v[c] + v[d];
			v[b] = rotr(static_cast<word>(v[b] ^ v[c]), 24);
			v[a] = v[a] + v[b] + y;
			v[d] = rotr(static_cast<word>(v[d] ^ v[a]), 16);
			v[c] = v[c] + v[d];
			v[b] = rotr(static_cast<word>(v[b] ^ v[c]), 63);
		}

		//blake2 rfc 3.2
		void compress(bool last) noexcept
		{
			constexpr byte sigma[10][16] = {
				{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
				{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
				{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
				{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
				{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
				{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
				{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
				{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
				{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
				{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
			};

			word v[16], m[16], IV[8] = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};

			std::copy(h, h + 8, v);
			std::copy(IV, IV + 8, v + 8);
			v[12] ^= static_cast<word>(low_bits<64>(total_length));
			v[13] ^= static_cast<word>(high_bits<64>(total_length));
			if (last)
				v[14] = ~v[14];

			for (size_t i = 0; i < std::size(m); i++)
				m[i] = byte_to_word<endian::little, word>(b + i * sizeof(word));

			for (int i = 0; i < 12; i++)
			{
				mixing(v, 0, 4, 8, 12, m[sigma[i % 10][0]], m[sigma[i % 10][1]]);
				mixing(v, 1, 5, 9, 13, m[sigma[i % 10][2]], m[sigma[i % 10][3]]);
				mixing(v, 2, 6, 10, 14, m[sigma[i % 10][4]], m[sigma[i % 10][5]]);
				mixing(v, 3, 7, 11, 15, m[sigma[i % 10][6]], m[sigma[i % 10][7]]);
				mixing(v, 0, 5, 10, 15, m[sigma[i % 10][8]], m[sigma[i % 10][9]]);
				mixing(v, 1, 6, 11, 12, m[sigma[i % 10][10]], m[sigma[i % 10][11]]);
				mixing(v, 2, 7, 8, 13, m[sigma[i % 10][12]], m[sigma[i % 10][13]]);
				mixing(v, 3, 4, 9, 14, m[sigma[i % 10][14]], m[sigma[i % 10][15]]);
			}

			for (size_t i = 0; i < 8; i++)
				h[i] ^= v[i] ^ v[i + 8];
		}

		static constexpr size_t block_size = 128;

	private:
		word h[8];
		byte b[block_size];
		size_t b_length;
		size_t output_size;
		uint128_t total_length;
	};

	class blake2b : public blake2b_MAC
	{
	public:
		blake2b(size_t output_size = 64) noexcept : blake2b_MAC(nullptr, 0, output_size) {}
		blake2b(const byte* input, size_t length, byte* output, size_t output_size = 64) noexcept : blake2b_MAC(nullptr, 0, input, length, output, output_size) {}
	};

	//rfc 3.3
	void blake2b_long(byte* out, uint32_t outlen, const byte* in, uint32_t inlen, const byte* in2, uint32_t in2len) noexcept
	{
		byte temp[sizeof(uint32_t)];
		blake2b a(outlen < 64 ? outlen : 64);

		word_to_byte<endian::little>(outlen, temp);
		a.update(temp, sizeof(uint32_t));
		a.update(in, inlen);
		a.update(in2, in2len);
		a.final(out);

		if (outlen > 64)
		{
			byte v[64];
			const uint32_t r = outlen / 32 + static_cast<bool>(outlen % 32) - 2;

			std::copy(out, out + 64, v);
			for (uint32_t i = 1; i < r; i++)
			{
				blake2b(v, 64, v);
				std::copy(v, v + 32, out + i * 32);
			}
			blake2b(v, 64, out + r * 32, outlen - 32 * r);
		}
	}

	//-------------------------------------------------------------------------------------------------

	//rfc 3.6 GB
	void GB(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d) noexcept
	{
		a = a + b + 2 * low_bits<32>(a) * low_bits<32>(b);
		d = rotr(static_cast<uint64_t>(d ^ a), 32);
		c = c + d + 2 * low_bits<32>(c) * low_bits<32>(d);
		b = rotr(static_cast<uint64_t>(b ^ c), 24);

		a = a + b + 2 * low_bits<32>(a) * low_bits<32>(b);
		d = rotr(static_cast<uint64_t>(d ^ a), 16);
		c = c + d + 2 * low_bits<32>(c) * low_bits<32>(d);
		b = rotr(static_cast<uint64_t>(b ^ c), 63);
	}

	//rfc 3.6 permutation P
	void permutation(uint64_t* s0, uint64_t* s1, uint64_t* s2, uint64_t* s3, uint64_t* s4, uint64_t* s5, uint64_t* s6, uint64_t* s7) noexcept
	{
		GB(s0[0], s2[0], s4[0], s6[0]);
		GB(s0[1], s2[1], s4[1], s6[1]);
		GB(s1[0], s3[0], s5[0], s7[0]);
		GB(s1[1], s3[1], s5[1], s7[1]);

		GB(s0[0], s2[1], s5[0], s7[1]);
		GB(s0[1], s3[0], s5[1], s6[0]);
		GB(s1[0], s3[1], s4[0], s6[1]);
		GB(s1[1], s2[0], s4[1], s7[0]);
	}

	//rfc 3.5 compression function G
	argon2_block compression(const argon2_block& x, const argon2_block& y) noexcept
	{
		const argon2_block r = x ^ y;

		argon2_block z = r;
		for (int i = 0; i < 8; i++)
		{
			uint64_t* const row = z.data + i * 16;
			permutation(row + 0, row + 2, row + 4, row + 6, row + 8, row + 10, row + 12, row + 14);
		}
		for (int i = 0; i < 8; i++)
		{
			uint64_t* const col = z.data + i * 2;
			permutation(0 * 16 + col, 1 * 16 + col, 2 * 16 + col, 3 * 16 + col, 4 * 16 + col, 5 * 16 + col, 6 * 16 + col, 7 * 16 + col);
		}

		return z ^ r;
	}

	//-------------------------------------------------------------------------------------------------

	//rfc 3.4.2
	void mapping_index(uint32_t j1, uint32_t j2, uint32_t i, uint32_t q, uint32_t t, int slice, uint32_t j, argon2_option option, uint32_t& l, uint32_t& z) noexcept
	{
		if (t == 0 && slice == 0)
			l = i;
		else
			l = j2 % option.parallelism;

		uint32_t w;
		const uint32_t finished_blocks = (t == 0 ? slice : 3) * (q / 4);
		if (l == i)
			w = finished_blocks + j - 1;
		else
			w = finished_blocks - (j == 0 ? 1 : 0);

		const uint64_t x = (static_cast<uint64_t>(j1) * static_cast<uint64_t>(j1)) >> 32;
		const uint64_t y = (w * x) >> 32;
		const uint64_t zz = w - 1 - y;

		const uint32_t start_position = (t != 0 && slice != 3) ? (slice + 1) * (q / 4) : 0;
		z = (start_position + zz) % q;
	}

	void init_argon2i_index_block(argon2_block& input_block, argon2_block& address_block, uint32_t i, uint32_t q, uint32_t t, int slice, argon2_option option, argon2_type type) noexcept
	{
		constexpr argon2_block zero_block = {};

		input_block.data[0] = t;
		input_block.data[1] = i;
		input_block.data[2] = slice;
		input_block.data[3] = option.parallelism * q;
		input_block.data[4] = option.time_cost;
		input_block.data[5] = static_cast<uint64_t>(type);
		input_block.data[6] = 1;
		std::fill(input_block.data + 7, input_block.data + std::size(input_block.data), 0);

		address_block = compression(zero_block, compression(zero_block, input_block));
	}

	void update_argon2i_index_block(argon2_block& input_block, argon2_block& address_block) noexcept
	{
		constexpr argon2_block zero_block = {};

		input_block.data[6]++;

		address_block = compression(zero_block, compression(zero_block, input_block));
	}

	//rfc 3.4.1.2
	void compute_argon2i_index(argon2_block& input_block, argon2_block& address_block, uint32_t i, uint32_t q, uint32_t t, int slice, uint32_t j, argon2_option option, argon2_type type, uint32_t& l, uint32_t& z) noexcept
	{
		//128 = 1024-byte / 8-byte
		if (j == 0 || (t == 0 && slice == 0 && j == 2))
			init_argon2i_index_block(input_block, address_block, i, q, t, slice, option, type);
		else if (j % 128 == 0)
			update_argon2i_index_block(input_block, address_block);

		uint32_t j1 = low_bits<32>(address_block.data[j % 128]);
		uint32_t j2 = high_bits<32>(address_block.data[j % 128]);
		mapping_index(j1, j2, i, q, t, slice, j, option, l, z);
	}

	//rfc 3.4.1.1
	void compute_argon2d_index(const argon2_block& block, uint32_t i, uint32_t q, uint32_t t, int slice, uint32_t j, argon2_option option, uint32_t& l, uint32_t& z) noexcept
	{
		uint32_t j1 = low_bits<32>(block.data[0]);
		uint32_t j2 = high_bits<32>(block.data[0]);
		mapping_index(j1, j2, i, q, t, slice, j, option, l, z);
	}

	void compute_segment(matrix& B, barrier& sync_point, uint32_t i, uint32_t q, uint32_t t, int slice, argon2_option option, argon2_type type) noexcept
	{
		argon2_block input_block, address_block;

		const bool is_argon2i_index = (type == argon2_type::argon2i || (type == argon2_type::argon2id && t == 0 && (slice == 0 || slice == 1)));
		const uint32_t offset = slice * (q / 4);
		for (uint32_t j = 0; j < q / 4; j++)
		{
			if (t == 0 && slice == 0 && (j == 0 || j == 1))
				continue;

			argon2_block& curr = (slice == 0 && j == 0) ? B[i][0] : B[i][j + offset];
			argon2_block& prev = (slice == 0 && j == 0) ? B[i][q - 1] : B[i][j + offset - 1];

			uint32_t l, z;
			if (is_argon2i_index)
				compute_argon2i_index(input_block, address_block, i, q, t, slice, j, option, type, l, z);
			else
				compute_argon2d_index(prev, i, q, t, slice, j, option, l, z);
			argon2_block& ref = B[l][z];

			if (t == 0)
				curr = compression(prev, ref);
			else
				curr ^= compression(prev, ref);
		}

		sync_point.arrive_and_wait();
	}

	//rfc 3.2.3 and 3.2.4
	void compute_first_block(argon2_block& first, argon2_block& second, const byte* H0, uint32_t i) noexcept
	{
		byte temp[sizeof(uint32_t) * 2], buf[1024];

		word_to_byte<endian::little>(static_cast<uint32_t>(0), temp);
		word_to_byte<endian::little>(i, temp + sizeof(uint32_t));
		blake2b_long(buf, 1024, H0, 64, temp, sizeof(uint32_t) * 2);
		for (size_t i = 0; i < std::size(first.data); i++)
			first.data[i] = byte_to_word<endian::little, uint64_t>(buf + i * sizeof(uint64_t));

		word_to_byte<endian::little>(static_cast<uint32_t>(1), temp);
		word_to_byte<endian::little>(i, temp + sizeof(uint32_t));
		blake2b_long(buf, 1024, H0, 64, temp, sizeof(uint32_t) * 2);
		for (size_t i = 0; i < std::size(second.data); i++)
			second.data[i] = byte_to_word<endian::little, uint64_t>(buf + i * sizeof(uint64_t));
	}

	//rfc 3.2.5 and 3.2.6
	void compute_remainder_block(matrix& B, barrier& sync_point, uint32_t i, uint32_t q, argon2_option option, argon2_type type)
	{
		for (uint32_t t = 0; t < option.time_cost; t++)
			for (int slice = 0; slice < 4; slice++)
				compute_segment(B, sync_point, i, q, t, slice, option, type);
	}

	//-------------------------------------------------------------------------------------------------

	//rfc 3.2.1
	void init_H0(byte* H0, argon2_input input, uint32_t outlen, argon2_option option, argon2_type type) noexcept
	{
		blake2b a;
		byte temp[sizeof(uint32_t)];

		word_to_byte<endian::little>(option.parallelism, temp);
		a.update(temp, sizeof(uint32_t));

		word_to_byte<endian::little>(outlen, temp);
		a.update(temp, sizeof(uint32_t));

		word_to_byte<endian::little>(option.memory_cost, temp);
		a.update(temp, sizeof(uint32_t));

		word_to_byte<endian::little>(option.time_cost, temp);
		a.update(temp, sizeof(uint32_t));

		word_to_byte<endian::little>(static_cast<uint32_t>(0x13), temp);
		a.update(temp, sizeof(uint32_t));

		word_to_byte<endian::little>(static_cast<uint32_t>(type), temp);
		a.update(temp, sizeof(uint32_t));

		word_to_byte<endian::little>(input.password.length, temp);
		a.update(temp, sizeof(uint32_t));

		a.update(input.password.data, input.password.length);

		word_to_byte<endian::little>(input.salt.length, temp);
		a.update(temp, sizeof(uint32_t));

		a.update(input.salt.data, input.salt.length);

		word_to_byte<endian::little>(input.secret.length, temp);
		a.update(temp, sizeof(uint32_t));

		a.update(input.secret.data, input.secret.length);

		word_to_byte<endian::little>(input.associated_data.length, temp);
		a.update(temp, sizeof(uint32_t));

		a.update(input.associated_data.data, input.associated_data.length);

		a.final(H0);
	}

	//rfc 3.2.3 ~ 3.2.6
	void compute(matrix& B, barrier& sync_point, const byte* H0, uint32_t i, uint32_t q, argon2_option option, argon2_type type) noexcept
	{
		compute_first_block(B[i][0], B[i][1], H0, i);
		compute_remainder_block(B, sync_point, i, q, option, type);
	}

	//rfc 3.2.7
	void finalize(matrix& B, uint32_t row, uint32_t col, byte* out, uint32_t outlen) noexcept
	{
		argon2_block& C = B[0][col - 1];
		for (uint32_t i = 1; i < row; i++)
			C ^= B[i][col - 1];

		byte temp[sizeof(C)];
		for (size_t i = 0; i < std::size(C.data); i++)
			word_to_byte<endian::little>(C.data[i], temp + i * sizeof(uint64_t));
		blake2b_long(out, outlen, temp, sizeof(C), nullptr, 0);
	}

	void argon2(argon2_input input, argon2_option option, array output, argon2_type type)
	{
		byte H0[64];
		init_H0(H0, input, output.length, option, type);

		const uint32_t row = option.parallelism;
		const uint32_t col = 4 * (option.memory_cost / (4 * option.parallelism));
		matrix B(row, col);
		barrier sync_point(option.parallelism);

		std::vector<std::future<void>> vec;
		for (uint32_t i = 0; i < option.parallelism; i++)
			vec.push_back(std::async(std::launch::async, &compute, std::ref(B), std::ref(sync_point), H0, i, col, option, type));
		for (const auto& i : vec)
			i.wait();

		finalize(B, row, col, output.data, output.length);
	}
}

//-------------------------------------------------------------------------------------------------

void argon2i(argon2_input input, argon2_option option, array output)
{
	argon2(input, option, output, argon2_type::argon2i);
}

void argon2d(argon2_input input, argon2_option option, array output)
{
	argon2(input, option, output, argon2_type::argon2d);
}

void argon2id(argon2_input input, argon2_option option, array output)
{
	argon2(input, option, output, argon2_type::argon2id);
}
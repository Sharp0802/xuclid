#include <iostream>
#include <openssl/bn.h>


static BN_CTX* g_ctx;


class xint final
{
private:
	BIGNUM* _v;

public:
	xint() : _v(BN_new())
	{
	}

	xint(const xint& rhs) : _v(BN_dup(rhs._v))
	{
	}

	xint(uint64_t w) : _v(BN_new())
	{
		BN_set_word(_v, w);
	}

	xint(std::string_view v) : _v(BN_new())
	{
		BN_dec2bn(&_v, v.data());
	}

	~xint()
	{
		BN_free(_v);
	}

public:
	xint& operator=(const xint& rhs)
	{
		if (&rhs != this)
			BN_copy(_v, rhs._v);
		return *this;
	}

	xint operator+(const xint& rhs)
	{
		xint r{};
		BN_add(r._v, _v, rhs._v);
		return r;
	}

	xint operator-(const xint& rhs)
	{
		xint r{};
		BN_sub(r._v, _v, rhs._v);
		return r;
	}

	xint operator*(const xint& rhs)
	{
		xint r{};
		BN_mul(r._v, _v, rhs._v, g_ctx);
		return r;
	}

	xint operator/(const xint& rhs)
	{
		xint d{};
		xint r{};
		BN_div(d._v, r._v, _v, rhs._v, g_ctx);
		return d;
	}

	xint operator%(const xint& rhs)
	{
		xint d{};
		xint r{};
		BN_div(d._v, r._v, _v, rhs._v, g_ctx);
		return r;
	}

	xint operator-()
	{
		xint r(*this);
		BN_set_negative(r._v, *this > 0);
		return r;
	}

	bool operator==(const xint& rhs)
	{
		return BN_cmp(_v, rhs._v) == 0;
	}

	bool operator<=(const xint& rhs)
	{
		return BN_cmp(_v, rhs._v) <= 0;
	}

	bool operator<(const xint& rhs)
	{
		return BN_cmp(_v, rhs._v) < 0;
	}

	bool operator>=(const xint& rhs)
	{
		return BN_cmp(_v, rhs._v) >= 0;
	}

	bool operator>(const xint& rhs)
	{
		return BN_cmp(_v, rhs._v) > 0;
	}

	bool operator==(uint64_t w)
	{
		return BN_is_word(_v, w);
	}

	explicit operator std::string()
	{
		auto p = BN_bn2dec(_v);
		std::string s(p);
		OPENSSL_free(p);
		return s;
	}
};

int main(int argc, char* argv[])
{
	if (argc < 3)
	{
		std::cerr << "invalid syntax" << std::endl
				  << "syntax: ./xuclid <A> <B>" << std::endl
				  << "sample: ./xuclid 658430145 869745321" << std::endl;
		return -1;
	}

	g_ctx = BN_CTX_new();

	xint A(argv[1]);
	xint B(argv[2]);

	xint x0(1), y0(0), V0(A);
	xint x1(0), y1(1), V1(B);
	xint q, r;

	for (;;)
	{
		auto tr = V0 % V1;
		if (tr == 0)
			break;
		r = tr;
		q = V0 / V1;

		auto xp = x0;
		auto yp = y0;
		x0 = x1;
		y0 = y1;
		x1 = x1 * -q + xp;
		y1 = y1 * -q + yp;

		V0 = V1;
		V1 = r;
	}

	std::cout << "    | Ax + By = GCD(A, B)" << std::endl
			  << "GCD = " << static_cast<std::string>(r) << std::endl
			  << "  A = " << static_cast<std::string>(A) << std::endl
			  << "  B = " << static_cast<std::string>(B) << std::endl
			  << "  x = " << static_cast<std::string>(x1) << std::endl
			  << "  y = " << static_cast<std::string>(y1) << std::endl;

	BN_CTX_free(g_ctx);
	return 0;
}

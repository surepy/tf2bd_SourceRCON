#pragma once

#include <exception>
#include <system_error>

namespace srcon
{
	class srcon_error_category_type final : public std::error_category
	{
	public:
		const char* name() const noexcept override { return "srcon"; }
		std::string message(int condition) const override;
	};

	const srcon_error_category_type& srcon_error_category();

	enum class srcon_errc
	{
		success,

		no_preexisting_connection,
		rcon_connect_failed,
		bad_rcon_password,
		socket_send_failed,
		socket_recv_failed,
	};
}

namespace std
{
	template<> struct is_error_condition_enum<srcon::srcon_errc> : std::bool_constant<true> {};
	std::error_condition make_error_condition(srcon::srcon_errc e);
}

namespace srcon
{
	class srcon_error final : public std::exception
	{
	public:
		srcon_error(srcon_errc errc, std::error_code innerErrorCode, std::string detail);
		srcon_error(srcon_errc errc, std::error_code innerErrorCode = {}, const char* detail = nullptr);
		srcon_error(srcon_errc errc, const char* detail);

		std::error_condition get_error_condition() const { return m_Errc; }
		std::error_code get_inner_error_code() const { return m_InnerErrorCode; }
		srcon_errc get_errc() const { return m_Errc; }

		const char* what() const override { return m_Message.c_str(); }

	private:
		srcon_errc m_Errc;
		std::error_code m_InnerErrorCode;
		std::string m_Detail;
		std::string m_Message;
	};

	using LogFunc_t = void(*)(std::string&& msg);
	void SetLogFunc(LogFunc_t func);
}

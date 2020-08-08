#include "srcon_internal.h"

#include <iostream>

static void DefaultLogFunc(std::string&& str)
{
	std::clog << str << std::endl;
}

static srcon::LogFunc_t s_LogFunc = &DefaultLogFunc;
void srcon::SetLogFunc(LogFunc_t func)
{
	s_LogFunc = func ? func : &DefaultLogFunc;
}

srcon::LogFunc_t srcon::GetLogFunc()
{
	return s_LogFunc;
}

auto srcon::srcon_error_category() -> const srcon_error_category_type&
{
	static srcon_error_category_type s_Instance;
	return s_Instance;
}

std::string srcon::srcon_error_category_type::message(int condition) const
{
	switch ((srcon_errc)condition)
	{
	case srcon_errc::success:                    return "Success";
	case srcon_errc::no_preexisting_connection:  return "This action requires a preexisting RCON connection";
	case srcon_errc::rcon_connect_failed:        return "Failed to initiate RCON connection";
	case srcon_errc::bad_rcon_password:          return "Bad RCON password";
	case srcon_errc::socket_send_failed:         return "Failed to send data on a socket";
	case srcon_errc::socket_recv_failed:         return "Failed to receive data on a socket";

	default:
	{
		std::stringstream ss;
		ss << "srcon_errc(" << condition << ')';
		return ss.str();
	}
	}
}

std::error_condition std::make_error_condition(srcon::srcon_errc e)
{
	return std::error_condition(int(e), srcon::srcon_error_category());
}

srcon::srcon_error::srcon_error(srcon_errc errc, std::error_code innerErrorCode, std::string detail) :
	m_Errc(std::move(errc)), m_InnerErrorCode(std::move(innerErrorCode)), m_Detail(std::move(detail))
{
	std::stringstream ss;

	ss << get_error_condition().message();
	if (m_InnerErrorCode)
		ss << ": " << m_InnerErrorCode.message();
	if (!m_Detail.empty())
		ss << ": " << m_Detail;

	m_Message = ss.str();
}

srcon::srcon_error::srcon_error(srcon_errc errc, std::string detail) :
	srcon_error(std::move(errc), {}, std::move(detail))
{
}

std::error_condition srcon::srcon_error::get_error_condition() const
{
	return std::make_error_condition(get_errc());
}

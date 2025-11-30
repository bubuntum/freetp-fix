#ifndef FREETPFIX_LOG_HPP
#define FREETPFIX_LOG_HPP

#if _DEBUG

#include <cstdio>

void log(const char* const format, auto&&... args) {
	if (auto stream = std::fopen("log.txt", "a")) {
		std::fprintf(stream, format, args...);
		std::fputc('\n', stream);
		std::fclose(stream);
	}
}

#else

void log(const char* const, auto&&...) { }

#endif

#endif // FREETPFIX_LOG_HPP
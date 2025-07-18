#pragma once

// To fix regex_error(error_stack) for longer signatures
#define _REGEX_MAX_STACK_COUNT 20000

// Platform-specific includes
#ifndef __LINUX__
#include <Windows.h>
#endif
#include <vector>
#include <regex>
#include <string_view>

// Generic utility functions

bool SetClipboardText( std::string_view text );
bool GetRegexMatches( std::string string, std::regex regex, std::vector<std::string>& matches );
constexpr auto BIT( uint32_t x ) {
    return 1LLU << x;
}
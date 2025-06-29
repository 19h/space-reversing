#include "Utils.h"
#include <cstring>
#include <cstdio>

bool SetClipboardText( std::string_view text ) {
	if( text.empty( ) ) {
		return false;
	}

#ifdef __LINUX__
	// Linux implementation - print to console for now
	// In a production environment, you might use X11 clipboard APIs
	// or system calls to xclip/xsel
	printf("Signature copied to console (clipboard not implemented on Linux):\n%.*s\n", 
	       (int)text.size(), text.data());
	return true;
#else
	// Windows clipboard implementation
	if( OpenClipboard( NULL ) == false || EmptyClipboard( ) == false ) {
		return false;
	}

	auto memoryHandle = GlobalAlloc( GMEM_MOVEABLE | GMEM_ZEROINIT, text.size( ) + 1 );
	if( memoryHandle == nullptr ) {
		CloseClipboard( );
		return false;
	}

	auto textMem = reinterpret_cast<char*>( GlobalLock( memoryHandle ) );
	if( textMem == nullptr ) {
		GlobalFree( memoryHandle );
		CloseClipboard( );
		return false;
	}

	memcpy( textMem, text.data( ), text.size( ) );
	GlobalUnlock( memoryHandle );
	auto handle = SetClipboardData( CF_TEXT, memoryHandle );
	GlobalFree( memoryHandle );
	CloseClipboard( );

	if( handle == nullptr ) {
		return false;
	}

	return true;
#endif
}

bool GetRegexMatches( std::string string, std::regex regex, std::vector<std::string>& matches ) {
	std::sregex_iterator iter( string.begin( ), string.end( ), regex );
	std::sregex_iterator end;

	matches.clear( );

	size_t i = 0;
	while( iter != end ) {
		matches.push_back( iter->str( ) );
		++iter;
	}
	return !matches.empty( );
}
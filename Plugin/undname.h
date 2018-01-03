
// Access to CRT C++ demangler/undecorator function
#pragma once

// Online: http://demangler.com/

typedef void * (__cdecl * _Alloc)(UINT);
typedef void(__cdecl * _Free)(PVOID);

const UINT UNDNAME_COMPLETE                 = 0x00000;  // Enable full undecoration
const UINT UNDNAME_NO_LEADING_UNDERSCORES   = 0x00001;  // Remove leading underscores from MS extended keywords
const UINT UNDNAME_NO_MS_KEYWORDS           = 0x00002;  // Disable expansion of MS extended keywords
const UINT UNDNAME_NO_FUNCTION_RETURNS      = 0x00004;  // Disable expansion of return type for primary declaration
const UINT UNDNAME_NO_ALLOCATION_MODEL      = 0x00008;  // Disable expansion of the declaration model
const UINT UNDNAME_NO_ALLOCATION_LANGUAGE   = 0x00010;  // Disable expansion of the declaration language specifier
const UINT UNDNAME_NO_MS_THISTYPE           = 0x00020;  // Disable expansion of MS keywords on the 'this' type for primary declaration
const UINT UNDNAME_NO_CV_THISTYPE           = 0x00040;  // Disable expansion of CV modifiers on the 'this' type for primary declaration
const UINT UNDNAME_NO_THISTYPE              = 0x00060;  // Disable all modifiers on the 'this' type
const UINT UNDNAME_NO_ACCESS_SPECIFIERS     = 0x00080;  // Disable expansion of access specifiers for members
const UINT UNDNAME_NO_THROW_SIGNATURES      = 0x00100;  // Disable expansion of 'throw-signatures' for functions and pointers to functions
const UINT UNDNAME_NO_MEMBER_TYPE           = 0x00200;  // Disable expansion of 'static' or 'virtual'ness of members
const UINT UNDNAME_NO_RETURN_UDT_MODEL      = 0x00400;  // Disable expansion of MS model for UDT returns
const UINT UNDNAME_32_BIT_DECODE            = 0x00800;  // Undecorate 32-bit decorated names
const UINT UNDNAME_NAME_ONLY                = 0x01000;  // Crack only the name for primary declaration; return just [scope::]name.  Does expand template params
const UINT UNDNAME_TYPE_ONLY                = 0x02000;  // Input is just a type encoding; compose an abstract declarator
const UINT UNDNAME_HAVE_PARAMETERS          = 0x04000;  // The real templates parameters are available
const UINT UNDNAME_NO_ECSU                  = 0x08000;  // Suppress enum/class/struct/union
const UINT UNDNAME_NO_IDENT_CHAR_CHECK      = 0x10000;  // Suppress check for IsValidIdentChar

/*
To supply a buffer to use use 'buffer' and 'sizeBuffer', else for a allocated buffer
'buffer' = NULL, 'sizeBuffer' = 0, and use the return string.
Call Free on the return result when done with the string.
Note: CRT documentation error, the Allocator and Free must be supplied regardless if supplied or allocation buffer method desired.
*/
extern "C" LPSTR __cdecl __unDName(__out LPSTR buffer, __in LPCSTR name, int sizeBuffer, _Alloc allocator, _Free _free, UINT flags);
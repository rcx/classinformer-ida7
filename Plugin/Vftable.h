
// ****************************************************************************
// File: Vftable.h
// Desc: Virtual function table parsing support
//
// ****************************************************************************
#pragma once

namespace vftable
{
	// vftable info container
	struct vtinfo
	{
		ea_t start, end;
		int  methodCount;
		//char name[MAXSTR];
	};

	BOOL getTableInfo(ea_t ea, vtinfo &info);

	// Returns TRUE if mangled name indicates a vftable
	inline BOOL isValid(LPCSTR name){ return(*((PDWORD) name) == 0x375F3F3F /*"??_7"*/); }

	// Identify and name common member functions
	//void processMembers(LPCTSTR name, ea_t eaStart, ea_t eaEnd);
}


// ****************************************************************************
// File: Vftable.cpp
// Desc: Virtual function table parsing support
//
// ****************************************************************************
#include "stdafx.h"
#include "Main.h"
#include "Vftable.h"
#include "RTTI.h"

/*
namespace vftable
{
	int tryKnownMember(LPCTSTR name, ea_t eaMember);
};
*/

// Attempt to get information of and fix vftable at address
// Return TRUE along with info if valid vftable parsed at address
BOOL vftable::getTableInfo(ea_t ea, vtinfo &info)
{
	// Start of a vft should have an xref and a name (auto, or user, etc).
    // Ideal flags 32bit: FF_DWRD, FF_0OFF, FF_REF, FF_NAME, FF_DATA, FF_IVL
    //dumpFlags(ea);
    flags_t flags = get_flags(ea);
	if(has_xref(flags) && has_any_name(flags) && (isEa(flags) || is_unknown(flags)))
    {
		ZeroMemory(&info, sizeof(vtinfo));

        // Get raw (auto-generated mangled, or user named) vft name
        //if (!get_name(BADADDR, ea, info.name, SIZESTR(info.name)))
        //    msg(EAFORMAT" ** vftable::getTableInfo(): failed to get raw name!\n", ea);

        // Determine the vft's method count
        ea_t start = info.start = ea;
        while (TRUE)
        {
            // Should be an ea_t sized offset to a function here (could be unknown if dirty IDB)
            // Ideal flags for 32bit: FF_DWRD, FF_0OFF, FF_REF, FF_NAME, FF_DATA, FF_IVL
            //dumpFlags(ea);
            flags_t indexFlags = get_flags(ea);
            if (!(isEa(indexFlags) || is_unknown(indexFlags)))
            {
                //msg(" ******* 1\n");
                break;
            }

            // Look at what this (assumed vftable index) points too
            ea_t memberPtr = getEa(ea);
            if (!(memberPtr && (memberPtr != BADADDR)))
            {
                // vft's often have a trailing zero ea_t (alignment, or?), fix it
                if (memberPtr == 0)
                    fixEa(ea);

                //msg(" ******* 2\n");
                break;
            }

            // Should see code for a good vft method here, but it could be dirty
            flags_t flags = get_flags(memberPtr);
            if (!(is_code(flags) || is_unknown(flags)))
            {
				// New for version 2.5: there are rare cases where IDA hasn't fix unresolved bytes
				// So except if the member pointer is in a code segment as a 2nd chance
				if (segment_t *s = getseg(memberPtr))
				{
					if (s->type != SEG_CODE)
					{
						//msg(" ******* 3\n");
						break;
					}
				}
				else
				{
					//msg(" ******* 3.5\n");
					break;
				}
            }


            if (ea != start)
            {
                // If we see a ref after first index it's probably the beginning of the next vft or something else
                if (has_xref(indexFlags))
                {
                    //msg(" ******* 4\n");
                    break;
                }

                // If we see a COL here it must be the start of another vftable
                if (RTTI::_RTTICompleteObjectLocator::isValid(memberPtr))
                {
                    //msg(" ******* 5\n");
                    break;
                }
            }

            // As needed fix ea_t pointer, and, or, missing code and function def here
            fixEa(ea);
            fixFunction(memberPtr);

            ea += sizeof(ea_t);
        };

        // Reached the presumed end of it
        if ((info.methodCount = ((ea - start) / sizeof(ea_t))) > 0)
        {
            info.end = ea;
            //msg(" vftable: "EAFORMAT"-"EAFORMAT", methods: %d\n", rtInfo.eaStart, rtInfo.eaEnd, rtInfo.uMethods);
            return(TRUE);
        }
    }

    //dumpFlags(ea);
    return(FALSE);
}


// Get relative jump target address
/*
static ea_t getRelJmpTarget(ea_t eaAddress)
{
	BYTE bt = get_byte(eaAddress);
	if(bt == 0xEB)
	{
		bt = get_byte(eaAddress + 1);
		if(bt & 0x80)
			return(eaAddress + 2 - ((~bt & 0xFF) + 1));
		else
			return(eaAddress + 2 + bt);
	}
	else
	if(bt == 0xE9)
	{
		UINT dw = get_32bit(eaAddress + 1);
		if(dw & 0x80000000)
			return(eaAddress + 5 - (~dw + 1));
		else
			return(eaAddress + 5 + dw);
	}
	else
		return(BADADDR);
}
*/

/*
#define SN_constructor 1
#define SN_destructor  2
#define SN_vdestructor 3
#define SN_scalardtr   4
#define SN_vectordtr   5
*/

// Try to identify and place known class member types
/*
int vftable::tryKnownMember(LPCTSTR name, ea_t eaMember)
{
	int iType = 0;

	#define IsPattern(Address, Pattern) (find_binary(Address, Address+(SIZESTR(Pattern)/2), Pattern, 16, (SEARCH_DOWN | SEARCH_NOBRK | SEARCH_NOSHOW)) == Address)

	if(eaMember && (eaMember != BADADDR))
	{
		// Skip if it already has a name
		flags_t flags = get_flags((ea_t) eaMember);
		if(!has_name(flags) || has_dummy_name(flags))
		{
			// Should be code
			if(is_code(flags))
			{
				ea_t eaAddress = eaMember;

				// E9 xx xx xx xx   jmp   xxxxxxx
				BYTE Byte = get_byte(eaAddress);
				if((Byte == 0xE9) ||(Byte == 0xEB))
				{
					return(tryKnownMember(name, getRelJmpTarget(eaAddress)));
				}
				else
				if(IsPattern(eaAddress, " "))
				{

				}
			}
			else
				msg(" "EAFORMAT" ** Not code at this member! **\n", eaMember);
		}
	}

	return(iType);
}
*/

/*
TODO: On hold for now.
Do we really care about detected ctors and dtors?
Is it helpful vs the problems of naming member functions?
*/


// Process vftable member functions
/*
// TODO: Just try the fix missing function code
void vftable::processMembers(LPCTSTR lpszName, ea_t eaStart, ea_t eaEnd)
{
	//msg(" "EAFORMAT" to "EAFORMAT"\n", eaStart, eaEnd);

	ea_t eaAddress = eaStart;

	while(eaAddress < eaEnd)
	{
		ea_t eaMember;
		if(GetVerify32_t(eaAddress, eaMember))
		{
			// Missing/bad code?
			if(!get_func(eaMember))
			{
				//msg(" "EAFORMAT" ** No member function here! **\n", eaMember);
                fixFunction(eaMember);
			}

			tryKnownMember(lpszName, eaMember);
		}
		else
			msg(" "EAFORMAT" ** Failed to read member pointer! **\n", eaAddress);

		eaAddress += 4;
	};
}
*/
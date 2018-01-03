
// ****************************************************************************
// File: RTTI.cpp
// Desc: Run-Time Type Information (RTTI) support
//
// ****************************************************************************
#include "stdafx.h"
#include "Core.h"
#include "RTTI.h"
#include "Vftable.h"

// const Name::`vftable'
static LPCSTR FORMAT_RTTI_VFTABLE = "??_7%s6B@";
static LPCSTR FORMAT_RTTI_VFTABLE_PREFIX = "??_7";
// type 'RTTI Type Descriptor'
static LPCSTR FORMAT_RTTI_TYPE = "??_R0?%s@8";
// 'RTTI Base Class Descriptor at (a,b,c,d)'
static LPCSTR FORMAT_RTTI_BCD = "??_R1%s%s%s%s%s8";
// `RTTI Base Class Array'
static LPCSTR FORMAT_RTTI_BCA = "??_R2%s8";
// 'RTTI Class Hierarchy Descriptor'
static LPCSTR FORMAT_RTTI_CHD = "??_R3%s8";
// 'RTTI Complete Object Locator'
static LPCSTR FORMAT_RTTI_COL = "??_R4%s6B@";
static LPCSTR FORMAT_RTTI_COL_PREFIX = "??_R4";

// Skip type_info tag for class/struct mangled name strings
#define SKIP_TD_TAG(_str) (_str + SIZESTR(".?Ax"))

// Class name list container
struct bcdInfo
{
    char m_name[496];
    UINT m_attribute;
	RTTI::PMD m_pmd;
};
typedef qvector<bcdInfo> bcdList;

namespace RTTI
{
    void getBCDInfo(ea_t col, __out bcdList &nameList, __out UINT &numBaseClasses);
};


typedef std::unordered_map<ea_t, qstring> stringMap;
static stringMap stringCache;
static eaSet tdSet;
static eaSet chdSet;
static eaSet bcdSet;

void RTTI::freeWorkingData()
{
    stringCache.clear();
    tdSet.clear();
    chdSet.clear();
    bcdSet.clear();
}

// Mangle number for labeling
static LPSTR mangleNumber(UINT number, __out_bcount(16) LPSTR buffer)
{
	//
	// 0 = A@
	// X = X-1 (1 <= X <= 10)
	// -X = ? (X - 1)
	// 0x0..0xF = 'A'..'P'

	// Can only get unsigned inputs
	int iNumber = *((PINT) &number);

	if(iNumber == 0)
		return("A@");
	else
	{
		int sign = 0;
		if(iNumber < 0)
		{
			sign = 1;
			iNumber = -iNumber;
		}

		if(iNumber <= 10)
		{
			_snprintf(buffer, 16, "%s%d", (sign ? "?" : ""), (iNumber - 1));
			return(buffer);
		}
		else
		{
			// How many digits max?
			char buffer2[512] = {0};
			int  iCount = sizeof(buffer2);

			while((iNumber > 0) && (iCount > 0))
			{
				buffer2[sizeof(buffer2) - iCount] = ('A' + (iNumber % 16));
				iNumber = (iNumber / 16);
				iCount--;
			};

			if(iCount == 0)
				msg(" *** mangleNumber() Overflow! ***");

			_snprintf(buffer, 16, "%s%s@", (sign ? "?" : ""), buffer2);
			return(buffer);
		}
	}
}


// Return a short label indicating the CHD inheritance type by attributes
// TODO: Consider CHD_AMBIGUOUS?
static LPCSTR attributeLabel(UINT attributes)
{
    if ((attributes & 3) == RTTI::CHD_MULTINH)
		return("[MI]");
	else
    if ((attributes & 3) == RTTI::CHD_VIRTINH)
		return("[VI]");
	else
    if ((attributes & 3) == (RTTI::CHD_MULTINH | RTTI::CHD_VIRTINH))
		return("[MI VI]");
    else
        return("");
}


// Attempt to serialize a managed name until it succeeds
static BOOL serializeName(ea_t ea, __in LPCSTR name)
{
    for (int i = 0; i < 1000000; i++)
    {
        char buffer[MAXSTR]; buffer[SIZESTR(buffer)] = 0;
        _snprintf(buffer, SIZESTR(buffer), "%s_%d", name, i);
        if (set_name(ea, buffer, (SN_NON_AUTO | SN_NOWARN)))
            return(TRUE);
    }
    return(FALSE);
}


// Add RTTI definitions to IDA
// Structure type IDs
static tid_t s_type_info_ID = 1;
static tid_t s_ClassHierarchyDescriptor_ID = 2;
static tid_t s_PMD_ID = 3;
static tid_t s_BaseClassDescriptor_ID = 4;
static tid_t s_CompleteObjectLocator_ID = 5;

// Create structure definition w/comment
static struc_t *AddStruct(__out tid_t &id, __in LPCSTR name, LPCSTR comment)
{
    struc_t *structPtr = NULL;

    // If it exists get current def else create it
    id = get_struc_id(name);
    if (id == BADADDR)
        id = add_struc(BADADDR, name);
    if (id != BADADDR)
        structPtr = get_struc(id);

    if (structPtr)
    {
        // Clear the old one out if it exists and set the comment
        int dd = del_struc_members(structPtr, 0, MAXADDR);
        dd = dd;
        bool rr = set_struc_cmt(id, comment, true);
        rr = rr;
    }
    else
        msg("** AddStruct(\"%s\") failed!\n", name);

    return(structPtr);
}

void RTTI::addDefinitionsToIda()
{
	// Member type info for 32bit offset types
    opinfo_t mtoff;
    ZeroMemory(&mtoff, sizeof(refinfo_t));
    #ifndef __EA64__
	mtoff.ri.flags  = REF_OFF32;
    #define EAOFFSET (off_flag() | dword_flag())
    #else
    mtoff.ri.flags = REF_OFF64;
    #define EAOFFSET (off_flag() | qwrd_flag())
    #endif
	mtoff.ri.target = BADADDR;

    // Add structure member
    #define ADD_MEMBER(_flags, _mtoff, TYPE, _member)\
    {\
	    TYPE _type;\
        (void)_type;\
	    if(add_struc_member(structPtr, #_member, (ea_t)offsetof(TYPE, _member), (_flags), _mtoff, (asize_t)sizeof(_type._member)) != 0)\
		    msg(" ** ADD_MEMBER(): %s failed! %d, %d **\n", #_member, offsetof(TYPE, _member), sizeof(_type._member));\
    }

    struc_t *structPtr;
    if (structPtr = AddStruct(s_type_info_ID, "type_info", "RTTI std::type_info class (#classinformer)"))
    {
        ADD_MEMBER(EAOFFSET, &mtoff, RTTI::type_info, vfptr);
        ADD_MEMBER(dword_flag(), NULL, RTTI::type_info, _M_data);

        // Name string zero size
        opinfo_t mt;
        ZeroMemory(&mt, sizeof(refinfo_t));
        if(addStrucMember(structPtr, "_M_d_name", offsetof(RTTI::type_info, _M_d_name), strlit_flag(), &mt, 0) != 0)
            msg("** addDefinitionsToIda():  _M_d_name failed! \n");
    }

    // Must come before the following  "_RTTIBaseClassDescriptor"
    if (structPtr = AddStruct(s_PMD_ID, "_PMD", "RTTI Base class descriptor displacement container (#classinformer)"))
	{
		ADD_MEMBER(dword_flag(), NULL, RTTI::PMD, mdisp);
		ADD_MEMBER(dword_flag(), NULL, RTTI::PMD, pdisp);
		ADD_MEMBER(dword_flag(), NULL, RTTI::PMD, vdisp);
	}

    if (structPtr = AddStruct(s_ClassHierarchyDescriptor_ID, "_RTTIClassHierarchyDescriptor", "RTTI Class Hierarchy Descriptor (#classinformer)"))
    {
        ADD_MEMBER(dword_flag(), NULL, RTTI::_RTTIClassHierarchyDescriptor, signature);
        ADD_MEMBER(dword_flag(), NULL, RTTI::_RTTIClassHierarchyDescriptor, attributes);
        ADD_MEMBER(dword_flag(), NULL, RTTI::_RTTIClassHierarchyDescriptor, numBaseClasses);
        #ifndef __EA64__
        ADD_MEMBER(EAOFFSET, &mtoff, RTTI::_RTTIClassHierarchyDescriptor, baseClassArray);
        #else
        ADD_MEMBER(dword_flag(), NULL, RTTI::_RTTIClassHierarchyDescriptor, baseClassArray);
        #endif
    }

    if (structPtr = AddStruct(s_BaseClassDescriptor_ID, "_RTTIBaseClassDescriptor", "RTTI Base Class Descriptor (#classinformer)"))
	{
        #ifndef __EA64__
        ADD_MEMBER(EAOFFSET, &mtoff, RTTI::_RTTIBaseClassDescriptor, typeDescriptor);
        #else
        ADD_MEMBER(dword_flag(), NULL, RTTI::_RTTIBaseClassDescriptor, typeDescriptor);
        #endif
		ADD_MEMBER(dword_flag(), NULL, RTTI::_RTTIBaseClassDescriptor, numContainedBases);
        opinfo_t mt;
        ZeroMemory(&mt, sizeof(refinfo_t));
		mt.tid = s_PMD_ID;
		ADD_MEMBER(stru_flag(), &mt, RTTI::_RTTIBaseClassDescriptor, pmd);
        ADD_MEMBER(dword_flag(), NULL, RTTI::_RTTIBaseClassDescriptor, attributes);
	}

	if(structPtr = AddStruct(s_CompleteObjectLocator_ID, "_RTTICompleteObjectLocator", "RTTI Complete Object Locator (#classinformer)"))
	{
		ADD_MEMBER(dword_flag(), NULL, RTTI::_RTTICompleteObjectLocator, signature);
		ADD_MEMBER(dword_flag(), NULL, RTTI::_RTTICompleteObjectLocator, offset);
		ADD_MEMBER(dword_flag(), NULL, RTTI::_RTTICompleteObjectLocator, cdOffset);
        #ifndef __EA64__
        ADD_MEMBER(EAOFFSET, &mtoff, RTTI::_RTTICompleteObjectLocator, typeDescriptor);
        ADD_MEMBER(EAOFFSET, &mtoff, RTTI::_RTTICompleteObjectLocator, classDescriptor);
        #else
        ADD_MEMBER(dword_flag(), NULL, RTTI::_RTTICompleteObjectLocator, typeDescriptor);
        ADD_MEMBER(dword_flag(), NULL, RTTI::_RTTICompleteObjectLocator, classDescriptor);
        ADD_MEMBER(dword_flag(), NULL, RTTI::_RTTICompleteObjectLocator, objectBase);
        #endif
	}

    #undef ADD_MEMBER
}

// Version 1.05, manually set fields and then try "create_struct()"
// If it fails at least the fields should be set
static void create_structRTTI(ea_t ea, tid_t tid, __in_opt LPSTR typeName = NULL, BOOL bHasChd = FALSE)
{
	#define putDword(ea) create_dword(ea, sizeof(DWORD))
    #ifndef __EA64__
    #define putEa(ea) create_dword(ea, sizeof(ea_t))
    #else
    #define putEa(ea) doQwrd(ea, sizeof(ea_t))
    #endif

	if(tid == s_type_info_ID)
	{
        _ASSERT(typeName != NULL);
		UINT nameLen    = (strlen(typeName) + 1);
        UINT structSize = (offsetof(RTTI::type_info, _M_d_name) + nameLen);

		// Place struct
        setUnknown(ea, structSize);
        BOOL result = FALSE;
        if (optionPlaceStructs)
            result = create_struct(ea, structSize, s_type_info_ID);
        if (!result)
        {
            putEa(ea + offsetof(RTTI::type_info, vfptr));
            putEa(ea + offsetof(RTTI::type_info, _M_data));
            create_strlit((ea + offsetof(RTTI::type_info, _M_d_name)), nameLen);
        }

        // sh!ft: End should be aligned
        ea_t end = (ea + offsetof(RTTI::type_info, _M_d_name) + nameLen);
        if (end % 4)
            create_align(end, (4 - (end % 4)), 0);
	}
	else
    if (tid == s_ClassHierarchyDescriptor_ID)
    {
        setUnknown(ea, sizeof(RTTI::_RTTIClassHierarchyDescriptor));
        BOOL result = FALSE;
        if (optionPlaceStructs)
            result = create_struct(ea, sizeof(RTTI::_RTTIClassHierarchyDescriptor), s_ClassHierarchyDescriptor_ID);
        if (!result)
        {
            putDword(ea + offsetof(RTTI::_RTTIClassHierarchyDescriptor, signature));
            putDword(ea + offsetof(RTTI::_RTTIClassHierarchyDescriptor, attributes));
            putDword(ea + offsetof(RTTI::_RTTIClassHierarchyDescriptor, numBaseClasses));
            #ifndef __EA64__
            putEa(ea + offsetof(RTTI::_RTTIClassHierarchyDescriptor, baseClassArray));
            #else
            putDword(ea + offsetof(RTTI::_RTTIClassHierarchyDescriptor, baseClassArray));
            #endif
        }
    }
    else
    if (tid == s_BaseClassDescriptor_ID)
    {
        setUnknown(ea, sizeof(RTTI::_RTTIBaseClassDescriptor));
        create_structRTTI(ea + offsetof(RTTI::_RTTIBaseClassDescriptor, pmd), s_PMD_ID);
        BOOL result = FALSE;
        if (optionPlaceStructs)
            result = create_struct(ea, sizeof(RTTI::_RTTIBaseClassDescriptor), s_BaseClassDescriptor_ID);
        if (!result)
        {
            #ifndef __EA64__
            putEa(ea + offsetof(RTTI::_RTTIBaseClassDescriptor, typeDescriptor));
            #else
            putDword(ea + offsetof(RTTI::_RTTIBaseClassDescriptor, typeDescriptor));
            #endif

            putDword(ea + offsetof(RTTI::_RTTIBaseClassDescriptor, numContainedBases));
            putDword(ea + offsetof(RTTI::_RTTIBaseClassDescriptor, attributes));
            if (bHasChd)
            {
                //_RTTIClassHierarchyDescriptor *classDescriptor; *X64 int32 offset
                #ifndef __EA64__
                putEa(ea + (offsetof(RTTI::_RTTIBaseClassDescriptor, attributes) + sizeof(UINT)));
                #else
                putDword(ea + (offsetof(RTTI::_RTTIBaseClassDescriptor, attributes) + sizeof(UINT)));
                #endif
            }
        }
    }
    else
	if(tid == s_PMD_ID)
	{
		setUnknown(ea, sizeof(RTTI::PMD));
        BOOL result = FALSE;
        if (optionPlaceStructs)
            result = create_struct(ea, sizeof(RTTI::PMD), s_PMD_ID);
        if (!result)
        {
            putDword(ea + offsetof(RTTI::PMD, mdisp));
            putDword(ea + offsetof(RTTI::PMD, pdisp));
            putDword(ea + offsetof(RTTI::PMD, vdisp));
        }
	}
    else
	if(tid == s_CompleteObjectLocator_ID)
	{
		setUnknown(ea, sizeof(RTTI::_RTTICompleteObjectLocator));
        BOOL result = FALSE;
        if (optionPlaceStructs)
            result = create_struct(ea, sizeof(RTTI::_RTTICompleteObjectLocator), s_CompleteObjectLocator_ID);
        if (!result)
        {
            putDword(ea + offsetof(RTTI::_RTTICompleteObjectLocator, signature));
            putDword(ea + offsetof(RTTI::_RTTICompleteObjectLocator, offset));
            putDword(ea + offsetof(RTTI::_RTTICompleteObjectLocator, cdOffset));

            #ifndef __EA64__
            putEa(ea + offsetof(RTTI::_RTTICompleteObjectLocator, typeDescriptor));
            putEa(ea + offsetof(RTTI::_RTTICompleteObjectLocator, classDescriptor));
            #else
            putDword(ea + offsetof(RTTI::_RTTICompleteObjectLocator, typeDescriptor));
            putDword(ea + offsetof(RTTI::_RTTICompleteObjectLocator, classDescriptor));
            putDword(ea + offsetof(RTTI::_RTTICompleteObjectLocator, objectBase));
            #endif
        }
	}
	else
	{
		_ASSERT(FALSE);
	}
}


// Read ASCII string from IDB at address
static int readIdaString(ea_t ea, __out LPSTR buffer, int bufferSize)
{
    // Return cached name if it exists
    stringMap::iterator it = stringCache.find(ea);
    if (it != stringCache.end())
    {
        LPCSTR str = it->second.c_str();
        int len = strlen(str);
        if (len > bufferSize) len = bufferSize;
        strncpy(buffer, str, len); buffer[len] = 0;
        return(len);
    }
    else
    {
        // Read string at ea if it exists
        int len = get_max_ascii_length(ea, ASCSTR_C, ALOPT_IGNHEADS);
        if (len > 0)
        {
            if (len > bufferSize) len = bufferSize;
            if (get_ascii_contents2(ea, len, ASCSTR_C, buffer, bufferSize))
            {
                // Cache it
                buffer[len - 1] = 0;
                stringCache[ea] = buffer;
            }
            else
                len = 0;
        }
        return(len);
    }
}


// --------------------------- Type descriptor ---------------------------

// Get type name into a buffer
// type_info assumed to be valid
int RTTI::type_info::getName(ea_t typeInfo, __out LPSTR buffer, int bufferSize)
{
    return(readIdaString(typeInfo + offsetof(type_info, _M_d_name), buffer, bufferSize));
}

// A valid type_info/TypeDescriptor at pointer?
BOOL RTTI::type_info::isValid(ea_t typeInfo)
{
    // TRUE if we've already seen it
    if (tdSet.find(typeInfo) != tdSet.end())
        return(TRUE);

    if (is_loaded(typeInfo))
	{
		// Verify what should be a vftable
        ea_t ea = getEa(typeInfo + offsetof(type_info, vfptr));
        if (is_loaded(ea))
		{
            // _M_data should be NULL statically
            ea_t _M_data = BADADDR;
            if (getVerifyEa((typeInfo + offsetof(type_info, _M_data)), _M_data))
            {
                if (_M_data == 0)
                    return(isTypeName(typeInfo + offsetof(type_info, _M_d_name)));
            }
		}
	}

	return(FALSE);
}

// Returns TRUE if known typename at address
BOOL RTTI::type_info::isTypeName(ea_t name)
{
    // Should start with a period
    if (get_byte(name) == '.')
    {
        // Read the rest of the possible name string
        char buffer[MAXSTR]; buffer[0] = buffer[SIZESTR(buffer)] = 0;
        if (readIdaString(name, buffer, SIZESTR(buffer)))
        {
            // Should be valid if it properly demangles
            if (LPSTR s = __unDName(NULL, buffer+1 /*skip the '.'*/, 0, (_Alloc)malloc, free, (UNDNAME_32_BIT_DECODE | UNDNAME_TYPE_ONLY)))
            {
                free(s);
                return(TRUE);
            }
        }
    }
    return(FALSE);
}

// Put struct and place name at address
void RTTI::type_info::doStruct(ea_t typeInfo)
{
    // Only place once per address
    if (tdSet.find(typeInfo) != tdSet.end())
        return;
    else
        tdSet.insert(typeInfo);

	// Get type name
	char name[MAXSTR]; name[0] = name[SIZESTR(name)] = 0;
    int nameLen = getName(typeInfo, name, SIZESTR(name));

	create_structRTTI(typeInfo, s_type_info_ID, name);
    if (nameLen > 0)
    {
        if (!hasUniqueName(typeInfo))
        {
            // Set decorated name/label
            char name2[MAXSTR]; name2[SIZESTR(name2)] = 0;
            _snprintf(name2, SIZESTR(name2), FORMAT_RTTI_TYPE, name + 2);
            set_name(typeInfo, name2, (SN_NON_AUTO | SN_NOWARN | SN_NOCHECK));
        }
    }
    #ifdef _DEVMODE
    else
        _ASSERT(FALSE);
    #endif
}


// --------------------------- Complete Object Locator ---------------------------

// Return TRUE if address is a valid RTTI structure
BOOL RTTI::_RTTICompleteObjectLocator::isValid(ea_t col)
{
    if (is_loaded(col))
    {
        // Check signature
        UINT signature = -1;
        if (getVerify32_t((col + offsetof(_RTTICompleteObjectLocator, signature)), signature))
        {
            #ifndef __EA64__
            if (signature == 0)
            {
                // Check valid type_info
                ea_t typeInfo = getEa(col + offsetof(_RTTICompleteObjectLocator, typeDescriptor));
                if (RTTI::type_info::isValid(typeInfo))
                {
                    ea_t classDescriptor = getEa(col + offsetof(_RTTICompleteObjectLocator, classDescriptor));
                    if (RTTI::_RTTIClassHierarchyDescriptor::isValid(classDescriptor))
                    {
                        //msg(EAFORMAT" " EAFORMAT " " EAFORMAT " \n", col, typeInfo, classDescriptor);
                        return(TRUE);
                    }
                }
            }
            #else
            if (signature == 1)
			{
                // TODO: Can any of these be zero and still be valid?
                UINT objectLocator = get_32bit(col + offsetof(RTTI::_RTTICompleteObjectLocator, objectBase));
                if (objectLocator != 0)
                {
                    UINT tdOffset = get_32bit(col + offsetof(_RTTICompleteObjectLocator, typeDescriptor));
                    if (tdOffset != 0)
                    {
                        UINT cdOffset = get_32bit(col + offsetof(RTTI::_RTTICompleteObjectLocator, classDescriptor));
                        if (cdOffset != 0)
                        {
                            ea_t colBase = (col - (UINT64)objectLocator);

                            ea_t typeInfo = (colBase + (UINT64)tdOffset);
                            if (RTTI::type_info::isValid(typeInfo))
                            {
                                ea_t classDescriptor = (colBase + (UINT64) cdOffset);
                                if (RTTI::_RTTIClassHierarchyDescriptor::isValid(classDescriptor, colBase))
                                {
                                    //msg(EAFORMAT" " EAFORMAT " " EAFORMAT " \n", col, typeInfo, classDescriptor);
                                    return(TRUE);
                                }
                            }
                        }
                    }
                }
			}
            #endif
		}
	}

	return(FALSE);
}

// Same as above but from an already validated type_info perspective
#ifndef __EA64__
BOOL RTTI::_RTTICompleteObjectLocator::isValid2(ea_t col)
{
    // 'signature' should be zero
    UINT signature = -1;
    if (getVerify32_t((col + offsetof(_RTTICompleteObjectLocator, signature)), signature))
    {
        if (signature == 0)
        {
            // Verify CHD
            ea_t classDescriptor = getEa(col + offsetof(_RTTICompleteObjectLocator, classDescriptor));
            if (classDescriptor && (classDescriptor != BADADDR))
                return(RTTI::_RTTIClassHierarchyDescriptor::isValid(classDescriptor));
        }
    }

    return(FALSE);
}
#endif

// Place full COL hierarchy structures
void RTTI::_RTTICompleteObjectLocator::doStruct(ea_t col)
{
    create_structRTTI(col, s_CompleteObjectLocator_ID);

    #ifndef __EA64__
    // Put type_def
    ea_t typeInfo = getEa(col + offsetof(RTTI::_RTTICompleteObjectLocator, typeDescriptor));
    RTTI::type_info::doStruct(typeInfo);

    // Place CHD hierarchy
    ea_t classDescriptor = getEa(col + offsetof(_RTTICompleteObjectLocator, classDescriptor));
	RTTI::_RTTIClassHierarchyDescriptor::doStruct(classDescriptor);
    #else
    UINT tdOffset = get_32bit(col + offsetof(_RTTICompleteObjectLocator, typeDescriptor));
    UINT cdOffset = get_32bit(col + offsetof(RTTI::_RTTICompleteObjectLocator, classDescriptor));
    UINT objectLocator = get_32bit(col + offsetof(RTTI::_RTTICompleteObjectLocator, objectBase));
    ea_t colBase = (col - (UINT64)objectLocator);

    ea_t typeInfo = (colBase + (UINT64)tdOffset);
    type_info::create_struct(typeInfo);

    ea_t classDescriptor = (colBase + (UINT64)cdOffset);
    _RTTIClassHierarchyDescriptor::create_struct(classDescriptor, colBase);

    // Set absolute address comments
    char buffer[64];
    sprintf(buffer, "0x" EAFORMAT, typeInfo);
    set_cmt((col + offsetof(RTTI::_RTTICompleteObjectLocator, typeDescriptor)), buffer, TRUE);
    sprintf(buffer, "0x" EAFORMAT, classDescriptor);
    set_cmt((col + offsetof(RTTI::_RTTICompleteObjectLocator, classDescriptor)), buffer, TRUE);
    #endif
}


// --------------------------- Base Class Descriptor ---------------------------

// Return TRUE if address is a valid BCD
BOOL RTTI::_RTTIBaseClassDescriptor::isValid(ea_t bcd, ea_t colBase64)
{
    // TRUE if we've already seen it
    if (bcdSet.find(bcd) != bcdSet.end())
        return(TRUE);

    if (is_loaded(bcd))
    {
        // Check attributes flags first
        UINT attributes = -1;
        if (getVerify32_t((bcd + offsetof(_RTTIBaseClassDescriptor, attributes)), attributes))
        {
            // Valid flags are the lower byte only
            if ((attributes & 0xFFFFFF00) == 0)
            {
                // Check for valid type_info
                #ifndef __EA64__
                return(RTTI::type_info::isValid(getEa(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor))));
                #else
                UINT tdOffset = get_32bit(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor));
                ea_t typeInfo = (colBase64 + (UINT64) tdOffset);
                return(RTTI::type_info::isValid(typeInfo));
                #endif
            }
        }
    }

    return(FALSE);
}

// Put BCD structure at address
void RTTI::_RTTIBaseClassDescriptor::doStruct(ea_t bcd, __out_bcount(MAXSTR) LPSTR baseClassName, ea_t colBase64)
{
    // Only place it once
    if (bcdSet.find(bcd) != bcdSet.end())
    {
        // Seen already, just return type name
        #ifndef __EA64__
        ea_t typeInfo = getEa(bcd + offsetof(RTTI::_RTTIBaseClassDescriptor, typeDescriptor));
        #else
        UINT tdOffset = get_32bit(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor));
        ea_t typeInfo = (colBase64 + (UINT64) tdOffset);
        #endif

        char buffer[MAXSTR]; buffer[0] = buffer[SIZESTR(buffer)] = 0;
		RTTI::type_info::getName(typeInfo, buffer, SIZESTR(buffer));
        strcpy(baseClassName, SKIP_TD_TAG(buffer));
        return;
    }
    else
        bcdSet.insert(bcd);

    if (is_loaded(bcd))
    {
        UINT attributes = get_32bit(bcd + offsetof(RTTI::_RTTIBaseClassDescriptor, attributes));
        create_structRTTI(bcd, s_BaseClassDescriptor_ID, NULL, ((attributes & RTTI::BCD_HASPCHD) > 0));

        // Has appended CHD?
        if (attributes & RTTI::BCD_HASPCHD)
        {
            // yes, process it
            ea_t chdOffset = (bcd + (offsetof(RTTI::_RTTIBaseClassDescriptor, attributes) + sizeof(UINT)));

            #ifndef __EA64__
            fixEa(chdOffset);
            ea_t chd = getEa(chdOffset);
            #else
            fixDword(chdOffset);
            UINT chdOffset32 = get_32bit(chdOffset);
            ea_t chd = (colBase64 + (UINT64) chdOffset32);

            char buffer[64];
            sprintf(buffer, "0x" EAFORMAT, chd);
            set_cmt(chdOffset, buffer, TRUE);
            #endif

            if (is_loaded(chd))
				RTTI::_RTTIClassHierarchyDescriptor::doStruct(chd, colBase64);
            else
                _ASSERT(FALSE);
        }

        // Place type_info struct
        #ifndef __EA64__
        ea_t typeInfo = getEa(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor));
        #else
        UINT tdOffset = get_32bit(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor));
        ea_t typeInfo = (colBase64 + (UINT64)tdOffset);
        #endif
		RTTI::type_info::doStruct(typeInfo);

        // Get raw type/class name
        char buffer[MAXSTR]; buffer[0] = buffer[SIZESTR(buffer)] = 0;
		RTTI::type_info::getName(typeInfo, buffer, SIZESTR(buffer));
        strcpy(baseClassName, SKIP_TD_TAG(buffer));

        if (!optionPlaceStructs && attributes)
        {
            // Place attributes comment
            if (!has_cmt(get_full_flags(bcd + offsetof(_RTTIBaseClassDescriptor, attributes))))
            {
                qstring s("");
                BOOL b = 0;
                #define ATRIBFLAG(_flag) { if (attributes & _flag) { if (b) s += " | ";  s += #_flag; b = 1; } }
                ATRIBFLAG(BCD_NOTVISIBLE);
                ATRIBFLAG(BCD_AMBIGUOUS);
                ATRIBFLAG(BCD_PRIVORPROTINCOMPOBJ);
                ATRIBFLAG(BCD_PRIVORPROTBASE);
                ATRIBFLAG(BCD_VBOFCONTOBJ);
                ATRIBFLAG(BCD_NONPOLYMORPHIC);
                ATRIBFLAG(BCD_HASPCHD);
                #undef ATRIBFLAG
                set_cmt((bcd + offsetof(_RTTIBaseClassDescriptor, attributes)), s.c_str(), TRUE);
            }
        }

        // Give it a label
        if (!hasUniqueName(bcd))
        {
            // Name::`RTTI Base Class Descriptor at (0, -1, 0, 0)'
            ZeroMemory(buffer, sizeof(buffer));
            char buffer1[32] = { 0 }, buffer2[32] = { 0 }, buffer3[32] = { 0 }, buffer4[32] = { 0 };
            _snprintf(buffer, SIZESTR(buffer), FORMAT_RTTI_BCD,
                mangleNumber(get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, mdisp))), buffer1),
                mangleNumber(get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, pdisp))), buffer2),
                mangleNumber(get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, vdisp))), buffer3),
                mangleNumber(attributes, buffer4),
                baseClassName);

            if (!set_name(bcd, buffer, (SN_NON_AUTO | SN_NOWARN)))
                serializeName(bcd, buffer);
        }
    }
    else
        _ASSERT(FALSE);
}


// --------------------------- Class Hierarchy Descriptor ---------------------------

// Return true if address is a valid CHD structure
BOOL RTTI::_RTTIClassHierarchyDescriptor::isValid(ea_t chd, ea_t colBase64)
{
    // TRUE if we've already seen it
    if (chdSet.find(chd) != chdSet.end())
        return(TRUE);

    if (is_loaded(chd))
    {
        // signature should be zero statically
        UINT signature = -1;
        if (getVerify32_t((chd + offsetof(_RTTIClassHierarchyDescriptor, signature)), signature))
        {
            if (signature == 0)
            {
                // Check attributes flags
                UINT attributes = -1;
                if (getVerify32_t((chd + offsetof(_RTTIClassHierarchyDescriptor, attributes)), attributes))
                {
                    // Valid flags are the lower nibble only
                    if ((attributes & 0xFFFFFFF0) == 0)
                    {
                        // Should have at least one base class
                        UINT numBaseClasses = 0;
                        if (getVerify32_t((chd + offsetof(_RTTIClassHierarchyDescriptor, numBaseClasses)), numBaseClasses))
                        {
                            if (numBaseClasses >= 1)
                            {
                                // Check the first BCD entry
                                #ifndef __EA64__
                                ea_t baseClassArray = getEa(chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
                                #else
                                UINT baseClassArrayOffset = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
                                ea_t baseClassArray = (colBase64 + (UINT64) baseClassArrayOffset);
                                #endif

                                if (is_loaded(baseClassArray))
                                {
                                    #ifndef __EA64__
                                    ea_t baseClassDescriptor = getEa(baseClassArray);
                                    return(RTTI::_RTTIBaseClassDescriptor::isValid(baseClassDescriptor));
                                    #else
                                    ea_t baseClassDescriptor = (colBase64 + (UINT64) get_32bit(baseClassArray));
                                    return(RTTI::_RTTIBaseClassDescriptor::isValid(baseClassDescriptor, colBase64));
                                    #endif
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return(FALSE);
}


// Put CHD structure at address
void RTTI::_RTTIClassHierarchyDescriptor::doStruct(ea_t chd, ea_t colBase64)
{
    // Only place it once per address
    if (chdSet.find(chd) != chdSet.end())
        return;
    else
        chdSet.insert(chd);

    if (is_loaded(chd))
    {
        // Place CHD
        create_structRTTI(chd, s_ClassHierarchyDescriptor_ID);

        // Place attributes comment
        UINT attributes = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, attributes));
        if (!optionPlaceStructs && attributes)
        {
            if (!has_cmt(get_full_flags(chd + offsetof(_RTTIClassHierarchyDescriptor, attributes))))
            {
                qstring s("");
                BOOL b = 0;
                #define ATRIBFLAG(_flag) { if (attributes & _flag) { if (b) s += " | ";  s += #_flag; b = 1; } }
                ATRIBFLAG(CHD_MULTINH);
                ATRIBFLAG(CHD_VIRTINH);
                ATRIBFLAG(CHD_AMBIGUOUS);
                #undef ATRIBFLAG
                set_cmt((chd + offsetof(_RTTIClassHierarchyDescriptor, attributes)), s.c_str(), TRUE);
            }
        }

        // ---- Place BCD's ----
        UINT numBaseClasses = 0;
        if (getVerify32_t((chd + offsetof(_RTTIClassHierarchyDescriptor, numBaseClasses)), numBaseClasses))
        {
            // Get pointer
            #ifndef __EA64__
            ea_t baseClassArray = getEa(chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
            #else
            UINT baseClassArrayOffset = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
            ea_t baseClassArray = (colBase64 + (UINT64) baseClassArrayOffset);

            char buffer[MAXSTR];
            sprintf(buffer, "0x" EAFORMAT, baseClassArray);
            set_cmt((chd + offsetof(RTTI::_RTTIClassHierarchyDescriptor, baseClassArray)), buffer, TRUE);
            #endif

            if (baseClassArray && (baseClassArray != BADADDR))
            {
                // Create offset string based on input digits
                #ifndef __EA64__
                char format[32];
                if(numBaseClasses > 1)
                {
                    int iDigits = strlen(_itoa(numBaseClasses, format, 10));
                    if (iDigits > 1)
                        _snprintf(format, SIZESTR(format), "  BaseClass[%%0%dd]", iDigits);
                    else
                        strncpy(format, "  BaseClass[%d]", SIZESTR(format));
                }
                #else
                char format[128];
                if (numBaseClasses > 1)
                {
                    int iDigits = strlen(_itoa(numBaseClasses, format, 10));
                    if (iDigits > 1)
                        _snprintf(format, SIZESTR(format), "  BaseClass[%%0%dd] 0x%016I64X", iDigits);
                    else
                        strncpy(format, "  BaseClass[%d] 0x%016I64X", SIZESTR(format));
                }
                #endif

                for (UINT i = 0; i < numBaseClasses; i++, baseClassArray += sizeof(UINT)) // sizeof(ea_t)
                {
                    #ifndef __EA64__
                    fixEa(baseClassArray);

                    // Add index comment to to it
                    if (!has_cmt(get_flags_novalue(baseClassArray)))
                    {
                        if (numBaseClasses == 1)
                            set_cmt(baseClassArray, "  BaseClass", FALSE);
                        else
                        {
                            char ptrComent[MAXSTR]; ptrComent[SIZESTR(ptrComent)] = 0;
                            _snprintf(ptrComent, SIZESTR(ptrComent), format, i);
                            set_cmt(baseClassArray, ptrComent, false);
                        }
                    }

                    // Place BCD struct, and grab the base class name
                    char baseClassName[MAXSTR];
					RTTI::_RTTIBaseClassDescriptor::doStruct(getEa(baseClassArray), baseClassName);
                    #else
                    fixDword(baseClassArray);
                    UINT bcOffset = get_32bit(baseClassArray);
                    ea_t bcd = (colBase64 + (UINT64)bcOffset);

                    // Add index comment to to it
                    if (!has_cmt(get_flags_novalue(baseClassArray)))
                    {
                        if (numBaseClasses == 1)
                        {
                            sprintf(buffer, "  BaseClass 0x" EAFORMAT, bcd);
                            set_cmt(baseClassArray, buffer, FALSE);
                        }
                        else
                        {
                            _snprintf(buffer, SIZESTR(buffer), format, i, bcd);
                            set_cmt(baseClassArray, buffer, false);
                        }
                    }

                    // Place BCD struct, and grab the base class name
                    char baseClassName[MAXSTR];
                    _RTTIBaseClassDescriptor::create_struct(bcd, baseClassName, colBase64);
                    #endif

                    // Now we have the base class name, name and label some things
                    if (i == 0)
                    {
                        // Set array name
                        if (!hasUniqueName(baseClassArray))
                        {
                            // ??_R2A@@8 = A::`RTTI Base Class Array'
                            char mangledName[MAXSTR]; mangledName[SIZESTR(mangledName)] = 0;
                            _snprintf(mangledName, SIZESTR(mangledName), FORMAT_RTTI_BCA, baseClassName);
                            if (!set_name(baseClassArray, mangledName, (SN_NON_AUTO | SN_NOWARN)))
                                serializeName(baseClassArray, mangledName);
                        }

                        // Add a spacing comment line above us
                        if (optionOverwriteComments)
                        {
                            killAnteriorComments(baseClassArray);
                            add_long_cmt(baseClassArray, true, "");
                        }
                        else
                        if (!hasAnteriorComment(baseClassArray))
                            add_long_cmt(baseClassArray, true, "");

                        // Set CHD name
                        if (!hasUniqueName(chd))
                        {
                            // A::`RTTI Class Hierarchy Descriptor'
                            char mangledName[MAXSTR]; mangledName[SIZESTR(mangledName)] = 0;
                            _snprintf(mangledName, (MAXSTR - 1), FORMAT_RTTI_CHD, baseClassName);
                            if (!set_name(chd, mangledName, (SN_NON_AUTO | SN_NOWARN)))
                                serializeName(chd, mangledName);
                        }
                    }
                }

                // Make following DWORD if it's bytes are zeros
                if (numBaseClasses > 0)
                {
                    if (is_loaded(baseClassArray))
                    {
                        if (get_32bit(baseClassArray) == 0)
                            fixDword(baseClassArray);
                    }
                }
            }
            else
                _ASSERT(FALSE);
        }
        else
            _ASSERT(FALSE);
    }
    else
        _ASSERT(FALSE);
}


// --------------------------- Vftable ---------------------------


// Get list of base class descriptor info
static void RTTI::getBCDInfo(ea_t col, __out bcdList &list, __out UINT &numBaseClasses)
{
	numBaseClasses = 0;

    #ifndef __EA64__
    ea_t chd = getEa(col + offsetof(_RTTICompleteObjectLocator, classDescriptor));
    #else
    UINT cdOffset = get_32bit(col + offsetof(RTTI::_RTTICompleteObjectLocator, classDescriptor));
    UINT objectLocator = get_32bit(col + offsetof(RTTI::_RTTICompleteObjectLocator, objectBase));
    ea_t colBase = (col - (UINT64) objectLocator);
    ea_t chd = (colBase + (UINT64) cdOffset);
    #endif

	if(chd)
	{
        if (numBaseClasses = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, numBaseClasses)))
		{
            list.resize(numBaseClasses);

			// Get pointer
            #ifndef __EA64__
            ea_t baseClassArray = getEa(chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
            #else
            UINT bcaOffset = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
            ea_t baseClassArray = (colBase + (UINT64) bcaOffset);
            #endif

			if(baseClassArray && (baseClassArray != BADADDR))
			{
				for(UINT i = 0; i < numBaseClasses; i++, baseClassArray += sizeof(UINT)) // sizeof(ea_t)
				{
                    #ifndef __EA64__
                    // Get next BCD
                    ea_t bcd = getEa(baseClassArray);

                    // Get type name
                    ea_t typeInfo = getEa(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor));
                    #else
                    UINT bcdOffset = get_32bit(baseClassArray);
                    ea_t bcd = (colBase + (UINT64) bcdOffset);

                    UINT tdOffset = get_32bit(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor));
                    ea_t typeInfo = (colBase + (UINT64) tdOffset);
                    #endif
                    bcdInfo *bi = &list[i];
                    type_info::getName(typeInfo, bi->m_name, SIZESTR(bi->m_name));

					// Add info to list
                    UINT mdisp = get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, mdisp)));
                    UINT pdisp = get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, pdisp)));
                    UINT vdisp = get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, vdisp)));
                    // As signed int
                    bi->m_pmd.mdisp = *((PINT) &mdisp);
                    bi->m_pmd.pdisp = *((PINT) &pdisp);
                    bi->m_pmd.vdisp = *((PINT) &vdisp);
                    bi->m_attribute = get_32bit(bcd + offsetof(_RTTIBaseClassDescriptor, attributes));

					//msg("   BN: [%d] \"%s\", ATB: %04X\n", i, szBuffer1, get_32bit((ea_t) &pBCD->attributes));
					//msg("       mdisp: %d, pdisp: %d, vdisp: %d, attributes: %04X\n", *((PINT) &mdisp), *((PINT) &pdisp), *((PINT) &vdisp), attributes);
				}
			}
		}
	}
}


// Process RTTI vftable info
void RTTI::processVftable(ea_t vft, ea_t col)
{
    #ifdef __EA64__
    UINT tdOffset = get_32bit(col + offsetof(_RTTICompleteObjectLocator, typeDescriptor));
    UINT objectLocator = get_32bit(col + offsetof(RTTI::_RTTICompleteObjectLocator, objectBase));
    ea_t colBase  = (col - (UINT64) objectLocator);
    ea_t typeInfo = (colBase + (UINT64) tdOffset);
    #endif

    // Get vftable info
    vftable::vtinfo vi;
    if (vftable::getTableInfo(vft, vi))
    {
        //msg(EAFORMAT" - " EAFORMAT " c: %d\n", vi.start, vi.end, vi.methodCount);

	    // Get COL type name
        #ifndef __EA64__
        ea_t typeInfo = getEa(col + offsetof(_RTTICompleteObjectLocator, typeDescriptor));
        ea_t chd = get_32bit(col + offsetof(_RTTICompleteObjectLocator, classDescriptor));
        #else
        UINT cdOffset = get_32bit(col + offsetof(RTTI::_RTTICompleteObjectLocator, classDescriptor));
        ea_t chd = (colBase + (UINT64) cdOffset);
        #endif

        char colName[MAXSTR]; colName[0] = colName[SIZESTR(colName)] = 0;
        type_info::getName(typeInfo, colName, SIZESTR(colName));
        char demangledColName[MAXSTR];
        getPlainTypeName(colName, demangledColName);

        UINT chdAttributes = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, attributes));
        UINT offset = get_32bit(col + offsetof(_RTTICompleteObjectLocator, offset));

	    // Parse BCD info
	    bcdList list;
        UINT numBaseClasses;
	    getBCDInfo(col, list, numBaseClasses);

        BOOL sucess = FALSE, isTopLevel = FALSE;
        qstring cmt;

	    // ======= Simple or no inheritance
        if ((offset == 0) && ((chdAttributes & (CHD_MULTINH | CHD_VIRTINH)) == 0))
	    {
		    // Set the vftable name
            if (!hasUniqueName(vft))
		    {
                // Decorate raw name as a vftable. I.E. const Name::`vftable'
                char decorated[MAXSTR]; decorated[SIZESTR(decorated)] = 0;
                _snprintf(decorated, SIZESTR(decorated), FORMAT_RTTI_VFTABLE, SKIP_TD_TAG(colName));
                if (!set_name(vft, decorated, (SN_NON_AUTO | SN_NOWARN)))
                    serializeName(vft, decorated);
		    }

		    // Set COL name. I.E. const Name::`RTTI Complete Object Locator'
            if (!hasUniqueName(col))
            {
                char decorated[MAXSTR]; decorated[SIZESTR(decorated)] = 0;
                _snprintf(decorated, SIZESTR(decorated), FORMAT_RTTI_COL, SKIP_TD_TAG(colName));
                if (!set_name(col, decorated, (SN_NON_AUTO | SN_NOWARN)))
                    serializeName(col, decorated);
            }

		    // Build object hierarchy string
            int placed = 0;
            if (numBaseClasses > 1)
            {
                // Parent
                char plainName[MAXSTR];
                getPlainTypeName(list[0].m_name, plainName);
                cmt.sprnt("%s%s: ", ((list[0].m_name[3] == 'V') ? "" : "struct "), plainName);
                placed++;
                isTopLevel = ((strcmp(list[0].m_name, colName) == 0) ? TRUE : FALSE);

                // Child object hierarchy
                for (UINT i = 1; i < numBaseClasses; i++)
                {
                    // Append name
                    getPlainTypeName(list[i].m_name, plainName);
                    cmt.cat_sprnt("%s%s, ", ((list[i].m_name[3] == 'V') ? "" : "struct "), plainName);
                    placed++;
                }

                // Nix the ending ',' for the last one
                if (placed > 1)
                    cmt.remove((cmt.length() - 2), 2);
            }
            else
            {
                // Plain, no inheritance object(s)
                cmt.sprnt("%s%s: ", ((colName[3] == 'V') ? "" : "struct "), demangledColName);
                isTopLevel = TRUE;
            }
            if (placed > 1)
                cmt += ';';
            sucess = TRUE;
	    }
	    // ======= Multiple inheritance, and, or, virtual inheritance hierarchies
        else
        {
            bcdInfo *bi = NULL;
            int index = 0;

            // Must be the top level object for the type
            if (offset == 0)
            {
                _ASSERT(strcmp(colName, list[0].m_name) == 0);
                bi = &list[0];
                isTopLevel = TRUE;
            }
            else
            {
                // Get our object BCD level by matching COL offset to displacement
                for (UINT i = 0; i < numBaseClasses; i++)
                {
                    if (list[i].m_pmd.mdisp == offset)
                    {
                        bi = &list[i];
                        index = i;
                        break;
                    }
                }

                // If not found in list, use the first base object instead
                if (!bi)
                {
                    //msg("** " EAFORMAT " MI COL class offset: %X(%d) not in BCD.\n", vft, offset, offset);
                    for (UINT i = 0; i < numBaseClasses; i++)
                    {
                        if (list[i].m_pmd.pdisp != -1)
                        {
                            bi = &list[i];
                            index = i;
                            break;
                        }
                    }
                }
            }

            if (bi)
            {
                // Top object level layout
                int placed = 0;
                if (isTopLevel)
                {
                    // Set the vft name
                    if (!hasUniqueName(vft))
                    {
                        char decorated[MAXSTR]; decorated[SIZESTR(decorated)] = 0;
                        _snprintf(decorated, SIZESTR(decorated), FORMAT_RTTI_VFTABLE, SKIP_TD_TAG(colName));
                        if (!set_name(vft, decorated, (SN_NON_AUTO | SN_NOWARN)))
                            serializeName(vft, decorated);
                    }

                    // COL name
                    if (!hasUniqueName(col))
                    {
                        char decorated[MAXSTR]; decorated[SIZESTR(decorated)] = 0;
                        _snprintf(decorated, SIZESTR(decorated), FORMAT_RTTI_COL, SKIP_TD_TAG(colName));
                        if (!set_name(col, decorated, (SN_NON_AUTO | SN_NOWARN)))
                            serializeName(col, decorated);
                    }

                    // Build hierarchy string starting with parent
                    char plainName[MAXSTR];
                    getPlainTypeName(list[0].m_name, plainName);
                    cmt.sprnt("%s%s: ", ((list[0].m_name[3] == 'V') ? "" : "struct "), plainName);
                    placed++;

                    // Concatenate forward child hierarchy
                    for (UINT i = 1; i < numBaseClasses; i++)
                    {
                        getPlainTypeName(list[i].m_name, plainName);
                        cmt.cat_sprnt("%s%s, ", ((list[i].m_name[3] == 'V') ? "" : "struct "), plainName);
                        placed++;
                    }
                    if (placed > 1)
                        cmt.remove((cmt.length() - 2), 2);
                }
                else
                {
                    // Combine COL and CHD name
                    char combinedName[MAXSTR]; combinedName[SIZESTR(combinedName)] = 0;
                    _snprintf(combinedName, SIZESTR(combinedName), "%s6B%s@", SKIP_TD_TAG(colName), SKIP_TD_TAG(bi->m_name));

                    // Set vftable name
                    if (!hasUniqueName(vft))
                    {
                        char decorated[MAXSTR];
                        strncat(strcpy(decorated, FORMAT_RTTI_VFTABLE_PREFIX), combinedName, (MAXSTR - (1 + SIZESTR(FORMAT_RTTI_VFTABLE_PREFIX))));
                        if (!set_name(vft, decorated, (SN_NON_AUTO | SN_NOWARN)))
                            serializeName(vft, decorated);
                    }

                    // COL name
                    if (!hasUniqueName((ea_t) col))
                    {
                        char decorated[MAXSTR];
                        strncat(strcpy(decorated, FORMAT_RTTI_COL_PREFIX), combinedName, (MAXSTR - (1 + SIZESTR(FORMAT_RTTI_COL_PREFIX))));
                        if (!set_name((ea_t) col, decorated, (SN_NON_AUTO | SN_NOWARN)))
                            serializeName((ea_t)col, decorated);
                    }

                    // Build hierarchy string starting with parent
                    char plainName[MAXSTR];
                    getPlainTypeName(bi->m_name, plainName);
                    cmt.sprnt("%s%s: ", ((bi->m_name[3] == 'V') ? "" : "struct "), plainName);
                    placed++;

                    // Concatenate forward child hierarchy
                    if (++index < (int) numBaseClasses)
                    {
                        for (; index < (int) numBaseClasses; index++)
                        {
                            getPlainTypeName(list[index].m_name, plainName);
                            cmt.cat_sprnt("%s%s, ", ((list[index].m_name[3] == 'V') ? "" : "struct "), plainName);
                            placed++;
                        }
                        if (placed > 1)
                            cmt.remove((cmt.length() - 2), 2);
                    }

                    /*
                    Experiment, maybe better this way to show before and after to show it's location in the hierarchy
                    // Concatenate reverse child hierarchy
                    if (--index >= 0)
                    {
                        for (; index >= 0; index--)
                        {
                            getPlainTypeName(list[index].m_name, plainName);
                            cmt.cat_sprnt("%s%s, ", ((list[index].m_name[3] == 'V') ? "" : "struct "), plainName);
                            placed++;
                        }
                        if (placed > 1)
                            cmt.remove((cmt.length() - 2), 2);
                    }
                    */
                }
                if (placed > 1)
                    cmt += ';';
                sucess = TRUE;
            }
            else
                msg(EAFORMAT" ** Couldn't find a BCD for MI/VI hierarchy!\n", vft);
        }

        if (sucess)
        {
            // Store entry
            addTableEntry(((chdAttributes & 0xF) | ((isTopLevel == TRUE) ? RTTI::IS_TOP_LEVEL : 0)), vft, vi.methodCount, "%s@%s", demangledColName, cmt.c_str());

            //cmt.cat_sprnt("  %s O: %d, A: %d  (#classinformer)", attributeLabel(chdAttributes, numBaseClasses), offset, chdAttributes);
            cmt.cat_sprnt("  %s (#classinformer)", attributeLabel(chdAttributes));

            // Add a separating comment above RTTI COL
            ea_t cmtPtr = (vft - sizeof(ea_t));
            if (optionOverwriteComments)
            {
                killAnteriorComments(cmtPtr);
                describe(cmtPtr, true, "\n; %s %s", ((colName[3] == 'V') ? "class" : "struct"), cmt.c_str());
            }
            else
            if (!hasAnteriorComment(cmtPtr))
                describe(cmtPtr, true, "\n; %s %s", ((colName[3] == 'V') ? "class" : "struct"), cmt.c_str()); // add_long_cmt

            //vftable::processMembers(plainName, vft, end);
        }
    }
    else
    {
        msg(EAFORMAT" ** Vftable attached to this COL, error?\n", vft);

        // Set COL name
        if (!hasUniqueName(col))
        {
            #ifndef __EA64__
            ea_t typeInfo = getEa(col + offsetof(_RTTICompleteObjectLocator, typeDescriptor));
            #endif
            char colName[MAXSTR]; colName[0] = colName[SIZESTR(colName)] = 0;
            type_info::getName(typeInfo, colName, SIZESTR(colName));

            char decorated[MAXSTR]; decorated[SIZESTR(decorated)] = 0;
            _snprintf(decorated, SIZESTR(decorated), FORMAT_RTTI_COL, SKIP_TD_TAG(colName));
            if (!set_name(col, decorated, (SN_NON_AUTO | SN_NOWARN)))
                serializeName(col, decorated);
        }
    }
}


// ****************************************************************************
// File: RTTI.h
// Desc: Run-Time Type Information (RTTI) support
//
// ****************************************************************************
#pragma once

namespace RTTI
{
	#pragma pack(push, 1)

	// std::type_info class representation
    struct type_info
	{
		ea_t vfptr;	       // type_info class vftable
        ea_t _M_data;      // NULL until loaded at runtime
		char _M_d_name[1]; // Mangled name (prefix: .?AV=classes, .?AU=structs)

        static BOOL isValid(ea_t typeInfo);
        static BOOL isTypeName(ea_t name);
        static int  getName(ea_t typeInfo, __out LPSTR bufffer, int bufferSize);
        static void tryStruct(ea_t typeInfo);
    };
    const UINT MIN_TYPE_INFO_SIZE = (offsetof(type_info, _M_d_name) + sizeof(".?AVx"));
    typedef type_info _TypeDescriptor;
    typedef type_info _RTTITypeDescriptor;

    // Base class "Pointer to Member Data"
	struct PMD
	{
		int mdisp;	// 00 Member displacement
		int pdisp;  // 04 Vftable displacement
		int vdisp;  // 08 Displacement inside vftable
	};

    // Describes all base classes together with information to derived class access dynamically
    // attributes flags
    const UINT BCD_NOTVISIBLE          = 0x01;
    const UINT BCD_AMBIGUOUS           = 0x02;
    const UINT BCD_PRIVORPROTINCOMPOBJ = 0x04;
    const UINT BCD_PRIVORPROTBASE      = 0x08;
    const UINT BCD_VBOFCONTOBJ         = 0x10;
    const UINT BCD_NONPOLYMORPHIC      = 0x20;
    const UINT BCD_HASPCHD             = 0x40;

    struct _RTTIBaseClassDescriptor
	{
        #ifndef __EA64__
		ea_t typeDescriptor;        // 00 Type descriptor of the class
        #else
        UINT typeDescriptor;        // 00 Type descriptor of the class  *X64 int32 offset
        #endif
		UINT numContainedBases;		// 04 Number of nested classes following in the Base Class Array
		PMD  pmd;					// 08 Pointer-to-member displacement info
		UINT attributes;			// 14 Flags
        // 18 When attributes & BCD_HASPCHD
        //_RTTIClassHierarchyDescriptor *classDescriptor; *X64 int32 offset

        static BOOL isValid(ea_t bcd, ea_t colBase64 = NULL);
        static void tryStruct(ea_t bcd, __out_bcount(MAXSTR) LPSTR baseClassName, ea_t colBase64 = NULL);
	};

    // "Class Hierarchy Descriptor" describes the inheritance hierarchy of a class; shared by all COLs for the class
    // attributes flags
    const UINT CHD_MULTINH   = 0x01;    // Multiple inheritance
    const UINT CHD_VIRTINH   = 0x02;    // Virtual inheritance
    const UINT CHD_AMBIGUOUS = 0x04;    // Ambiguous inheritance

    /*
    struct _RTTIBaseClassArray
    {
        _RTTIBaseClassDescriptor *arrayOfBaseClassDescriptors[];
    };
    */

    struct _RTTIClassHierarchyDescriptor
	{
		UINT signature;			// 00 Zero until loaded
		UINT attributes;		// 04 Flags
		UINT numBaseClasses;	// 08 Number of classes in the following 'baseClassArray'
        #ifndef __EA64__
        ea_t baseClassArray;    // 0C _RTTIBaseClassArray*
        #else
        UINT baseClassArray;    // 0C *X64 int32 offset to _RTTIBaseClassArray*
        #endif

        static BOOL isValid(ea_t chd, ea_t colBase64 = NULL);
        static void tryStruct(ea_t chd, ea_t colBase64 = NULL);
	};

    // "Complete Object Locator" location of the complete object from a specific vftable pointer
    struct _RTTICompleteObjectLocator
	{
		UINT signature;				// 00 32bit zero, 64bit one, until loaded
		UINT offset;				// 04 Offset of this vftable in the complete class
		UINT cdOffset;				// 08 Constructor displacement offset
        #ifndef __EA64__
        ea_t typeDescriptor;	    // 0C (type_info *) of the complete class
        ea_t classDescriptor;       // 10 (_RTTIClassHierarchyDescriptor *) Describes inheritance hierarchy
        #else
        UINT typeDescriptor;	    // 0C (type_info *) of the complete class  *X64 int32 offset
        UINT classDescriptor;       // 10 (_RTTIClassHierarchyDescriptor *) Describes inheritance hierarchy  *X64 int32 offset
        UINT objectBase;            // 14 Object base offset (base = ptr col - objectBase)
        #endif

        static BOOL isValid(ea_t col);
        #ifndef __EA64__
        static BOOL isValid2(ea_t col);
        #endif
        static BOOL tryStruct(ea_t col);
	};
	#pragma pack(pop)

    const WORD IS_TOP_LEVEL = 0x8000;

    void freeWorkingData();
	void addDefinitionsToIda();
    BOOL processVftable(ea_t eaTable, ea_t col);
}


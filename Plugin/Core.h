
// ****************************************************************************
// File: Core.h
// Desc:
//
// ****************************************************************************

extern void fixEa(ea_t ea);
extern void fixDword(ea_t eaAddress);
extern void fixFunction(ea_t eaFunc);
extern void setUnknown(ea_t ea, int size);
extern BOOL getVerifyEa(ea_t ea, ea_t &rValue);
extern BOOL hasAnteriorComment(ea_t ea);
extern void killAnteriorComments(ea_t ea);
extern int  addStrucMember(struc_t *sptr, char *name, ea_t offset, flags_t flag, opinfo_t *type, asize_t nbytes);
extern void addTableEntry(UINT flags, ea_t vft, int methodCount, LPCSTR format, ...);
extern BOOL getPlainTypeName(__in LPCSTR mangled, __out_bcount(MAXSTR) LPSTR outStr);

extern BOOL optionOverwriteComments, optionPlaceStructs;

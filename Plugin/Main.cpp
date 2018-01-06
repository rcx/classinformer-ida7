
// ****************************************************************************
// File: Main.cpp
// Desc: Plug-in main
//
// ****************************************************************************
#include "stdafx.h"

// === Function Prototypes ===
int idaapi IDAP_init();
void idaapi IDAP_term();
bool idaapi IDAP_run(size_t arg);
extern void CORE_Init();
extern void CORE_Process(int iArg);
extern void CORE_Exit();

// === Data ===
static char IDAP_comment[] = "Class Informer: Locates and fixes C++ Run Time Type class and structure information.";
static char IDAP_help[]	   = "";
static char IDAP_name[]    = "Class Informer";

// Plug-in description block
extern "C" ALIGN(16) plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,	// IDA version plug-in is written for
    PLUGIN_PROC,            // Plug-in flags
	IDAP_init,	            // Initialization function
	IDAP_term,	            // Clean-up function
	IDAP_run,	            // Main plug-in body
	IDAP_comment,	        // Comment
	IDAP_help,	            // Help
	IDAP_name,	            // Plug-in name shown in Edit->Plugins menu
	NULL	                // Hot key to run the plug-in
};

int idaapi IDAP_init()
{
	if(strcmp(inf.procname, "metapc") == 0) // (ph.id == PLFM_386)
	{
		CORE_Init();
		return(PLUGIN_KEEP);
	}
	return(PLUGIN_SKIP);
}

void idaapi IDAP_term()
{
    CORE_Exit();
}

bool idaapi IDAP_run(size_t arg)
{
	CORE_Process(arg);
	return true; // ???? there's no documentation on what the return value should be
}

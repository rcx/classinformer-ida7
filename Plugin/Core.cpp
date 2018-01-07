
// ****************************************************************************
// File: Core.cpp
// Desc: Class Informer
//
// ****************************************************************************
#include "stdafx.h"
#include "Core.h"
#include "Vftable.h"
#include "RTTI.h"
#include "MainDialog.h"
#include <map>
//
#include <WaitBoxEx.h>
#include <IdaOgg.h>

typedef std::map<ea_t, std::string> STRMAP;

// Netnode constants
const static char NETNODE_NAME[] = {"$ClassInformer_node"};
const char NN_DATA_TAG  = 'A';
const char NN_TABLE_TAG = 'S';

// Our netnode value indexes
enum NETINDX
{
    NIDX_VERSION,   // ClassInformer version
    NIDX_COUNT      // Table entry count
};

// VFTable entry container (fits in a netnode MAXSPECSIZE size)
#pragma pack(push, 1)
struct TBLENTRY
{
    ea_t vft;
    WORD methods;
    WORD flags;
    WORD strSize;
    char str[MAXSPECSIZE - (sizeof(ea_t) + (sizeof(WORD) * 3))]; // IDA MAXSTR = 1024
};
#pragma pack(pop)

// Line background color for non parent/top level hierarchy lines
// TOOD: Assumes text background is white. A way to make these user theme/style color aware?
#define GRAY(v) RGB(v,v,v)
static const bgcolor_t NOT_PARENT_COLOR = GRAY(235);

// === Function Prototypes ===
static BOOL processStaticTables();
static void showEndStats();
static BOOL getRttiData(SegSelect::segments *segList);

// === Data ===
static TIMESTAMP s_startTime = 0;
static HMODULE myModuleHandle = NULL;
static UINT staticCCtorCnt = 0, staticCppCtorCnt = 0, staticCDtorCnt = 0;
static UINT startingFuncCount = 0, staticCtorDtorCnt = 0;
static BOOL initResourcesOnce = FALSE;
static int  chooserIcon = 0;
static netnode *netNode = NULL;
static eaList colList;

// Options
BOOL optionPlaceStructs      = TRUE;
BOOL optionProcessStatic     = TRUE;
BOOL optionOverwriteComments = FALSE;
BOOL optionAudioOnDone       = TRUE;

// List box defs
static const char LBTITLE[] = {"[Class Informer]"};
static const UINT LBCOLUMNCOUNT = 5;
static const int listBColumnWidth[LBCOLUMNCOUNT] = { (8 | CHCOL_HEX), (4 | CHCOL_DEC), 3, 19, 500 };
static const LPCSTR columnHeader[LBCOLUMNCOUNT] =
{
    "Vftable",
    "Methods",
    "Flags",
    "Type",
    "Hierarchy"
};

static ssize_t idaapi uiCallback(PVOID obj, int eventID, va_list va);
static void freeWorkingData()
{
    try
    {    
        RTTI::freeWorkingData();
        colList.clear();

        if (netNode)
        {
            delete netNode;
            netNode = NULL;
        }		
    }
    CATCH()
}

// Initialize
void CORE_Init()
{
    GetModuleHandleEx((GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS), (LPCTSTR)&CORE_Init, &myModuleHandle);
}

// Uninitialize
// Normally doesn't happen as we need to stay resident for the modal windows
void CORE_Exit()
{
    try
    {		
        OggPlay::endPlay();
        freeWorkingData();

		if (initResourcesOnce)
		{
			unhook_from_notification_point(HT_UI, uiCallback, myModuleHandle);

			if (chooserIcon)
			{
				free_custom_icon(chooserIcon);
				chooserIcon = 0;
			}

			Q_CLEANUP_RESOURCE(ClassInformerRes);
			initResourcesOnce = FALSE;
		}
    }
    CATCH()
}


// Init new netnode storage
static void newNetnodeStore()
{
    // Kill any existing store data first
    netNode->altdel_all(NN_DATA_TAG);
    netNode->supdel_all(NN_TABLE_TAG);

    // Init defaults
    netNode->altset_idx8(NIDX_VERSION, MY_VERSION, NN_DATA_TAG);
    netNode->altset_idx8(NIDX_COUNT,   0,          NN_DATA_TAG);
}

static WORD getStoreVersion(){ return((WORD)netNode->altval_idx8(NIDX_VERSION, NN_DATA_TAG)); }
static UINT getTableCount(){ return(netNode->altval_idx8(NIDX_COUNT, NN_DATA_TAG)); }
static BOOL setTableCount(UINT count){ return(netNode->altset_idx8(NIDX_COUNT, count, NN_DATA_TAG)); }
static BOOL getTableEntry(TBLENTRY &entry, UINT index){ return(netNode->supval(index, &entry, sizeof(TBLENTRY), NN_TABLE_TAG) > 0); }
static BOOL setTableEntry(TBLENTRY &entry, UINT index){ return(netNode->supset(index, &entry, (offsetof(TBLENTRY, str) + entry.strSize), NN_TABLE_TAG)); }

static UINT CALLBACK lw_onGetLineCount(){ return(getTableCount()); }
static void CALLBACK lw_onMakeLine(UINT n, qstrvec_t* cols)
{
    #ifdef __EA64__
    static char addressFormat[16];
    #endif

    // Populate requested row
	char buf[MAXSTR];

    TBLENTRY e;
    getTableEntry(e, n);
    // vft address
    #ifdef __EA64__
    sprintf(buf, addressFormat, e.vft);
    #else
    sprintf(buf, EAFORMAT, e.vft);
	(*cols)[0] = buf;
    #endif
    // Method count
    if (e.methods > 0)
        sprintf(buf, "%u", e.methods); // "%04u"
    else
        strcpy(buf, "???");
	(*cols)[1] = buf;
    // Flags
    char flags[4];
    int pos = 0;
    if (e.flags & RTTI::CHD_MULTINH)   flags[pos++] = 'M';
    if (e.flags & RTTI::CHD_VIRTINH)   flags[pos++] = 'V';
    if (e.flags & RTTI::CHD_AMBIGUOUS) flags[pos++] = 'A';
    flags[pos++] = 0;
    memcpy(buf, flags, pos);
	(*cols)[2] = buf;
    // Type
    LPCSTR tag = strchr(e.str, '@');
    if (tag)
    {
        pos = (tag - e.str);
        memcpy(buf, e.str, pos);
        buf[pos] = 0;
        ++tag;
    }
    else
    {
        // Can happen when string is MAXSTR and greater
        //_ASSERT(FALSE);
        strcpy(buf, "??** MAXSTR overflow!");
        tag = e.str;
        pos = (strlen(e.str) + 1);
    }
	(*cols)[3] = buf;
    // Composition/hierarchy
    strncpy(buf, tag, (MAXSTR - 1));
	(*cols)[4] = buf;
}

static int CALLBACK lw_onGetIcon(UINT n)
{
    //return(n);
    if(n == 0)
        return(0);
    else
    {
        /*
        TBLENTRY e;
        getTableEntry(e, (n));
        return((e.flags & RTTI::IS_TOP_LEVEL) ? 77 : 191);
        */
        return(191);
    }
}

static void CALLBACK lw_onSelect(UINT n)
{
    TBLENTRY e;
    getTableEntry(e, n);
    jumpto(e.vft);
}
static void CALLBACK lw_onClose() { freeWorkingData(); }

// Add an entry to the vftable list
void addTableEntry(UINT flags, ea_t vft, int methodCount, LPCTSTR format, ...)
{
    TBLENTRY e;
    e.vft     = vft;
    e.methods = methodCount;
    e.flags   = flags;
    e.str[SIZESTR(e.str)] = 0;

    va_list vl;
    va_start(vl, format);
    _vsntprintf(e.str, SIZESTR(e.str), format, vl);
    va_end(vl);
    e.strSize = (WORD) (strlen(e.str) + 1);

    UINT count = getTableCount();
    setTableEntry(e, count);
    setTableCount(++count);
}


static QWidget *findChildByClass(QWidgetList &wl, LPCSTR className)
{
    foreach(QWidget *w, wl)
        if (strcmp(w->metaObject()->className(), className) == 0)
            return(w);
    return(NULL);
}


// Find widget by title text
// If IDs are constant can use "static QWidget *QWidget::find(WId);"?
void customizeChooseWindow()
{
    try
    {
		QApplication::processEvents();

        // Get parent chooser dock widget
        QWidgetList pl = QApplication::activeWindow()->findChildren<QWidget*>("[Class Informer]");
        if (QWidget *dw = findChildByClass(pl, "IDADockWidget"))
        {
            QFile file(STYLE_PATH "view-style.qss");
            if (file.open(QFile::ReadOnly | QFile::Text))
                dw->setStyleSheet(QTextStream(&file).readAll());
        }
        else
            msg("** customizeChooseWindow(): \"IDADockWidget\" not found!\n");

        // Get chooser widget
        if (QTableView *tv = (QTableView *) findChildByClass(pl, "TChooserView"))
        {
            // Set sort by type name
            tv->sortByColumn(3, Qt::DescendingOrder);

            // Resize to contents
            tv->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
            tv->resizeColumnsToContents();
            tv->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);

            UINT count = getTableCount();
            for (UINT row = 0; row < count; row++)
                tv->setRowHeight(row, 24);
        }
        else
            msg("** customizeChooseWindow(): \"TChooserView\" not found!\n");
    }
    CATCH()
}

// UI callback to handle chooser window coloring
static ssize_t idaapi uiCallback(PVOID obj, int eventID, va_list va)
{
    if (eventID == ui_get_chooser_item_attrs)
    {
        // ** Stack vars, keep in order
        void *chooserObj = va_arg(va, PVOID);  // 0
        UINT n = va_arg(va, UINT);             // 1
        chooser_item_attrs_t *itemAttrubutes = va_arg(va, chooser_item_attrs_t *); // 2

        // My chooser?
        if (obj == myModuleHandle)
        {
            if (itemAttrubutes)
            {
                TBLENTRY e;
                if (getTableEntry(e, n))
                {
                    // Indicate entry is not a top/parent level
                    if (!(e.flags & RTTI::IS_TOP_LEVEL))
                        itemAttrubutes->color = NOT_PARENT_COLOR;
                }
            }
        }
    }
    return(0);
}


//static HWND WINAPI getIdaHwnd(){ return((HWND)callui(ui_get_hwnd).vptr); }

struct result_window_t : public chooser_multi_t // chooser_multi_t has different api, so i won't be using it.
{
	result_window_t() : chooser_multi_t(CH_ATTRS, LBCOLUMNCOUNT, listBColumnWidth, columnHeader, LBTITLE)
	{
		icon = ((chooserIcon != 0) ? chooserIcon : 160);
	};

	virtual void idaapi closed()
	{
		lw_onClose();
	}

	virtual cbres_t idaapi enter(sizevec_t* sel)
	{
		lw_onSelect(sel->front());
		return NOTHING_CHANGED;
	}

	virtual void idaapi get_row(
		qstrvec_t *cols,
		int *icon_,
		chooser_item_attrs_t *attrs,
		size_t n) const
	{
		lw_onMakeLine(n, cols);
		*icon_ = lw_onGetIcon(n);
	}

	virtual size_t idaapi get_count() const
	{
		return lw_onGetLineCount();
	}

} results_window;

void CORE_Process(int arg)
{
    try
    {		
        char version[16];
        sprintf(version, "%u.%u", HIBYTE(MY_VERSION), LOBYTE(MY_VERSION));
        msg("\n>> Class Informer: v: %s, built: %s, By Sirmabus\n", version, __DATE__);
        refreshUI();

		if (!initResourcesOnce)
		{
			initResourcesOnce = TRUE;
			Q_INIT_RESOURCE(ClassInformerRes);			

			QFile file(STYLE_PATH "icon.png");
			if (file.open(QFile::ReadOnly))
			{
				QByteArray ba = file.readAll();
				chooserIcon = load_custom_icon(ba.constData(), ba.size(), "png");
			}

			// Hook to control line color
			hook_to_notification_point(HT_UI, uiCallback, myModuleHandle);
		}

        if(!auto_is_ok())
        {
            msg("** Class Informer: Must wait for IDA to finish processing before starting plug-in! **\n*** Aborted ***\n\n");
            return;
        }

        OggPlay::endPlay();
        freeWorkingData();
        optionAudioOnDone       = TRUE;
        optionProcessStatic     = TRUE;
        optionOverwriteComments = FALSE;
        optionPlaceStructs      = TRUE;
        startingFuncCount       = get_func_qty();
		colList.clear();
        staticCppCtorCnt = staticCCtorCnt = staticCtorDtorCnt = staticCDtorCnt = 0;

        // Create storage netnode
        if(!(netNode = new netnode(NETNODE_NAME, SIZESTR(NETNODE_NAME), TRUE)))
        {
            QASSERT(66, FALSE);
            return;
        }

		// Read existing storage if any
        UINT tableCount     = getTableCount();
        WORD storageVersion = getStoreVersion();
        BOOL storageExists  = (tableCount > 0);

        // Ask if we should use storage or process again
		if (storageExists)
		{							
			// Version 2.3 didn't change the format
			UINT major = HIBYTE(storageVersion), minor = LOBYTE(storageVersion);
			if ((major != 2) || (minor < 2))
			{
				msg("* Storage version mismatch, must rescan *\n");
				refreshUI();
			}
			else
				storageExists = (ask_yn(1, "TITLE Class Informer \nHIDECANCEL\nUse previously stored result?        ") == 1);
		}

        BOOL aborted = FALSE;
        if(!storageExists)
        {
            newNetnodeStore();

            // Only MS Visual C++ targets are supported
            comp_t cmp = get_comp(default_compiler());
            if (cmp != COMP_MS)
            {
                msg("** IDA reports target compiler: \"%s\"\n", get_compiler_name(cmp));
                refreshUI();
                int iResult = ask_buttons(NULL, NULL, NULL, 0, "TITLE Class Informer\nHIDECANCEL\nIDA reports this IDB's compiler as: \"%s\" \n\nThis plug-in only understands MS Visual C++ targets.\nRunning it on other targets (like Borland© compiled, etc.) will have unpredicted results.   \n\nDo you want to continue anyhow?", get_compiler_name(cmp));
                if (iResult != 1)
                {
                    msg("- Aborted -\n\n");
                    return;
                }
            }

            // Do UI
			SegSelect::segments *segList = NULL;
            if (doMainDialog(optionPlaceStructs, optionProcessStatic, optionOverwriteComments, optionAudioOnDone, &segList))
            {
                msg("- Canceled -\n\n");
                return;
            }			

            msg("Working..\n");
            refreshUI();
            WaitBox::show("Class Informer", "Please wait..", "url(" STYLE_PATH "progress-style.qss)", STYLE_PATH "icon.png");
            WaitBox::updateAndCancelCheck(-1);
            s_startTime = getTimeStamp();

            // Add structure definitions to IDA once per session
            static BOOL createStructsOnce = FALSE;
            if (optionPlaceStructs && !createStructsOnce)
            {
                createStructsOnce = TRUE;
                RTTI::addDefinitionsToIda();
            }

            if(optionProcessStatic)
            {
                // Process global and static ctor sections
                msg("\nProcessing C/C++ ctor & dtor tables.\n");
                refreshUI();
                if (!(aborted = processStaticTables()))
                    msg("Processing time: %s.\n", timeString(getTimeStamp() - s_startTime));
                refreshUI();
            }

            if (!aborted)
            {
                // Get RTTI data
                if (!(aborted = getRttiData(segList)))
                {
                    // Optionally play completion sound
                    if (optionAudioOnDone)
                    {
                        TIMESTAMP endTime = (getTimeStamp() - s_startTime);
                        if (endTime > (TIMESTAMP) 2.4)
                        {
                            OggPlay::endPlay();
                            QFile file(STYLE_PATH "completed.ogg");
                            if (file.open(QFile::ReadOnly))
                            {
                                QByteArray ba = file.readAll();
                                OggPlay::playFromMemory((const PVOID)ba.constData(), ba.size(), TRUE);
                            }
                        }
                    }

                    showEndStats();
                    WaitBox::hide();
                    msg("Done.\n\n");
                }
            }

            refresh_idaview_anyway();
            if (aborted)
            {
                msg("- Aborted -\n\n");
                return;
            }
        }

        // Show list result window
        if (!aborted && (getTableCount() > 0))
        {
			static result_window_t* results_window = new result_window_t;
			results_window->choose();

            customizeChooseWindow();
        }
    }
    CATCH()
}

// Print out end stats
static void showEndStats()
{
    try
    {
        msg(" \n\n");
        msg("=========== Stats ===========\n");
        msg("  RTTI vftables: %u\n", getTableCount());
        msg("Functions fixed: %u\n", (get_func_qty() - startingFuncCount));
        msg("Processing time: %s\n", timeString(getTimeStamp() - s_startTime));
    }
    CATCH()
}


// ================================================================================================

// Fix/create label and comment C/C++ initializer tables
static void setIntializerTable(ea_t start, ea_t end, BOOL isCpp)
{
    try
    {
        if (UINT count = ((end - start) / sizeof(ea_t)))
        {
            // Set table elements as pointers
            ea_t ea = start;
            while (ea <= end)
            {
                fixEa(ea);

                // Might fix missing/messed stubs
                if (ea_t func = get_32bit(ea))
                    fixFunction(func);

                ea += sizeof(ea_t);
            };

            // Start label
            if (!hasUniqueName(start))
            {
                char name[MAXSTR]; name[SIZESTR(name)] = 0;
                if (isCpp)
                    _snprintf(name, SIZESTR(name), "__xc_a_%d", staticCppCtorCnt);
                else
                    _snprintf(name, SIZESTR(name), "__xi_a_%d", staticCCtorCnt);
                set_name(start, name, (SN_NON_AUTO | SN_NOWARN));
            }

            // End label
            if (!hasUniqueName(end))
            {
                char name[MAXSTR]; name[SIZESTR(name)] = 0;
                if (isCpp)
                    _snprintf(name, SIZESTR(name), "__xc_z_%d", staticCppCtorCnt);
                else
                    _snprintf(name, SIZESTR(name), "__xi_z_%d", staticCCtorCnt);
                set_name(end, name, (SN_NON_AUTO | SN_NOWARN));
            }

            // Comment
            // Never overwrite, it might be the segment comment
            if (!hasAnteriorComment(start))
            {
                if (isCpp)
					add_extra_cmt(start, TRUE, "%d C++ static ctors (#classinformer)", count);
                else
					add_extra_cmt(start, TRUE, "%d C initializers (#classinformer)", count);
            }
            else
            // Place comment @ address instead
            if (!has_cmt(get_flags(start)))
            {
                char comment[MAXSTR]; comment[SIZESTR(comment)] = 0;
                if (isCpp)
                {
                    _snprintf(comment, SIZESTR(comment), "%d C++ static ctors (#classinformer)", count);
                    set_cmt(start, comment, TRUE);
                }
                else
                {
                    _snprintf(comment, SIZESTR(comment), "%d C initializers (#classinformer)", count);
                    set_cmt(start, comment, TRUE);
                }
            }

            if (isCpp)
                staticCppCtorCnt++;
            else
                staticCCtorCnt++;
        }
    }
    CATCH()
}

// Fix/create label and comment C/C++ terminator tables
static void setTerminatorTable(ea_t start, ea_t end)
{
    try
    {
        if (UINT count = ((end - start) / sizeof(ea_t)))
        {
            // Set table elements as pointers
            ea_t ea = start;
            while (ea <= end)
            {
                fixEa(ea);

                // Fix function
                if (ea_t func = getEa(ea))
                    fixFunction(func);

                ea += sizeof(ea_t);
            };

            // Start label
            if (!hasUniqueName(start))
            {
                char name[MAXSTR]; name[SIZESTR(name)] = 0;
                _snprintf(name, SIZESTR(name), "__xt_a_%d", staticCDtorCnt);
                set_name(start, name, (SN_NON_AUTO | SN_NOWARN));
            }

            // End label
            if (!hasUniqueName(end))
            {
                char name[MAXSTR]; name[SIZESTR(name)] = 0;
                _snprintf(name, SIZESTR(name), "__xt_z_%d", staticCDtorCnt);
                set_name(end, name, (SN_NON_AUTO | SN_NOWARN));
            }

            // Comment
            // Never overwrite, it might be the segment comment
            if (!hasAnteriorComment(start))
                add_extra_cmt(start, TRUE, "%d C terminators (#classinformer)", count);
            else
            // Place comment @ address instead
            if (!has_cmt(get_flags(start)))
            {
                char comment[MAXSTR]; comment[SIZESTR(comment)] = 0;
                _snprintf(comment, SIZESTR(comment), "%d C terminators (#classinformer)", count);
                set_cmt(start, comment, TRUE);
            }

            staticCDtorCnt++;
        }
    }
    CATCH()
}

// "" for when we are uncertain of ctor or dtor type table
static void setCtorDtorTable(ea_t start, ea_t end)
{
    try
    {
        if (UINT count = ((end - start) / sizeof(ea_t)))
        {
            // Set table elements as pointers
            ea_t ea = start;
            while (ea <= end)
            {
                fixEa(ea);

                // Fix function
                if (ea_t func = getEa(ea))
                    fixFunction(func);

                ea += sizeof(ea_t);
            };

            // Start label
            if (!hasUniqueName(start))
            {
                char name[MAXSTR]; name[SIZESTR(name)] = 0;
                _snprintf(name, SIZESTR(name), "__x?_a_%d", staticCtorDtorCnt);
                set_name(start, name, (SN_NON_AUTO | SN_NOWARN));
            }

            // End label
            if (!hasUniqueName(end))
            {
                char name[MAXSTR]; name[SIZESTR(name)] = 0;
                _snprintf(name, SIZESTR(name), "__x?_z_%d", staticCtorDtorCnt);
                set_name(end, name, (SN_NON_AUTO | SN_NOWARN));
            }

            // Comment
            // Never overwrite, it might be the segment comment
            if (!hasAnteriorComment(start))
                add_extra_cmt(start, TRUE, "%d C initializers/terminators (#classinformer)", count);
            else
            // Place comment @ address instead
            if (!has_cmt(get_flags(start)))
            {
                char comment[MAXSTR]; comment[SIZESTR(comment)] = 0;
                _snprintf(comment, SIZESTR(comment), "%d C initializers/terminators (#classinformer)", count);
                set_cmt(start, comment, TRUE);
            }

            staticCtorDtorCnt++;
        }
    }
    CATCH()
}


// Process redister based _initterm()
static void processRegisterInitterm(ea_t start, ea_t end, ea_t call)
{
    if ((end != BADADDR) && (start != BADADDR))
    {
        // Should be in the same segment
        if (getseg(start) == getseg(end))
        {
            if (start > end)
                swap_t(start, end);

            msg("    " EAFORMAT " to " EAFORMAT " CTOR table.\n", start, end);
            setIntializerTable(start, end, TRUE);
            set_cmt(call, "_initterm", TRUE);
        }
        else
            msg("  ** Bad address range of " EAFORMAT ", " EAFORMAT " for \"_initterm\" type ** <click address>.\n", start, end);
    }
}

static UINT doInittermTable(func_t *func, ea_t start, ea_t end, LPCTSTR name)
{
    UINT found = FALSE;

    if ((start != BADADDR) && (end != BADADDR))
    {
        // Should be in the same segment
        if (getseg(start) == getseg(end))
        {
            if (start > end)
                swap_t(start, end);

            // Try to determine if we are in dtor or ctor section
            if (func)
            {
                qstring qstr;
                if (get_long_name(&qstr, func->start_ea) > 0)
                {
                    char funcName[MAXSTR]; funcName[SIZESTR(funcName)] = 0;
                    strncpy(funcName, qstr.c_str(), (MAXSTR - 1));
                    _strlwr(funcName);

                    // Start/ctor?
                    if (strstr(funcName, "cinit") || strstr(funcName, "tmaincrtstartup") || strstr(funcName, "start"))
                    {
                        msg("    " EAFORMAT " to " EAFORMAT " CTOR table.\n", start, end);
                        setIntializerTable(start, end, TRUE);
                        found = TRUE;
                    }
                    else
                    // Exit/dtor function?
                    if (strstr(funcName, "exit"))
                    {
                        msg("    " EAFORMAT " to " EAFORMAT " DTOR table.\n", start, end);
                        setTerminatorTable(start, end);
                        found = TRUE;
                    }
                }
            }

            if (!found)
            {
                // Fall back to generic assumption
                msg("    " EAFORMAT " to " EAFORMAT " CTOR/DTOR table.\n", start, end);
                setCtorDtorTable(start, end);
                found = TRUE;
            }
        }
        else
            msg("    ** Miss matched segment table addresses " EAFORMAT ", " EAFORMAT " for \"%s\" type **\n", start, end, name);
    }
    else
        msg("    ** Bad input address range of " EAFORMAT ", " EAFORMAT " for \"%s\" type **\n", start, end, name);

    return(found);
}

// Process _initterm function
// Returns TRUE if at least one found
static BOOL processInitterm(ea_t address, LPCTSTR name)
{
    msg(EAFORMAT" processInitterm: \"%s\" \n", address, name);
    UINT count = 0;

    // Walk xrefs
    ea_t xref = get_first_fcref_to(address);
    while (xref && (xref != BADADDR))
    {
        msg("  " EAFORMAT " \"%s\" xref.\n", xref, name);

        // Should be code
        if (is_code(get_flags(xref)))
        {
            do
            {
                // The most common are two instruction arguments
                // Back up two instructions
                ea_t instruction1 = prev_head(xref, 0);
                if (instruction1 == BADADDR)
                    break;
                ea_t instruction2 = prev_head(instruction1, 0);
                if (instruction2 == BADADDR)
                    break;

                // Bail instructions are past the function start now
                func_t *func = get_func(xref);
                if (func && (instruction2 < func->start_ea))
                {
                    //msg("   " EAFORMAT " arg2 outside of contained function **\n", func->start_ea);
                    break;
                }

                struct ARG2PAT
                {
                    LPCSTR pattern;
                    UINT start, end, padding;
                } static const ALIGN(16) arg2pat[] =
                {
                    #ifndef __EA64__
                    { "68 ?? ?? ?? ?? 68 ?? ?? ?? ??", 6, 1 },          // push offset s, push offset e
                    { "B8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ??", 8, 1 },    // mov [esp+4+var_4], offset s, mov eax, offset e   Maestia
                    { "68 ?? ?? ?? ?? B8 ?? ?? ?? ??", 6, 1 },          // mov eax, offset s, push offset e
                    #else
                    { "48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ??", 3, 3 },  // lea rdx,s, lea rcx,e
                    #endif
                };
                BOOL matched = FALSE;
                for (UINT i = 0; (i < qnumber(arg2pat)) && !matched; i++)
                {
                    ea_t match = find_binary(instruction2, xref, arg2pat[i].pattern, 16, (SEARCH_DOWN | SEARCH_NOBRK | SEARCH_NOSHOW));
                    if (match != BADADDR)
                    {
                        #ifndef __EA64__
                        ea_t start = getEa(match + arg2pat[i].start);
                        ea_t end   = getEa(match + arg2pat[i].end);
                        #else
                        UINT startOffset = get_32bit(instruction1 + arg2pat[i].start);
                        UINT endOffset   = get_32bit(instruction2 + arg2pat[i].end);
                        ea_t start = (instruction1 + 7 + *((PINT) &startOffset)); // TODO: 7 is hard coded instruction length, put this in arg2pat table?
                        ea_t end   = (instruction2 + 7 + *((PINT) &endOffset));
                        #endif
                        msg("  " EAFORMAT " Two instruction pattern match #%d\n", match, i);
                        count += doInittermTable(func, start, end, name);
                        matched = TRUE;
                        break;
                    }
                }

                // 3 instruction
                /*
                searchStart = prev_head(searchStart, BADADDR);
                if (searchStart == BADADDR)
                    break;
                if (func && (searchStart < func->start_ea))
                    break;

                    if (func && (searchStart < func->start_ea))
                    {
                        msg("  " EAFORMAT " arg3 outside of contained function **\n", func->start_ea);
                        break;
                    }

                .text:10008F78                 push    offset unk_1000B1B8
                .text:10008F7D                 push    offset unk_1000B1B0
                .text:10008F82                 mov     dword_1000F83C, 1
                "68 ?? ?? ?? ?? 68 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ??"
                */

                if (!matched)
                    msg("  ** arguments not located!\n");

            } while (FALSE);
        }
        else
            msg("  " EAFORMAT " ** \"%s\" xref is not code! **\n", xref, name);

        xref = get_next_fcref_to(address, xref);
    };

    msg(" \n");
    return(count > 0);
}


// Process global/static ctor & dtor tables.
// Returns TRUE if user aborted
static BOOL processStaticTables()
{
    staticCppCtorCnt = staticCCtorCnt = staticCtorDtorCnt = staticCDtorCnt = 0;

    // x64 __tmainCRTStartup, _CRT_INIT

    try
    {
        // Locate _initterm() and _initterm_e() functions
        STRMAP inittermMap;
        func_t  *cinitFunc = NULL;
        UINT funcCount = get_func_qty();
        for (UINT i = 0; i < funcCount; i++)
        {
            if (func_t *func = getn_func(i))
            {
                qstring qstr;
                if (get_long_name(&qstr, func->start_ea) > 0)
                {
                    char name[MAXSTR]; name[SIZESTR(name)] = 0;
                    strncpy(name, qstr.c_str(), (MAXSTR - 1));

                    int len = strlen(name);
                    if (len >= SIZESTR("_cinit"))
                    {
                        if (strcmp((name + (len - SIZESTR("_cinit"))), "_cinit") == 0)
                        {
                            // Skip stub functions
                            if (func->size() > 16)
                            {
                                msg(EAFORMAT" C: \"%s\", %d bytes.\n", func->start_ea, name, func->size());
                                _ASSERT(cinitFunc == NULL);
                                cinitFunc = func;
                            }
                        }
                        else
                        if ((len >= SIZESTR("_initterm")) && (strcmp((name + (len - SIZESTR("_initterm"))), "_initterm") == 0))
                        {
                            msg(EAFORMAT" I: \"%s\", %d bytes.\n", func->start_ea, name, func->size());
                            inittermMap[func->start_ea] = name;
                        }
                        else
                        if ((len >= SIZESTR("_initterm_e")) && (strcmp((name + (len - SIZESTR("_initterm_e"))), "_initterm_e") == 0))
                        {
                            msg(EAFORMAT" E: \"%s\", %d bytes.\n", func->start_ea, name, func->size());
                            inittermMap[func->start_ea] = name;
                        }
                    }
                }
            }
        }
        refreshUI();
        if (WaitBox::updateAndCancelCheck())
            return(TRUE);

        // Look for import versions
        {
            static LPCSTR imports[] =
            {
                "__imp__initterm", "__imp__initterm_e"
            };
            for (UINT i = 0; i < qnumber(imports); i++)
            {
                ea_t adress = get_name_ea(BADADDR, imports[i]);
                if (adress != BADADDR)
                {
                    if (inittermMap.find(adress) == inittermMap.end())
                    {
                        msg(EAFORMAT" import: \"%s\".\n", adress, imports[i]);
                        inittermMap[adress] = imports[i];
                    }
                }
            }
        }

        // Process register based _initterm() calls inside _cint()
        if (cinitFunc)
        {
            struct CREPAT
            {
                LPCSTR pattern;
                UINT start, end, call;
            } static const ALIGN(16) pat[] =
            {
                { "B8 ?? ?? ?? ?? BE ?? ?? ?? ?? 59 8B F8 3B C6 73 0F 8B 07 85 C0 74 02 FF D0 83 C7 04 3B FE 72 F1", 1, 6, 0x17},
                { "BE ?? ?? ?? ?? 8B C6 BF ?? ?? ?? ?? 3B C7 59 73 0F 8B 06 85 C0 74 02 FF D0 83 C6 04 3B F7 72 F1", 1, 8, 0x17},
            };

            for (UINT i = 0; i < qnumber(pat); i++)
            {
                ea_t match = find_binary(cinitFunc->start_ea, cinitFunc->end_ea, pat[i].pattern, 16, (SEARCH_DOWN | SEARCH_NOBRK | SEARCH_NOSHOW));
                while (match != BADADDR)
                {
                    msg("  " EAFORMAT " Register _initterm(), pattern #%d.\n", match, i);
                    ea_t start = getEa(match + pat[i].start);
                    ea_t end   = getEa(match + pat[i].end);
                    processRegisterInitterm(start, end, (match + pat[i].call));
                    match = find_binary(match + 30, cinitFunc->end_ea, pat[i].pattern, 16, (SEARCH_NEXT | SEARCH_DOWN | SEARCH_NOBRK | SEARCH_NOSHOW));
                };
            }
        }
        msg(" \n");
        refreshUI();
        if (WaitBox::updateAndCancelCheck())
            return(TRUE);

        // Process _initterm references
        for (STRMAP::iterator it = inittermMap.begin(); it != inittermMap.end(); ++it)
        {
            if (processInitterm(it->first, it->second.c_str()))
                if (WaitBox::updateAndCancelCheck())
                    return(TRUE);
        }
        refreshUI();
    }
    CATCH()

    return(FALSE);
}

// ================================================================================================


// Return TRUE if address as a anterior comment
inline BOOL hasAnteriorComment(ea_t ea)
{
    return(get_first_free_extra_cmtidx(ea, E_PREV) != E_PREV);
}

// Delete any anterior comment(s) at address if there is some
inline void killAnteriorComments(ea_t ea)
{
    delete_extra_cmts(ea, E_PREV);
}

// Force a memory location to be DWORD size
void fixDword(ea_t ea)
{
    if (!is_dword(get_flags(ea)))
    {
        setUnknown(ea, sizeof(DWORD));
        create_dword(ea, sizeof(DWORD));
    }
}

// Force memory location to be ea_t size
void fixEa(ea_t ea)
{
    #ifndef __EA64__
    if (!is_dword(get_flags(ea)))
    #else
    if (!is_qword(get_flags(ea)))
    #endif
    {
        setUnknown(ea, sizeof(ea_t));
        #ifndef __EA64__
        create_dword(ea, sizeof(ea_t));
        #else
		create_qword(ea, sizeof(ea_t));
        #endif
    }
}

// Make address a function
void fixFunction(ea_t ea)
{
    flags_t flags = get_flags(ea);
    if (!is_code(flags))
    {
        create_insn(ea);
        add_func(ea, BADADDR);
    }
    else
    if (!is_func(flags))
        add_func(ea, BADADDR);
}

// Get IDA EA bit value with verification
BOOL getVerifyEa(ea_t ea, ea_t &rValue)
{
    // Location valid?
    if (is_loaded(ea))
    {
        // Get ea_t value
        rValue = getEa(ea);
        return(TRUE);
    }

    return(FALSE);
}


// Undecorate to minimal class name
// typeid(T).name()
// http://en.wikipedia.org/wiki/Name_mangling
// http://en.wikipedia.org/wiki/Visual_C%2B%2B_name_mangling
// http://www.agner.org/optimize/calling_conventions.pdf

BOOL getPlainTypeName(__in LPCSTR mangled, __out_bcount(MAXSTR) LPSTR outStr)
{
    outStr[0] = outStr[MAXSTR - 1] = 0;

    // Use CRT function for type names
    if (mangled[0] == '.')
    {
        __unDName(outStr, mangled + 1, MAXSTR, (_Alloc)malloc, free, (UNDNAME_32_BIT_DECODE | UNDNAME_TYPE_ONLY | UNDNAME_NO_ECSU));
        if ((outStr[0] == 0) || (strcmp((mangled + 1), outStr) == 0))
        {
            msg("** getPlainClassName:__unDName() failed to unmangle! input: \"%s\"\n", mangled);
            return(FALSE);
        }
    }
    else
    // IDA demangler for everything else
    {
        qstring qstr;
        int result = demangle_name(&qstr, mangled, (MT_MSCOMP | MNG_NODEFINIT));
        if (result < 0)
        {
            //msg("** getPlainClassName:demangle_name2() failed to unmangle! result: %d, input: \"%s\"\n", result, mangled);
            return(FALSE);
        }

        // No inhibit flags will drop this
        strncpy(outStr, qstr.c_str(), (MAXSTR - 1));
        if (LPSTR ending = strstr(outStr, "::`vftable'"))
            *ending = 0;
    }

    return(TRUE);
}

// Wrapper for 'add_struc_member()' with error messages
// See to make more sense of types: http://idapython.googlecode.com/svn-history/r116/trunk/python/idc.py
int addStrucMember(struc_t *sptr, char *name, ea_t offset, flags_t flag, opinfo_t *type, asize_t nbytes)
{
    int r = add_struc_member(sptr, name, offset, flag, type, nbytes);
    switch(r)
    {
        case STRUC_ERROR_MEMBER_NAME:
        msg("AddStrucMember(): error: already has member with this name (bad name)\n");
        break;

        case STRUC_ERROR_MEMBER_OFFSET:
        msg("AddStrucMember(): error: already has member at this offset\n");
        break;

        case STRUC_ERROR_MEMBER_SIZE:
        msg("AddStrucMember(): error: bad number of bytes or bad sizeof(type)\n");
        break;

        case STRUC_ERROR_MEMBER_TINFO:
        msg("AddStrucMember(): error: bad typeid parameter\n");
        break;

        case STRUC_ERROR_MEMBER_STRUCT:
        msg("AddStrucMember(): error: bad struct id (the 1st argument)\n");
        break;

        case STRUC_ERROR_MEMBER_UNIVAR:
        msg("AddStrucMember(): error: unions can't have variable sized members\n");
        break;

        case STRUC_ERROR_MEMBER_VARLAST:
        msg("AddStrucMember(): error: variable sized member should be the last member in the structure\n");
        break;

        case STRUC_ERROR_MEMBER_NESTED:
        msg("AddStrucMember(): error: recursive structure nesting is forbidden\n");
        break;
    };

    return(r);
}


void setUnknown(ea_t ea, int size)
{
    // TODO: Does the overrun problem still exist?
    //do_unknown_range(ea, (size_t)size, DOUNK_SIMPLE);
    while (size > 0)
    {
        int isize = get_item_size(ea);
        if (isize > size)
            break;
        else
        {
			del_items(ea, DELIT_SIMPLE);
            ea += (ea_t)isize, size -= isize;
        }
    };
}


// Scan segment for COLs
static BOOL scanSeg4Cols(segment_t *seg)
{
	qstring name;
	if (get_segm_name(&name, seg) <= 0)
		name = "???";
    msg(" N: \"%s\", A: " EAFORMAT " - " EAFORMAT ", S: %s.\n", name.c_str(), seg->start_ea, seg->end_ea, byteSizeString(seg->size()));
    refreshUI();

    UINT found = 0;
    if (seg->size() >= sizeof(RTTI::_RTTICompleteObjectLocator))
    {
        ea_t startEA = ((seg->start_ea + sizeof(UINT)) & ~((ea_t)(sizeof(UINT) - 1)));
        ea_t endEA   = (seg->end_ea - sizeof(RTTI::_RTTICompleteObjectLocator));

        for (ea_t ptr = startEA; ptr < endEA;)
        {
            #ifdef __EA64__
            // Check for possible COL here
            // Signature will be one
            // TODO: Is this always 1 or can it be zero like 32bit?
            if (get_32bit(ptr + offsetof(RTTI::_RTTICompleteObjectLocator, signature)) == 1)
            {
                if (RTTI::_RTTICompleteObjectLocator::isValid(ptr))
                {
                    // yes
                    colList.push_front(ptr);
                    RTTI::_RTTICompleteObjectLocator::doStruct(ptr);
                    ptr += sizeof(RTTI::_RTTICompleteObjectLocator);
                    continue;
                }
            }
            else
            {
                // TODO: Should we check stray BCDs?
                // Each value would have to be tested for a valid type_def and
                // the pattern is pretty ambiguous.
            }
            #else
            // TypeDescriptor address here?
            ea_t ea = getEa(ptr);
            if (ea >= 0x10000)
            {
                if (RTTI::type_info::isValid(ea))
                {
                    // yes, a COL here?
                    ea_t col = (ptr - offsetof(RTTI::_RTTICompleteObjectLocator, typeDescriptor));
                    if (RTTI::_RTTICompleteObjectLocator::isValid2(col))
                    {
                        // yes
                        colList.push_front(col);
                        RTTI::_RTTICompleteObjectLocator::doStruct(col);
                        ptr += sizeof(RTTI::_RTTICompleteObjectLocator);
                        continue;
                    }
                    /*
                    else
                    // No, is it a BCD then?
                    if (RTTI::_RTTIBaseClassDescriptor::isValid2(ptr))
                    {
                        // yes
                        char dontCare[MAXSTR];
                        RTTI::_RTTIBaseClassDescriptor::doStruct(ptr, dontCare);
                    }
                    */
                }
            }
            #endif

            if (WaitBox::isUpdateTime())
                if (WaitBox::updateAndCancelCheck())
                    return(TRUE);

            ptr += sizeof(UINT);
        }
    }

    if (found)
    {
        char numBuffer[32];
        msg(" Count: %s\n", prettyNumberString(found, numBuffer));
        refreshUI();
    }
    return(FALSE);
}
//
// Locate COL by descriptor list
static BOOL findCols(SegSelect::segments *segList)
{
    try
    {
        #ifdef _DEVMODE
        TIMESTAMP startTime = getTimeStamp();
        #endif

		// Use user selected segments
		if (segList && !segList->empty())
		{
			for (SegSelect::segments::iterator it = segList->begin(); it != segList->end(); ++it)
			{
				if (scanSeg4Cols(*it))
					return(FALSE);				
			}
		}
		else
		// Scan data segments named
		{
			int segCount = get_segm_qty();
			for (int i = 0; i < segCount; i++)
			{
				if (segment_t *seg = getnseg(i))
				{
					if (seg->type == SEG_DATA)
					{
						if (scanSeg4Cols(seg))
							return(FALSE);
					}
				}
			}
		}

        char numBuffer[32];
        msg("     Total COL: %s\n", prettyNumberString(colList.size(), numBuffer));
        #ifdef _DEVMODE
        msg("COL scan time: %.3f\n", (getTimeStamp() - startTime));
        #endif
        refreshUI();
    }
    CATCH()
    return(FALSE);
}


// Locate vftables
static BOOL scanSeg4Vftables(segment_t *seg, eaRefMap &colMap)
{
	qstring name;
    if (get_segm_name(&name, seg) <= 0)
		name = "???";
    msg(" N: \"%s\", A: " EAFORMAT "-" EAFORMAT ", S: %s.\n", name.c_str(), seg->start_ea, seg->end_ea, byteSizeString(seg->size()));
    refreshUI();
	
    UINT found = 0;
    if (seg->size() >= sizeof(ea_t))
    {
        ea_t startEA = ((seg->start_ea + sizeof(ea_t)) & ~((ea_t)(sizeof(ea_t) - 1)));
        ea_t endEA   = (seg->end_ea - sizeof(ea_t));
        eaRefMap::iterator colEnd = colMap.end();

        for (ea_t ptr = startEA; ptr < endEA; ptr += sizeof(UINT))  //sizeof(ea_t)
        {
            // COL here?
            ea_t ea = getEa(ptr);
            eaRefMap::iterator it = colMap.find(ea);
            if (it != colEnd)
            {
                // yes, look for vftable one ea_t below
                ea_t vfptr  = (ptr + sizeof(ea_t));
                ea_t method = getEa(vfptr);
                // Points to code?
                if (segment_t *s = getseg(method))
                {
                    // yes,
                    if (s->type == SEG_CODE)
                    {
                        RTTI::processVftable(vfptr, it->first);
                        it->second++, found++;
                    }
                }
            }

            if (WaitBox::isUpdateTime())
                if (WaitBox::updateAndCancelCheck())
                    return(TRUE);
        }
    }

    if (found)
    {
        char numBuffer[32];
        msg(" Count: %s\n", prettyNumberString(found, numBuffer));
        refreshUI();
    }
    return(FALSE);
}
//
static BOOL findVftables(SegSelect::segments *segList)
{
    try
    {
        #ifdef _DEVMODE
        TIMESTAMP startTime = getTimeStamp();
        #endif

        // COLs in hash map for speed, plus match counts
        eaRefMap colMap;
        for (eaList::const_iterator it = colList.begin(), end = colList.end(); it != end; ++it)
            colMap[*it] = 0;

		// Use user selected segments
		if (segList && !segList->empty())
		{
			for (SegSelect::segments::iterator it = segList->begin(); it != segList->end(); ++it)
			{
				if (scanSeg4Vftables(*it, colMap))
					return(FALSE);				
			}
		}
		else
		// Scan data segments named
		{
			int segCount = get_segm_qty();
			for (int i = 0; i < segCount; i++)
			{
				if (segment_t *seg = getnseg(i))
				{
					if (seg->type == SEG_DATA)
					{
						if (scanSeg4Vftables(seg, colMap))
							return(FALSE);
					}
				}
			}
		}

        // Rebuild 'colList' with any that were not located
        if (!colList.empty())
        {
            colList.clear();
            for (eaRefMap::const_iterator it = colMap.begin(), end = colMap.end(); it != end; ++it)
            {
                if (it->second == 0)
                    colList.push_front(it->first);
            }
        }

        #ifdef _DEVMODE
        msg("vftable scan time: %.3f\n", (getTimeStamp() - startTime));
        #endif
    }
    CATCH()
    return(FALSE);
}


// ================================================================================================

// Gather RTTI data
static BOOL getRttiData(SegSelect::segments *segList)
{
    // Free RTTI working data on return
    struct OnReturn  { ~OnReturn() { RTTI::freeWorkingData(); }; } onReturn;

    try
    {
        // ==== Locate __type_info_root_node
        BOOL aborted = FALSE;

        // ==== Find and process COLs
        msg("\nScanning for for RTTI Complete Object Locators.\n");
        refreshUI();
        if(findCols(segList))
            return(TRUE);
        // typeDescList = TDs left that don't have a COL reference
        // colList = Located COLs

        // ==== Find and process vftables
        msg("\nScanning for vftables.\n");
        refreshUI();
        if(findVftables(segList))
            return(TRUE);
        // colList = COLs left that don't have a vft reference

        // Could use the unlocated ref lists typeDescList & colList around for possible separate listing, etc.
        // They get cleaned up on return of this function anyhow.
    }
    CATCH()

    return(FALSE);
}

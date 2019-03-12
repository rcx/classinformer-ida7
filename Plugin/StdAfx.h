
#pragma once

#define WIN32_LEAN_AND_MEAN
#define WINVER		 0x0601 // _WIN32_WINNT_WIN7
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <tchar.h>
#include <math.h>
#include <crtdbg.h>
#include <intrin.h>

#pragma intrinsic(memset, memcpy, strcat, strcmp, strcpy, strlen, abs, fabs, labs, atan, atan2, tan, sqrt, sin, cos)

// IDA libs
#define USE_DANGEROUS_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
#define NO_OBSOLETE_FUNCS
// Nix the many warning about int type conversions
#pragma warning(push)
#pragma warning(disable:4244)
#pragma warning(disable:4267)
#include <ida.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <search.hpp>
#include <typeinf.hpp>
#include <struct.hpp>
#include <nalt.hpp>
#include <demangle.hpp>
#pragma warning(pop)

// Qt libs
#include <QtCore/QTextStream>
#include <QtCore/QFile>
#include <QtWidgets/QApplication>
#include <QtWidgets/QProgressDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTableView>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QScrollBar>
// IDA SDK Qt libs
#pragma comment(lib, "Qt5Core.lib")
#pragma comment(lib, "Qt5Gui.lib")
#pragma comment(lib, "Qt5Widgets.lib")

// QT_NO_UNICODE_LITERAL must be defined (best in preprocessor setting)
// So Qt doesn't a static string pool that will cause IDA to crash on unload
#ifndef QT_NO_UNICODE_LITERAL
# error QT_NO_UNICODE_LITERAL must be defined to avoid Qt string crashes
#endif

#include <Utility.h>
#include "undname.h"

#include <unordered_set>
#include <unordered_map>

typedef qlist<ea_t> eaList;
typedef std::unordered_set<ea_t> eaSet;
typedef std::unordered_map<ea_t, UINT> eaRefMap; // address & ref count

//#define STYLE_PATH "C:/Projects/IDA Pro Work/IDA_ClassInformer_PlugIn/Plugin/"
#define STYLE_PATH ":/classinf/"

#define MY_VERSION MAKEWORD(5, 2) // Low, high, convention: 0 to 99


// ****************************************************************************
// File: MainDialog.cpp
// Desc: Main Dialog
//
// ****************************************************************************
#include "stdafx.h"
#include "MainDialog.h"

#include <QtWidgets/QDialogButtonBox>


MainDialog::MainDialog(BOOL &optionPlaceStructs, BOOL &optionProcessStatic, BOOL &optionAudioOnDone, SegSelect::segments **segs) : QDialog(QApplication::activeWindow(), 0)
{
    Ui::MainCIDialog::setupUi(this);
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);
    buttonBox->addButton("CONTINUE", QDialogButtonBox::AcceptRole);
    buttonBox->addButton("CANCEL", QDialogButtonBox::RejectRole);

    #define INITSTATE(obj,state) obj->setCheckState((state == TRUE) ? Qt::Checked : Qt::Unchecked);
    INITSTATE(checkBox1, optionPlaceStructs);
    INITSTATE(checkBox2, optionProcessStatic);
    INITSTATE(checkBox3, optionAudioOnDone);
    #undef INITSTATE

    // Apply style sheet
    QFile file(STYLE_PATH "style.qss");
    if (file.open(QFile::ReadOnly | QFile::Text))
        setStyleSheet(QTextStream(&file).readAll());

	this->segs = segs;
}

// On choose segments
void MainDialog::segmentSelect()
{
	*segs = SegSelect::select((SegSelect::DATA_HINT | SegSelect::RDATA_HINT), "Choose segments to scan");
}

// Do main dialog, return TRUE if canceled
BOOL doMainDialog(BOOL &optionPlaceStructs, BOOL &optionProcessStatic, BOOL &optionAudioOnDone, SegSelect::segments **segs)
{
	BOOL result = TRUE;
    MainDialog *dlg = new MainDialog(optionPlaceStructs, optionProcessStatic, optionAudioOnDone, segs);
    if (dlg->exec())
    {
        #define CHECKSTATE(obj,var) var = dlg->obj->isChecked()
        CHECKSTATE(checkBox1, optionPlaceStructs);
        CHECKSTATE(checkBox2, optionProcessStatic);
        CHECKSTATE(checkBox3, optionAudioOnDone);
        #undef CHECKSTATE
		result = FALSE;
    }
	delete dlg;
    return(result);
}
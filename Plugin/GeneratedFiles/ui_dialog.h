/********************************************************************************
** Form generated from reading UI file 'dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.4.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_DIALOG_H
#define UI_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>

QT_BEGIN_NAMESPACE

class Ui_MainCIDialog
{
public:
    QDialogButtonBox *buttonBox;
    QCheckBox *checkBox1;
    QCheckBox *checkBox2;
    QCheckBox *checkBox3;
    QCheckBox *checkBox4;
    QLabel *linkLabel;
    QLabel *image;
    QLabel *versionLabel;
    QPushButton *pushButton1;

    void setupUi(QDialog *MainCIDialog)
    {
        if (MainCIDialog->objectName().isEmpty())
            MainCIDialog->setObjectName(QStringLiteral("MainCIDialog"));
        MainCIDialog->resize(292, 344);
        QSizePolicy sizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(MainCIDialog->sizePolicy().hasHeightForWidth());
        MainCIDialog->setSizePolicy(sizePolicy);
        MainCIDialog->setMinimumSize(QSize(292, 344));
        MainCIDialog->setMaximumSize(QSize(292, 344));
        MainCIDialog->setWindowTitle(QStringLiteral("Class Informer"));
        QIcon icon;
        icon.addFile(QStringLiteral(":/classinf/icon.png"), QSize(), QIcon::Normal, QIcon::Off);
        MainCIDialog->setWindowIcon(icon);
#ifndef QT_NO_TOOLTIP
        MainCIDialog->setToolTip(QStringLiteral(""));
#endif // QT_NO_TOOLTIP
        MainCIDialog->setModal(true);
        buttonBox = new QDialogButtonBox(MainCIDialog);
        buttonBox->setObjectName(QStringLiteral("buttonBox"));
        buttonBox->setGeometry(QRect(120, 312, 156, 24));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::NoButton);
        buttonBox->setCenterButtons(false);
        checkBox1 = new QCheckBox(MainCIDialog);
        checkBox1->setObjectName(QStringLiteral("checkBox1"));
        checkBox1->setGeometry(QRect(15, 95, 121, 17));
        QFont font;
        font.setFamily(QStringLiteral("Noto Sans"));
        font.setPointSize(10);
        checkBox1->setFont(font);
#ifndef QT_NO_TOOLTIP
        checkBox1->setToolTip(QStringLiteral(""));
#endif // QT_NO_TOOLTIP
        checkBox2 = new QCheckBox(MainCIDialog);
        checkBox2->setObjectName(QStringLiteral("checkBox2"));
        checkBox2->setGeometry(QRect(15, 125, 256, 17));
        checkBox2->setFont(font);
#ifndef QT_NO_TOOLTIP
        checkBox2->setToolTip(QStringLiteral(""));
#endif // QT_NO_TOOLTIP
        checkBox3 = new QCheckBox(MainCIDialog);
        checkBox3->setObjectName(QStringLiteral("checkBox3"));
        checkBox3->setGeometry(QRect(15, 155, 201, 17));
        checkBox3->setFont(font);
#ifndef QT_NO_TOOLTIP
        checkBox3->setToolTip(QStringLiteral(""));
#endif // QT_NO_TOOLTIP
        checkBox4 = new QCheckBox(MainCIDialog);
        checkBox4->setObjectName(QStringLiteral("checkBox4"));
        checkBox4->setGeometry(QRect(15, 185, 151, 17));
        checkBox4->setFont(font);
#ifndef QT_NO_TOOLTIP
        checkBox4->setToolTip(QStringLiteral(""));
#endif // QT_NO_TOOLTIP
        linkLabel = new QLabel(MainCIDialog);
        linkLabel->setObjectName(QStringLiteral("linkLabel"));
        linkLabel->setGeometry(QRect(15, 256, 141, 16));
        linkLabel->setFont(font);
        linkLabel->setFrameShadow(QFrame::Sunken);
        linkLabel->setTextFormat(Qt::AutoText);
        linkLabel->setOpenExternalLinks(true);
        image = new QLabel(MainCIDialog);
        image->setObjectName(QStringLiteral("image"));
        image->setGeometry(QRect(0, 0, 292, 74));
#ifndef QT_NO_TOOLTIP
        image->setToolTip(QStringLiteral(""));
#endif // QT_NO_TOOLTIP
        image->setTextFormat(Qt::PlainText);
        image->setPixmap(QPixmap(QString::fromUtf8(":/classinf/banner.png")));
        image->setTextInteractionFlags(Qt::NoTextInteraction);
        versionLabel = new QLabel(MainCIDialog);
        versionLabel->setObjectName(QStringLiteral("versionLabel"));
        versionLabel->setGeometry(QRect(225, 45, 61, 21));
        QFont font1;
        font1.setFamily(QStringLiteral("Noto Sans"));
        font1.setPointSize(9);
        versionLabel->setFont(font1);
#ifndef QT_NO_TOOLTIP
        versionLabel->setToolTip(QStringLiteral(""));
#endif // QT_NO_TOOLTIP
        versionLabel->setTextFormat(Qt::PlainText);
        versionLabel->setTextInteractionFlags(Qt::NoTextInteraction);
        pushButton1 = new QPushButton(MainCIDialog);
        pushButton1->setObjectName(QStringLiteral("pushButton1"));
        pushButton1->setGeometry(QRect(15, 215, 129, 27));
        pushButton1->setFont(font);
#ifndef QT_NO_TOOLTIP
        pushButton1->setToolTip(QStringLiteral("<html><head/><body><p>Optionally select wich segments to scan for strings.</p></body></html>"));
#endif // QT_NO_TOOLTIP
        pushButton1->setText(QStringLiteral("SELECT SEGMENTS"));
        pushButton1->setAutoDefault(false);

        retranslateUi(MainCIDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), MainCIDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), MainCIDialog, SLOT(reject()));
        QObject::connect(pushButton1, SIGNAL(pressed()), MainCIDialog, SLOT(segmentSelect()));

        QMetaObject::connectSlotsByName(MainCIDialog);
    } // setupUi

    void retranslateUi(QDialog *MainCIDialog)
    {
        checkBox1->setText(QApplication::translate("MainCIDialog", "Place structures", 0));
        checkBox2->setText(QApplication::translate("MainCIDialog", "Process static initializers && terminators", 0));
        checkBox3->setText(QApplication::translate("MainCIDialog", "Overwrite anterior comments", 0));
        checkBox4->setText(QApplication::translate("MainCIDialog", "Audio on completion", 0));
        linkLabel->setText(QApplication::translate("MainCIDialog", "<a href=\"http://www.macromonkey.com/bb/index.php/topic,13.0.html\" style=\"color:#AA00FF;\">Class Informer Fourm</a>", 0));
        image->setText(QString());
        versionLabel->setText(QApplication::translate("MainCIDialog", "Version: 2.4\n"
"By Sirmabus", 0));
        Q_UNUSED(MainCIDialog);
    } // retranslateUi

};

namespace Ui {
    class MainCIDialog: public Ui_MainCIDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_DIALOG_H

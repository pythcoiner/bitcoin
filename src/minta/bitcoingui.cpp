// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include "minta/controller.h"
#include <minta/bitcoingui.h>
#include <qlogging.h>
#include <qt/QtWidgets/qpushbutton.h>

#include <vector>

#ifdef Q_OS_MACOS
#include <qt/macdockiconhandler.h>
#endif

#include <minta/column.h>

const std::string BitcoinGUI::DEFAULT_UIPLATFORM =
#if defined(Q_OS_MACOS)
        "macosx"
#elif defined(Q_OS_WIN)
        "windows"
#else
        "other"
#endif
        ;

BitcoinGUI::BitcoinGUI(
    GuiController *controller
) : m_controller(controller)
{


#ifdef Q_OS_MACOS
    m_app_nap_inhibitor = new CAppNapInhibitor;
#endif

    m_button = new QPushButton("yay");
    auto *col = (new Column())
        ->push(m_button);

    connect(m_button, &QPushButton::clicked, this, &BitcoinGUI::listCommands);

    this->setCentralWidget(col);
}

BitcoinGUI::~BitcoinGUI()
{

#ifdef Q_OS_MACOS
    delete m_app_nap_inhibitor;
    MacDockIconHandler::cleanup();
#endif
}

void BitcoinGUI::closeEvent(QCloseEvent *ev) {
    Q_EMIT this->quitRequested();
    if (m_allow_close) {
        ev->accept();
    } else {
        ev->ignore();
    }
}

void BitcoinGUI::doClose() {
    m_allow_close = true;
    QApplication::exit(0);
}

void BitcoinGUI::rcvCommands(std::vector<std::string> commands) {
    for (auto cmd : commands) {
        qDebug() << cmd;
    }

}

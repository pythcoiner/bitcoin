// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BITCOINGUI_H
#define BITCOIN_QT_BITCOINGUI_H

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <QMainWindow>
#include <QPushButton>
#include <qevent.h>
#include <vector>

#ifdef Q_OS_MACOS
#include <qt/macos_appnap.h>
#endif

class GuiController;

QT_BEGIN_NAMESPACE
// class QAction;
QT_END_NAMESPACE

class BitcoinGUI : public QMainWindow
{
    Q_OBJECT

public:
    static const std::string DEFAULT_UIPLATFORM;

    explicit BitcoinGUI(GuiController *controller);
    ~BitcoinGUI() override;

Q_SIGNALS:
    void quitRequested();
    void listCommands();

public Q_SLOT:
    void rcvCommands(std::vector<std::string> commands);
    void doClose();

protected:
    void closeEvent(QCloseEvent *ev) override;

private:
    GuiController *m_controller;
    QPushButton *m_button = nullptr;
    bool m_allow_close = false;

#ifdef Q_OS_MACOS
    CAppNapInhibitor* m_app_nap_inhibitor = nullptr;
#endif
};

#endif // BITCOIN_QT_BITCOINGUI_H

#pragma once

#include "init.h"
#include "interfaces/chain.h"
#include "interfaces/init.h"
#include "interfaces/node.h"
#include "node/context.h"
#include "minta/initexecutor.h"
#include <QApplication>
#include <QList>
#include <QObject>
#include <QPair>
#include <QPointer>
#include <QThread>
#include <QWidget>
#include <qmetaobject.h>
#include <qobject.h>
#include <qtmetamacros.h>
#include <qtypes.h>

class BitcoinGUI;
class Panel;
class NodeWorker;
class Chain;
class BitcoinQtInit;

class GuiController : public QObject {
    Q_OBJECT
public:
    GuiController(
        QApplication *parent
    );
    ~GuiController() override = default;

Q_SIGNALS:
    void initNode();
    void quitRequested();

protected Q_SLOTS:
    void load(Panel *panel);

private:
    QPointer<Panel> m_current_panel;
    BitcoinGUI *m_window;
    NodeWorker *m_node;
    QThread *m_node_thread;
};

class NodeWorker : public QObject {
    Q_OBJECT
public:
    NodeWorker(GuiController *controller);
    ~NodeWorker() override = default;

Q_SIGNALS:
    void commands(std::vector<std::string>);

    void baseInitSuccess();
    void baseInitFail();

    void initSuccess();
    void initFail();
    void shutdown();
    void shutdownResult();

public Q_SLOTS:
    void baseInitNode();
    void initNode();
    void initializeResult(bool success, interfaces::BlockAndHeaderTipInfo tip_info);

    static void onBaseInitFail();
    static void onInitFail();

    void onShutdown();
    static void quitApplication();

    void listCommands();

private:
    std::optional<InitExecutor> m_executor;
    interfaces::Init *m_init;
    std::unique_ptr<interfaces::Node> m_node;
    std::unique_ptr<interfaces::Chain> m_chain;
    GuiController *m_controller;

};


class BitcoinQtInit : public interfaces::Init
{
public:
    BitcoinQtInit()
    {
        InitContext(m_node);
        m_node.init = this;
    }
    std::unique_ptr<interfaces::Node> makeNode() override { return interfaces::MakeNode(m_node); }
    std::unique_ptr<interfaces::Chain> makeChain() override { return interfaces::MakeChain(m_node); }
    std::unique_ptr<interfaces::Mining> makeMining() override { return interfaces::MakeMining(m_node); }
    std::unique_ptr<interfaces::WalletLoader> makeWalletLoader(interfaces::Chain& chain) override
    {
        return MakeWalletLoader(chain, *Assert(m_node.args));
    }
    std::unique_ptr<interfaces::Echo> makeEcho() override { return interfaces::MakeEcho(); }
    node::NodeContext m_node;
};




#include "bitcoingui.h"
#include "common/args.h"
#include "controller.h"
#include "minta/initexecutor.h"
#include "panel.h"
#include <common/init.h>
#include <memory>
#include <qassert.h>
#include <qcoreapplication.h>
#include <qlogging.h>
#include <qmainwindow.h>
#include <qnamespace.h>
#include <qobject.h>
#include <qtmetamacros.h>

GuiController::GuiController(
    QApplication *parent
) : QObject(parent) {
    qDebug() << "GuiController::GuiController()" << QThread::currentThreadId();

    // Parse bitcoin.conf, determine network, switch to network specific
    // options, and create datadir and settings.json.
    // - Do not call gArgs.GetDataDirNet() before this step finishes
    // - Do not call Params() before this step
    if (auto error = common::InitConfig(gArgs)) {
        qCritical() << "Fail to open bitcoin.conf:" << error->message.original;
        QApplication::exit(1);
    }


    InitLogging(gArgs);
    InitParameterInteraction(gArgs);

    m_window = new  BitcoinGUI(this);
    m_node = new NodeWorker( this);
    m_node_thread = new QThread;


    connect(m_window, &BitcoinGUI::listCommands, m_node, &NodeWorker::listCommands);
    connect(m_node, &NodeWorker::commands, m_window, &BitcoinGUI::rcvCommands);

    connect(m_window, &BitcoinGUI::quitRequested, m_node, &NodeWorker::onShutdown);
    connect(m_node, &NodeWorker::shutdownResult, m_window , &BitcoinGUI::doClose);

    connect(this, &GuiController::initNode, m_node, &NodeWorker::baseInitNode);

    connect(m_node, &NodeWorker::initSuccess, m_window, &QMainWindow::show);

    m_node->moveToThread(m_node_thread);
    m_node_thread->start();

    Q_EMIT this->initNode();
    qDebug() << "GuiController::GuiController() ended" << QThread::currentThreadId();

}

void GuiController::load(Panel *panel) {
    // if we don't take the previous it will be deleted
    auto *old = m_window->takeCentralWidget(); // NOLINT
    m_window->setCentralWidget(panel->widget());
    m_current_panel = panel;
}

NodeWorker::NodeWorker(
    GuiController *controller
// cannot move an object that have a parent
) : QObject(nullptr),  m_controller(controller) {
    m_init = new BitcoinQtInit();
    m_node = m_init->makeNode();
    m_chain = m_init->makeChain();
    m_executor.emplace(*m_node);
    connect(this, &NodeWorker::shutdown, &m_executor.value(), &InitExecutor::shutdown);
    connect(this, &NodeWorker::baseInitSuccess, this, &NodeWorker::initNode);
    connect(this, &NodeWorker::baseInitFail, this, &NodeWorker::onBaseInitFail);
    connect(this, &NodeWorker::initFail, this, &NodeWorker::onInitFail);
    connect(&m_executor.value(), &InitExecutor::initializeResult, this, &NodeWorker::initializeResult);
    connect(&m_executor.value(), &InitExecutor::initializeResult, this, &NodeWorker::initializeResult);
    connect(&m_executor.value(), &InitExecutor::shutdownResult, this, &NodeWorker::shutdownResult);
}

void NodeWorker::baseInitNode() {
    qDebug() << "NodeController::baseInitNode() ";
    auto baseInit = m_node->baseInitialize();
    if (baseInit) {
        Q_EMIT this->baseInitSuccess();
    } else {
        Q_EMIT this->baseInitFail();
    }
}

void NodeWorker::initNode() {
    qDebug() << "NodeController::initNode() " ;
    m_executor->initialize();
}

void NodeWorker::initializeResult(bool success, interfaces::BlockAndHeaderTipInfo tip_info) {
    qDebug() << "NodeController::initializeResult() => header_height:" << tip_info.header_height;
    if (success) {
        Q_EMIT this->initSuccess();
    } else {
        Q_EMIT this->initFail();
    }
}

void NodeWorker::onBaseInitFail() {
    qDebug() << "NodeController::onBaseInitFail() " << QThread::currentThreadId();
    QCoreApplication::exit(1);
}

void NodeWorker::onInitFail() {
    qDebug() << "NodeController::onInitFail() " << QThread::currentThreadId();
    QCoreApplication::exit(1);

}

void NodeWorker::onShutdown() {
    Q_EMIT this->shutdown();
}


void NodeWorker::quitApplication() {
    QThread::sleep(3);
    QCoreApplication::exit(0);

}

void NodeWorker::listCommands() {
    qDebug() << "NodeController::listCommands()" << QThread::currentThreadId();
    auto res = m_node->listRpcCommands();
    Q_EMIT this->commands(res);

}

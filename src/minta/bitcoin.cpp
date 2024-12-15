// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "minta/controller.h"
#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <QApplication>
#include <QDebug>
#include <common/args.h>
#include <common/init.h>
#include <common/system.h>
#include <cstdlib>

int GuiMain(int argc, char* argv[])
{
#ifdef WIN32
    common::WinCmdLineArgs winArgs;
    std::tie(argc, argv) = winArgs.get();
#endif

    SetupEnvironment();

    QApplication app(argc, argv);

    // Parse command-line options
    SetupServerArgs(gArgs, false);
    std::string error;
    if (!gArgs.ParseParameters(argc, argv, error)) {
        qCritical() << "fail to parse args: " << error;
        return EXIT_FAILURE;
    }

    try
    {
        auto controller = GuiController(&app);
        QApplication::exec();
    } catch (const std::exception& e) {
        qCritical() << e.what();
        return EXIT_FAILURE;
    } catch (...) {
        qCritical() << "Runaway Exception";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

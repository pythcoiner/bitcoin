# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

set(QT_BIN minta)
set(QT_SOURCES mintaqt)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  enable_language(OBJCXX)
  set(CMAKE_OBJCXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
  set(CMAKE_OBJCXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
  set(CMAKE_OBJCXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
  set(CMAKE_OBJCXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL}")
  string(APPEND CMAKE_OBJCXX_COMPILE_OBJECT " ${APPEND_CPPFLAGS} ${APPEND_CXXFLAGS}")
endif()

get_target_property(qt_lib_type Qt6::Core TYPE)

function(import_plugins target)
  if(qt_lib_type STREQUAL "STATIC_LIBRARY")
    set(plugins Qt6::QMinimalIntegrationPlugin)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      list(APPEND plugins Qt6::QXcbIntegrationPlugin)
    elseif(WIN32)
      list(APPEND plugins Qt6::QWindowsIntegrationPlugin Qt6::QModernWindowsStylePlugin)
    elseif(APPLE)
      list(APPEND plugins Qt6::QCocoaIntegrationPlugin Qt6::QMacStylePlugin)
    endif()
    qt6_import_plugins(${target}
      INCLUDE ${plugins}
      EXCLUDE_BY_TYPE
        accessiblebridge
        platforms
        platforms_darwin
        xcbglintegrations
        platformthemes
        platforminputcontexts
        generic
        iconengines
        imageformats
        egldeviceintegrations
        styles
        networkaccess
        networkinformation
        tls
    )
  endif()
endfunction()

# For Qt-specific commands and variables, please consult:
#  - https://cmake.org/cmake/help/latest/manual/cmake-qt.7.html
#  - https://doc.qt.io/qt-5/cmake-manual.html

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOMOC_MOC_OPTIONS "-p${CMAKE_CURRENT_SOURCE_DIR}")
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOUIC_SEARCH_PATHS forms)

add_library(${QT_SOURCES} STATIC EXCLUDE_FROM_ALL
  bitcoin.cpp
  bitcoin.h
  bitcoingui.cpp
  bitcoingui.h
  column.h
  column.cpp
  controller.h
  controller.cpp
  initexecutor.cpp
  initexecutor.h
  $<$<PLATFORM_ID:Darwin>:macdockiconhandler.h>
  $<$<PLATFORM_ID:Darwin>:macdockiconhandler.mm>
  $<$<PLATFORM_ID:Darwin>:macnotificationhandler.h>
  $<$<PLATFORM_ID:Darwin>:macnotificationhandler.mm>
  $<$<PLATFORM_ID:Darwin>:macos_appnap.h>
  $<$<PLATFORM_ID:Darwin>:macos_appnap.mm>
  panel.cpp
  panel.h
  row.h
  row.cpp
  $<$<PLATFORM_ID:Windows>:winshutdownmonitor.cpp>
  $<$<PLATFORM_ID:Windows>:winshutdownmonitor.h>
)
target_compile_definitions(${QT_SOURCES}
  PUBLIC
    QT_NO_KEYWORDS
    QT_USE_QSTRINGBUILDER
)
target_include_directories(${QT_SOURCES}
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
)
set_property(SOURCE macnotificationhandler.mm
  # Ignore warnings "'NSUserNotificationCenter' is deprecated: first deprecated in macOS 11.0".
  APPEND PROPERTY COMPILE_OPTIONS -Wno-deprecated-declarations
)
target_link_libraries(${QT_SOURCES}
  PUBLIC
    Qt6::Widgets
  PRIVATE
    core_interface
    bitcoin_cli
    leveldb
    Boost::headers
    $<TARGET_NAME_IF_EXISTS:QRencode::QRencode>
    $<$<PLATFORM_ID:Darwin>:-framework\ AppKit>
    $<$<CXX_COMPILER_ID:MSVC>:shlwapi>
)

if(ENABLE_WALLET)
  target_sources(${QT_SOURCES}
    PRIVATE
  )
  target_link_libraries(${QT_SOURCES}
    PRIVATE
      bitcoin_wallet
      Qt6::Network
  )
endif()

if(WITH_DBUS)
  target_link_libraries(${QT_SOURCES} PRIVATE Qt6::DBus)
endif()

if(qt_lib_type STREQUAL "STATIC_LIBRARY")
  # We want to define static plugins to link ourselves, thus preventing
  # automatic linking against a "sane" set of default static plugins.
  qt6_import_plugins(${QT_SOURCES}
    EXCLUDE_BY_TYPE
      accessiblebridge
      platforms
      platforms_darwin
      xcbglintegrations
      platformthemes
      platforminputcontexts
      generic
      iconengines
      imageformats
      egldeviceintegrations
      styles
      networkaccess
      networkinformation
      tls
  )
endif()

add_executable(${QT_BIN}
  main.cpp
)

target_link_libraries(${QT_BIN}
  core_interface
  ${QT_SOURCES}
  bitcoin_node
)

import_plugins(${QT_BIN})
set(installable_targets ${QT_BIN})
if(WIN32)
  set_target_properties(${QT_BIN} PROPERTIES WIN32_EXECUTABLE TRUE)
endif()

install(TARGETS ${installable_targets}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  COMPONENT GUI
)

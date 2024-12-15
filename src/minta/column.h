#pragma once

#include <QHBoxLayout>
#include <QLabel>
#include <QMainWindow>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>
#include <qboxlayout.h>
#include <qlayout.h>
#include <qlogging.h>
#include <qnamespace.h>

class Column : public QWidget {
    Q_OBJECT

public:
    explicit Column(QWidget *parent = nullptr);
    auto layout() -> QVBoxLayout*;
    auto push(QWidgetItem *item) -> Column*;
    auto push(QWidget *widget) -> Column*;
    auto push(std::optional<QWidget*> opt_widget) -> Column*;
    auto push(QLayout *layout) -> Column*;
    auto widget() -> QWidget*;
    auto pushSpacer() -> Column*;
    auto pushSpacer(int height) -> Column*;
    auto pushStretch(int factor) -> Column*;
    void setLayout(QLayout *layout);

};

#pragma once

#include <QObject>
#include <QPointer>
#include <QWidget>

class Controller;

class Panel : public QObject {
    Q_OBJECT
public:
    Panel(QWidget *widget, QObject *parent);
    ~Panel() override = default;
    auto widget() -> QWidget*;
    virtual void onConnect(Controller *controller) = 0;
    virtual void onDisconnect(Controller *controller) =0;

private:
    QPointer<QWidget> m_widget;
};

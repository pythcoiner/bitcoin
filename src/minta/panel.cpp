#include "panel.h"
#include <qobject.h>
#include <qwidget.h>

Panel::Panel(QWidget *widget, QObject *parent): QObject(parent), m_widget(widget) {}

QWidget* Panel::widget() {
    return m_widget;
}

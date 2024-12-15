#include "row.h"
#include <qwidget.h>

Row::Row(QWidget *parent) : QWidget(parent) {
    auto *layout = new QHBoxLayout;
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    QWidget::setLayout(layout);
}

auto Row::push(QWidgetItem *item) -> Row* {
    this->layout()->addItem(item);
    return this;
}

auto Row::push(QWidget *widget) -> Row* {
    widget->setParent(this);
    this->layout()->addWidget(widget);
    return this;
}

auto Row::push(QLayout *layout) -> Row* {
    layout->setParent(this);
    this->layout()->addLayout(layout);
    return this;
}

auto Row::widget() -> QWidget* {
    return this;
}

auto Row::pushSpacer() -> Row* {
    this->layout()->addStretch();
    return this;
}

auto Row::pushSpacer(int width) -> Row* {
    this->layout()->addSpacing(width);
    return this;
}

auto Row::pushStretch(int factor) -> Row* {
    this->layout()->addStretch(factor);
    return this;
}

// NOTE:we need to override this method in order to prevent consumer to change layout type
void Row::setLayout(QLayout *layout) { // NOLINT
    qCritical() << "Layout of a Row cannot be changed";
}

// we need override the method in order to return a QHBoxLayout* because
// addLayout() is is not implemented on QLayout
auto Row::layout() -> QHBoxLayout* {
    QLayout* currentLayout = QWidget::layout();
    auto* hboxLayout = dynamic_cast<QHBoxLayout*>(currentLayout);
    if (hboxLayout == nullptr) {
        qFatal() << "layout is not of type QHBoxLayout!";
    }
    return hboxLayout;

}

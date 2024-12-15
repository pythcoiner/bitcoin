#include "column.h"

Column::Column(QWidget *parent) : QWidget(parent) {
    auto *layout = new QVBoxLayout;
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    QWidget::setLayout(layout);
}

auto Column::push(QWidgetItem *item) -> Column* {
    this->layout()->addItem(item);
    return this;
}

auto Column::push(QWidget *widget) -> Column* {
    this->layout()->addWidget(widget);
    return this;
}

auto Column::push(std::optional<QWidget*> opt_widget) -> Column* {
    if (opt_widget.has_value()) {
        this->push(opt_widget.value());
    }
    return this;
}

auto Column::push(QLayout *layout) -> Column* {
    this->layout()->addLayout(layout);
    return this;
}

auto Column::widget() -> QWidget* {
    return this;
}

auto Column::pushSpacer() -> Column* {
    this->layout()->addStretch();
    return this;
}

auto Column::pushSpacer(int height) -> Column* {
    this->layout()->addSpacing(height);
    return this;
}

auto Column::pushStretch(int factor) -> Column* {
    this->layout()->addStretch(factor);
    return this;
}

// NOTE:we need to override this method in order to impeach consumer to change layout type
void Column::setLayout(QLayout *layout) { // NOLINT
    qCritical() << "Layout of a Column cannot be changed";
}

// we need override the method in order to return a QHBoxLayout* because
// addLayout() is is not implemented on QLayout
auto Column::layout() -> QVBoxLayout* {
    QLayout* currentLayout = QWidget::layout();
    auto* vboxLayout = dynamic_cast<QVBoxLayout*>(currentLayout);
    if (vboxLayout == nullptr) {
        qFatal() << "layout is not of type QVBoxLayout!";
    }
    return vboxLayout;

}

#include "ChatMessageEdit.h"
#include <QKeyEvent>
#include <QSize>
#include <QAbstractTextDocumentLayout>
#include "Log.h"

ChatMessageEdit::ChatMessageEdit(QWidget *parent) :
	QTextEdit(parent)
{
	setMinimumHeight(sizeHint().height()); // empty
}

QSize ChatMessageEdit::sizeHint() const {
	return QSize(0, document()->documentLayout()->documentSize().toSize().height() + 2);
}

QSize ChatMessageEdit::minimumSizeHint() const {
	return sizeHint();
}

void ChatMessageEdit::keyPressEvent(QKeyEvent *e) {
	if(e->key() == Qt::Key_Return && !e->modifiers().testFlag(Qt::ShiftModifier)) {
		emit dispatchRequested();
		return;
	}

	QTextEdit::keyPressEvent(e);

	updateGeometry();
}

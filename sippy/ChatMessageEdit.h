#ifndef CHATMESSAGEEDIT_H
#define CHATMESSAGEEDIT_H

#include <QTextEdit>

class ChatMessageEdit : public QTextEdit
{
Q_OBJECT
public:
	ChatMessageEdit(QWidget *parent = 0);

	virtual QSize sizeHint() const;
	virtual QSize minimumSizeHint() const;

signals:
	void dispatchRequested();

protected:
	void keyPressEvent(QKeyEvent *e);
};

#endif // CHATMESSAGEEDIT_H

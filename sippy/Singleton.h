#ifndef __SINGLETON__H__
#define __SINGLETON__H__

#include <QMutex>

template<class T> class Singleton {
protected:
	Singleton() {

	}

	virtual ~Singleton() {

	}
public:
	static T * instance() {
		static QMutex objectMutex;
		static T * object = NULL;

		objectMutex.lock();

		if(object == NULL)
			object = new T();
		
		objectMutex.unlock();

		return object;
	}
};

#endif


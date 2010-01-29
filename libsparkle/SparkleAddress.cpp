#include <string.h>
#include "Log.h"
#include "SparkleAddress.h"

SparkleAddress::SparkleAddress() {
	memset(_bytes, 0, SPARKLE_ADDRESS_SIZE);
}

SparkleAddress::SparkleAddress(QByteArray origin) {
	if(origin.size() != SPARKLE_ADDRESS_SIZE) {
		Log::error("attempting to create SparkleAddress with size %1") << origin.size();
		origin.resize(SPARKLE_ADDRESS_SIZE);
	}

	memcpy(_bytes, origin.constData(), SPARKLE_ADDRESS_SIZE);
}

SparkleAddress::SparkleAddress(const quint8 origin[SPARKLE_ADDRESS_SIZE]) {
	memcpy(_bytes, origin, SPARKLE_ADDRESS_SIZE);
}

bool SparkleAddress::isNull() const {
	for(int i = 0; i < SPARKLE_ADDRESS_SIZE; i++) {
		if(_bytes[i] != 0)
			return false;
	}

	return true;
}

const QByteArray SparkleAddress::bytes() const {
	return QByteArray((const char*) _bytes, SPARKLE_ADDRESS_SIZE);
}

const quint8* SparkleAddress::rawBytes() const {
	return _bytes;
}

bool SparkleAddress::operator==(SparkleAddress other) const {
	return !memcmp(_bytes, other._bytes, SPARKLE_ADDRESS_SIZE);
}

bool SparkleAddress::operator!=(SparkleAddress other) const {
	return !(*this == other);
}

QString SparkleAddress::pretty() const {
	return QString(bytes().toHex()).toUpper().replace(QRegExp("(..)"), "\\1:").left(SPARKLE_ADDRESS_SIZE * 3 - 1);
}

uint qHash(const SparkleAddress &key) {
	return qHash(key.bytes());
}

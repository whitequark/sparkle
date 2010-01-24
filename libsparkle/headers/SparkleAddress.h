#ifndef SPARKLEADDRESS_H
#define SPARKLEADDRESS_H

#include <QByteArray>

#define SPARKLE_ADDRESS_SIZE	6

class SparkleAddress
{
public:
	SparkleAddress();
	SparkleAddress(QByteArray);
	SparkleAddress(const quint8[SPARKLE_ADDRESS_SIZE]);

	bool isNull() const;

	const QByteArray bytes() const;
	const quint8* rawBytes() const;

	bool operator==(SparkleAddress) const;

	QString pretty() const;
	static QString makePrettyMAC(QByteArray mac);

private:
	quint8 _bytes[SPARKLE_ADDRESS_SIZE];
};

uint qHash(const SparkleAddress &key);

#endif // SPARKLEADDRESS_H

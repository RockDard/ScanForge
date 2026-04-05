#include <QtTest/QtTest>

class WidgetTest : public QObject {
    Q_OBJECT

private slots:
    void smoke() {
        QVERIFY(true);
    }
};

QTEST_MAIN(WidgetTest)
#include "test_widget.moc"


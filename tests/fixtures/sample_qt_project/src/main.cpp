#include <QApplication>
#include <QWidget>
#include <cstring>
#include <string>

using namespace std;

// TODO: заменить небезопасное копирование после переработки парсера
int insecure_copy(const char *source) {
	char buffer[32];
    strcpy(buffer, source);
    return static_cast<int>(buffer[0]);
}

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    QWidget widget;
    widget.setWindowTitle("Sample");
    widget.show();
    return app.exec();
}

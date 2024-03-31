#ifndef ENCRYPTIONAPP_H
#define ENCRYPTIONAPP_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class EncryptionApp; }
QT_END_NAMESPACE

class EncryptionApp : public QMainWindow
{
    Q_OBJECT

public:
    EncryptionApp(QWidget *parent = nullptr);
    ~EncryptionApp();

private:
    Ui::EncryptionApp *ui;
};
#endif // ENCRYPTIONAPP_H

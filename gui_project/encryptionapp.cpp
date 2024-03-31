#include "encryptionapp.h"
#include "ui_encryptionapp.h"

EncryptionApp::EncryptionApp(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::EncryptionApp)
{
    ui->setupUi(this);
}

EncryptionApp::~EncryptionApp()
{
    delete ui;
}


#include <QApplication>
#include <QPushButton>
#include <QTextEdit>
#include <QWidget>
#include <QVBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QMessageBox>
#include <QFileDialog>
#include <QMessageBox>

#include "cryptopp/modes.h"
#include "cryptopp/aes.h"
#include "cryptopp/blowfish.h"
#include "cryptopp/filters.h"
#include "cryptopp/osrng.h"
#include "cryptopp/files.h"

using namespace CryptoPP;
using namespace std;

class CryptoApp : public QWidget {

public:
    CryptoApp(QWidget *parent = 0) : QWidget(parent) {
        // GUI setup


        QVBoxLayout *layout = new QVBoxLayout(this);
        inputText = new QTextEdit(this);
        outputText = new QTextEdit(this);
        outputText->setReadOnly(true);




        // AES Buttons
        QPushButton *aesEncryptButton = new QPushButton("AES Encrypt", this);
        QPushButton *aesDecryptButton = new QPushButton("AES Decrypt", this);

        // Blowfish Buttons
        QPushButton *blowfishEncryptButton = new QPushButton("Blowfish Encrypt", this);
        QPushButton *blowfishDecryptButton = new QPushButton("Blowfish Decrypt", this);

        // Refresh Button
        QPushButton *refreshButton = new QPushButton("Refresh/Reset", this);

        // Output Text Area
        QLabel *outputLabel = new QLabel("Output:");
        outputText = new QTextEdit(this);
        outputText->setReadOnly(true);
        QLabel *inputLabel = new QLabel("Enter Text:");
        inputText = new QTextEdit(this);

        // Adding widgets to the layout
        layout->addWidget(inputLabel);
        // Create a QLabel for the welcome message
                QLabel *welcomeLabel = new QLabel("Welcome to the uncrackable encryption tool!", this);
                welcomeLabel->setAlignment(Qt::AlignCenter);

                // Set the text color to red and make it bold

                QColor redColor(255, 0, 0); // Red color
                QPalette palette;
                palette.setColor(QPalette::WindowText, redColor);
                welcomeLabel->setPalette(palette);

                QFont boldFont;
                boldFont.setBold(true);
                welcomeLabel->setFont(boldFont);

                // Add the welcome message to the layout
                layout->addWidget(welcomeLabel);
        layout->addWidget(inputText);
        layout->addSpacing(10); // Adds space between input text and buttons

        QHBoxLayout *encryptionButtonsLayout = new QHBoxLayout();
        encryptionButtonsLayout->addWidget(aesEncryptButton);
        encryptionButtonsLayout->addWidget(blowfishEncryptButton);
        layout->addLayout(encryptionButtonsLayout);

        QHBoxLayout *decryptionButtonsLayout = new QHBoxLayout();
        decryptionButtonsLayout->addWidget(aesDecryptButton);
        decryptionButtonsLayout->addWidget(blowfishDecryptButton);
        layout->addLayout(decryptionButtonsLayout);

        layout->addWidget(refreshButton);
        layout->addSpacing(10); // Adds space before the output area

        layout->addWidget(outputLabel);
        layout->addWidget(outputText);

        // Connect signals to slots
        connect(aesEncryptButton, &QPushButton::clicked, this, &CryptoApp::encryptAes);
        connect(aesDecryptButton, &QPushButton::clicked, this, &CryptoApp::decryptAes);
        connect(blowfishEncryptButton, &QPushButton::clicked, this, &CryptoApp::encryptBlowfish);
        connect(blowfishDecryptButton, &QPushButton::clicked, this, &CryptoApp::decryptBlowfish);
        connect(refreshButton, &QPushButton::clicked, this, &CryptoApp::refreshApp);
        QPushButton *fileEncryptAesButton = new QPushButton("File AES Encrypt", this);
        QPushButton *fileDecryptAesButton = new QPushButton("File AES Decrypt", this);
        QPushButton *fileEncryptBlowfishButton = new QPushButton("File Blowfish Encrypt", this);
        QPushButton *fileDecryptBlowfishButton = new QPushButton("File Blowfish Decrypt", this);

        // Adding file encryption buttons to layout
        QHBoxLayout *fileEncryptionButtonsLayout = new QHBoxLayout();
        fileEncryptionButtonsLayout->addWidget(fileEncryptAesButton);
        fileEncryptionButtonsLayout->addWidget(fileDecryptAesButton);
        fileEncryptionButtonsLayout->addWidget(fileEncryptBlowfishButton);
        fileEncryptionButtonsLayout->addWidget(fileDecryptBlowfishButton);
        layout->addLayout(fileEncryptionButtonsLayout);

        // Connect signals to slots for file encryption buttons
        connect(fileEncryptAesButton, &QPushButton::clicked, this, &CryptoApp::fileEncryptAes);
        connect(fileDecryptAesButton, &QPushButton::clicked, this, &CryptoApp::fileDecryptAes);
        connect(fileEncryptBlowfishButton, &QPushButton::clicked, this, &CryptoApp::fileEncryptBlowfish);
        connect(fileDecryptBlowfishButton, &QPushButton::clicked, this, &CryptoApp::fileDecryptBlowfish);
    }

private slots:
    void fileEncryptAes() { //This slot is for encrypting FILES using AES
            QString filePath = QFileDialog::getOpenFileName(this, "Select File to Encrypt", "", "All Files (*)");
            if (!filePath.isEmpty()) {
                QString outputFilePath = QFileDialog::getSaveFileName(this, "Save Encrypted File", "", "All Files (*)");
                if (!outputFilePath.isEmpty()) {
                    string key = getEncryptionKeyFromUser();

                    try {
                        CBC_Mode<AES>::Encryption encryption((const byte*)key.data(), key.size(), iv_aes);
                        FileSource(filePath.toStdString().c_str(), true, new StreamTransformationFilter(encryption, new FileSink(outputFilePath.toStdString().c_str())));
                        QMessageBox::information(this, "File AES Encryption", "File AES Encryption Successful");
                    } catch (const Exception& e) {
                        QMessageBox::warning(this, "Error", "File AES Encryption Error: " + QString(e.what()));
                    }
                }
            }
        }

        void fileDecryptAes() {//This slot is for decrypting FILES using AES
            QString filePath = QFileDialog::getOpenFileName(this, "Select File to Decrypt", "", "All Files (*)");
            if (!filePath.isEmpty()) {
                QString outputFilePath = QFileDialog::getSaveFileName(this, "Save Decrypted File", "", "All Files (*)");
                if (!outputFilePath.isEmpty()) {
                    string key = getEncryptionKeyFromUser();

                    try {
                        CBC_Mode<AES>::Decryption decryption((const byte*)key.data(), key.size(), iv_aes);
                        FileSource(filePath.toStdString().c_str(), true, new StreamTransformationFilter(decryption, new FileSink(outputFilePath.toStdString().c_str())));
                        QMessageBox::information(this, "File AES Decryption", "File AES Decryption Successful");
                    } catch (const Exception& e) {
                        QMessageBox::warning(this, "Error", "File AES Decryption Error: " + QString(e.what()));
                    }
                }
            }
        }

        void fileEncryptBlowfish() { //This slot is for encrypting FILES using Blowfish
            QString filePath = QFileDialog::getOpenFileName(this, "Select File to Encrypt", "", "All Files (*)");
            if (!filePath.isEmpty()) {
                QString outputFilePath = QFileDialog::getSaveFileName(this, "Save Encrypted File", "", "All Files (*)");
                if (!outputFilePath.isEmpty()) {
                    string key = getEncryptionKeyFromUser();

                    try {
                        CBC_Mode<Blowfish>::Encryption encryption((const byte*)key.data(), key.size(), iv_blowfish);
                        FileSource(filePath.toStdString().c_str(), true, new StreamTransformationFilter(encryption, new FileSink(outputFilePath.toStdString().c_str())));
                        QMessageBox::information(this, "File Blowfish Encryption", "File Blowfish Encryption Successful");
                    } catch (const Exception& e) {
                        QMessageBox::warning(this, "Error", "File Blowfish Encryption Error: " + QString(e.what()));
                    }
                }
            }
        }

        void fileDecryptBlowfish() { //This slot is for decrypting FILES using AES
            QString filePath = QFileDialog::getOpenFileName(this, "Select File to Decrypt", "", "All Files (*)");
            if (!filePath.isEmpty()) {
                QString outputFilePath = QFileDialog::getSaveFileName(this, "Save Decrypted File", "", "All Files (*)");
                if (!outputFilePath.isEmpty()) {
                    string key = getEncryptionKeyFromUser();

                    try {
                        CBC_Mode<Blowfish>::Decryption decryption((const byte*)key.data(), key.size(), iv_blowfish);
                        FileSource(filePath.toStdString().c_str(), true, new StreamTransformationFilter(decryption, new FileSink(outputFilePath.toStdString().c_str())));
                        QMessageBox::information(this, "File Blowfish Decryption", "File Blowfish Decryption Successful");
                    } catch (const Exception& e) {
                        QMessageBox::warning(this, "Error", "File Blowfish Decryption Error: " + QString(e.what()));
                    }
                }
            }
        }
    void encryptAes() { //This slot is for encrypting input text using AES
        string plainText = inputText->toPlainText().toStdString();
        string key = getEncryptionKeyFromUser();

        // AES encryption
        SecByteBlock key_aes((const byte*)key.data(), key.size());
        AutoSeededRandomPool rng;
        rng.GenerateBlock(iv_aes, AES::BLOCKSIZE);

        try {
            CBC_Mode<AES>::Encryption encryption(key_aes, AES::DEFAULT_KEYLENGTH, iv_aes);
            StringSource(plainText, true, new StreamTransformationFilter(encryption, new StringSink(encryptedText_aes)));
            outputText->setText("AES Encrypted Text: " + QString::fromStdString(encryptedText_aes));
        } catch (const Exception& e) {
            QMessageBox::warning(this, "Error", "AES Encryption Error: " + QString(e.what()));
        }
    }

    void decryptAes() { //This slot is for decrypting input text using AES
        string decryptedText;
        string key = getEncryptionKeyFromUser();

        // AES decryption
        SecByteBlock key_aes((const byte*)key.data(), key.size());

        try {
            CBC_Mode<AES>::Decryption decryption(key_aes, AES::DEFAULT_KEYLENGTH, iv_aes);
            StringSource(encryptedText_aes, true, new StreamTransformationFilter(decryption, new StringSink(decryptedText)));
            outputText->setText("AES Decrypted Text: " + QString::fromStdString(decryptedText));
        } catch (const Exception& e) {
            QMessageBox::warning(this, "Error", "AES Decryption Error: " + QString(e.what()));
        }
    }

    void encryptBlowfish() { //This slot is for encrypting input text using blowfish
        string plainText = inputText->toPlainText().toStdString();
        string key = getEncryptionKeyFromUser();

        // Blowfish encryption
        SecByteBlock key_blowfish((const byte*)key.data(), key.size());
        AutoSeededRandomPool rng;
        rng.GenerateBlock(iv_blowfish, Blowfish::BLOCKSIZE);

        try {
            CBC_Mode<Blowfish>::Encryption encryption(key_blowfish, Blowfish::DEFAULT_KEYLENGTH, iv_blowfish);
            StringSource(plainText, true, new StreamTransformationFilter(encryption, new StringSink(encryptedText_blowfish)));
            outputText->setText("Blowfish Encrypted Text: " + QString::fromStdString(encryptedText_blowfish));
        } catch (const Exception& e) {
            QMessageBox::warning(this, "Error", "Blowfish Encryption Error: " + QString(e.what()));
        }
    }

    void decryptBlowfish() { //This slot is for decrypting input text using AES
        string decryptedText;
        string key = getEncryptionKeyFromUser();

        // Blowfish decryption
        SecByteBlock key_blowfish((const byte*)key.data(), key.size());

        try {
            CBC_Mode<Blowfish>::Decryption decryption(key_blowfish, Blowfish::DEFAULT_KEYLENGTH, iv_blowfish);
            StringSource(encryptedText_blowfish, true, new StreamTransformationFilter(decryption, new StringSink(decryptedText)));
            outputText->setText("Blowfish Decrypted Text: " + QString::fromStdString(decryptedText));
        } catch (const Exception& e) {
            QMessageBox::warning(this, "Error", "Blowfish Decryption Error: " + QString(e.what()));
        }
    }

    void refreshApp() { //This slot is refreshing / resetting the keys etc...
        // Clear all keys and encrypted texts
        memset(iv_aes, 0, sizeof(iv_aes));
        memset(iv_blowfish, 0, sizeof(iv_blowfish));
        encryptedText_aes.clear();
        encryptedText_blowfish.clear();

        // Clear input and output fields
        inputText->clear();
        outputText->clear();
    }

    string getEncryptionKeyFromUser() {
        bool ok;
        QString key = QInputDialog::getText(this, "Enter Key", "Encryption Key:", QLineEdit::Password, "", &ok);
        return ok ? key.toStdString() : "";
    }

private:
    QTextEdit *inputText;
    QTextEdit *outputText;
    byte iv_aes[AES::BLOCKSIZE];
    byte iv_blowfish[Blowfish::BLOCKSIZE];
    string encryptedText_aes, encryptedText_blowfish;
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    CryptoApp cryptoApp;
    cryptoApp.show();

    return app.exec();
}

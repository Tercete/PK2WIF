#include "mainwindow.h"
#include "ui_mainwindow.h"

//556e52
//5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEw6QwynKpQi

//1234567891234567891234567891234567891234567891234567891234567891
//5HxJb9hZQLtLgqxvPRnHSCYNN1GMq3g3LWQiQsZywxkS2y6PYX5

//123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF1234
//5HxJb9ha3pQ8iVHRoGLiW964ojFToUTduAacf28fCmbpMVqg32R


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::ValidaPK()
{
    //qDebug() << "1 " << ui->rbWIF2Hex->isChecked();
    if(!ui->rbWIF2Hex->isChecked()) {
        if(ui->edPrivateKey->text().size() != 64) {
            QString szPK = ui->edPrivateKey->text();
            ui->edPrivateKey->setText(QString(64 - ui->edPrivateKey->text().size(), '0') + szPK);
        }
    }
}

void MainWindow::ValidaWIF()
{
    //qDebug() << "2 " << ui->rbHex2WIF->isChecked();
    if(!ui->rbHex2WIF->isChecked()) {
        if(ui->edWIFPK->text().size() != 51) {
            qDebug() << ui->edWIFPK->text().size();
            QMessageBox::critical(0, tr("Erro"), tr("Chave WIF deve ter 51 caracteres!"));
        }
    }
}

void MainWindow::Processa()
{
    char    szPreHash[64];
    QString szTempKey;

    memset(szPreHash, 0, sizeof(szPreHash));
    if(ui->rbHex2WIF->isChecked()) {
        /* Private key to WIF

        1. Take a private key.

           0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
                                                                   b862a62e

        2. Add a 0x80 byte in front of it for mainnet addresses or 0xef for testnet addresses. Also add a 0x01 byte at the end if the private key will correspond to a compressed public key.

           800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D

        3. Perform SHA-256 hash on the extended key.

           8147786C4D15106333BF278D71DADAF1079EF2D2440A4DDE37D747DED5403592

        4. Perform SHA-256 hash on result of SHA-256 hash.

           507A5B8DFED0FC6FE8801743720CEDEC06AA5C6FCA72B07C49964492FB98A714

        5. Take the first 4 bytes of the second SHA-256 hash; this is the checksum.

           507A5B8D

        6. Add the 4 checksum bytes from point 5 at the end of the extended key from point 2.

           800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D507A5B8D

        7. Convert the result from a byte string into a base58 string using Base58Check encoding. This is the wallet import format (WIF).

           5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
        */

        szTempKey = "80" + ui->edPrivateKey->text();
        if(ui->chkCompressed->isChecked()) {
            szTempKey += "01";
        }

        QCryptographicHash  obHash(QCryptographicHash::Sha256);

        obHash.addData(QByteArray::fromHex(szTempKey.toStdString().c_str()), szTempKey.size()/2);
        QByteArray  obResultado = obHash.result();
        qDebug() << obResultado.toHex();

        obHash.reset();
        obHash.addData(obResultado, obResultado.size());
        obResultado = obHash.result();
        qDebug() << obResultado.toHex();

        qDebug() << szTempKey << " + " << obResultado.toHex().left(8);
        szTempKey += obResultado.toHex().left(8);
        szTempKey = szTempKey.toUpper();
        qDebug() << szTempKey << " + " << obResultado.toHex().left(8);

        qDebug() << szTempKey.toStdString().c_str();

        char* pInicio, *pFinal;

        obResultado = QByteArray::fromHex(szTempKey.toStdString().c_str());
        pInicio = obResultado.data();
        pFinal  = obResultado.data() + obResultado.size();
        QString szResultado = encodeBase58(const_cast<unsigned char*>((unsigned char*)pInicio), const_cast<unsigned char*>((unsigned char*)pFinal)).c_str();
        qDebug() << szResultado;
        ui->edWIFPK->setText(szResultado);
    } else {
        /*

    WIF to private key

    1. Take a wallet import format (WIF) string. 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ

       5HueCGU8rMjxEXxiPuD5BDk_SAMPLE_PRIVATE_KEY_DO_NOT_IMPORT_u4MkFqeZyd4dZ1jvhTVqvbTLvyTJ

    2. Convert it to a byte string using Base58Check encoding.

       800C28FCA386C7A227600B2FE50B7CAE11EC_SAMPLE_PRIVATE_KEY_DO_NOT_IMPORT_86D3BF1FBE471BE89827E19D72AA1D507A5B8D

    3. Drop the last 4 checksum bytes from the byte string.

       800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D

    4. Drop the first byte (it should be 0x80, however legacy Electrum[1][2] or some SegWit vanity address generators[3] may use 0x81-0x87). If the private key corresponded to a compressed public key, also drop the last byte (it should be 0x01). If it corresponded to a compressed public key, the WIF string will have started with K or L (or M, if it's exported from legacy Electrum[1][2] etc[3]) instead of 5 (or c instead of 9 on testnet). This is the private key.

       0C28FCA386C7A227600B2FE50B7CAE1_SAMPLE_PRIVATE_KEY_DO_NOT_IMPORT_1EC86D3BF1FBE471BE89827E19D72AA1D

    WIF checksum checking

    1. Take the wallet import format (WIF) string.

       5HueCGU8rMjxEXxiPuD5BD_SAMPLE_PRIVATE_KEY_DO_NOT_IMPORT_ku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ

    2. Convert it to a byte string using Base58Check encoding.

       800C28FCA386C7A227600B2FE50B7CAE11E_SAMPLE_PRIVATE_KEY_DO_NOT_IMPORT_C86D3BF1FBE471BE89827E19D72AA1D507A5B8D

    3. Drop the last 4 checksum bytes from the byte string.

       800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D

    4. Perform SHA-256 hash on the shortened string.

       8147786C4D15106333BF278D71DADAF1079EF2D2440A4DDE37D747DED5403592

    5. Perform SHA-256 hash on result of SHA-256 hash.

       507A5B8DFED0FC6FE8801743720CEDEC06AA5C6FCA72B07C49964492FB98A714

    6. Take the first 4 bytes of the second SHA-256 hash; this is the checksum.

       507A5B8D

    7. Make sure it is the same as the last 4 bytes from point 2.

       507A5B8D

    8. If they are, and the byte string from point 2 starts with 0x80 (0xef for testnet addresses), then there is no error.

    */
        QByteArray obResultado ;
        QString szResultado, szCheckSum ;
        szTempKey = ui->edWIFPK->text();
        decodeBase58(szTempKey.toStdString().c_str(), obResultado);
        szResultado = obResultado.toHex();
        szCheckSum = szResultado.right(8);
        szResultado = szResultado.left(szResultado.size()-8);

        QCryptographicHash  obHash(QCryptographicHash::Sha256);

        obHash.addData(QByteArray::fromHex(szResultado.toStdString().c_str()), szResultado.size()/2);
        obResultado = obHash.result();
        qDebug() << obResultado.toHex();

        obHash.reset();
        obHash.addData(obResultado, obResultado.size());
        obResultado = obHash.result();
        qDebug() << obResultado.toHex();
        if(obResultado.toHex().left(8) != szCheckSum) {
            QMessageBox::critical(0, tr("Erro"), tr("Checksum NAO CONFERE!!"));
        } else {
            ui->edPrivateKey->setText( szResultado.mid((2)) );
        }
    }
}

void MainWindow::Encerra()
{
    close();
}

void MainWindow::SelecionaWIF2PK(bool)
{
    ui->edPrivateKey->setText("");
    ui->chkCompressed->setCheckState(Qt::Unchecked);
}

void MainWindow::SelecionaPK2WIF(bool)
{
    ui->edWIFPK->setText("");
}



/*
 *
std::string word = "hello world";
int len = word.length();
unsigned char x[0]; // = something
unsigned char encoded[(len) * 137 / 100];
EncodeBase58(word, len, encoded);
printf("%s", encoded); // StV1DL6CwTryKyV *

inline static constexpr const uint8_t base58map[] = {
    '1', '2', '3', '4', '5', '6', '7', '8',
    '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q',
    'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
    'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p',
    'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
    'y', 'z' };

std::string EncodeBase58(const std::vector<uint8_t>& data, const uint8_t* mapping)
{
    std::vector<uint8_t> digits((data.size() * 138 / 100) + 1);
    size_t digitslen = 1;
    for (size_t i = 0; i < data.size(); i++)
    {
        uint32_t carry = static_cast<uint32_t>(data[i]);
        for (size_t j = 0; j < digitslen; j++)
        {
            carry = carry + static_cast<uint32_t>(digits[j] << 8);
            digits[j] = static_cast<uint8_t>(carry % 58);
            carry /= 58;
        }
        for (; carry; carry /= 58)
            digits[digitslen++] = static_cast<uint8_t>(carry % 58);
    }
    std::string result;
    for (size_t i = 0; i < (data.size() - 1) && !data[i]; i++)
        result.push_back(mapping[0]);
    for (size_t i = 0; i < digitslen; i++)
        result.push_back(mapping[digits[digitslen - 1 - i]]);
    return result;
}

Usage:
    std::vector<uint8_t> data{ 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd' };
    std::string result = EncodeBase58(data, base58map);



*/

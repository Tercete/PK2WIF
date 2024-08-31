#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QDebug>
#include <QString>
#include <QMessageBox>
#include <QCryptographicHash>
#include <QByteArray>

#include <base58.h>
//#include <bignum.h>
//#include <db.h>
//#include <headers.h>
//#include <irc.h>
//#include <key.h>
//#include <main.h>
//#include <market.h>
//#include <net.h>
//#include <script.h>
//#include <serialize.h>
//#include <sha.h>
//#include <uibase.h>
//#include <ui.h>
//#include <uint256.h>
//#include <util.h>


//0000000000000000000000000000000000000000000000000000000000123456
//5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEtYesssLrmy

//0000000000000000000000000000000000000000000000000000000000556e52
//5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEw6QwynKpQi

//1234567891234567891234567891234567891234567891234567891234567891
//5HxJb9hZQLtLgqxvPRnHSCYNN1GMq3g3LWQiQsZywxkS2y6PYX5

//123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF1234
//5HxJb9ha3pQ8iVHRoGLiW964ojFToUTduAacf28fCmbpMVqg32R

#include <QtWebEngineWidgets/QWebEngineView>
#include <QtWebEngineWidgets/QWebEnginePage>
#include <QtWebEngineWidgets/QWebEngineSettings>

using namespace std;

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

public slots:
    void ValidaPK();
    void Processa();
    void Encerra();
    void ValidaWIF();
    void SelecionaWIF2PK(bool);
    void SelecionaPK2WIF(bool);

private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H

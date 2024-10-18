#include <QApplication>
#include <QWidget>
#include <QVBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QListWidget>
#include <QDir>
#include <QFile>
#include <QClipboard>
#include <QHBoxLayout>
#include <QDialog>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

class SifreDuzenleDialog : public QDialog {
    Q_OBJECT

public:
    SifreDuzenleDialog(const QString &site, const QString &sifre, QWidget *parent = nullptr)
    : QDialog(parent), orijinalSite(site) {
        QVBoxLayout *duzenLayout = new QVBoxLayout(this);

        QLabel *siteLabel = new QLabel("Sifre Adi:");
        duzenLayout->addWidget(siteLabel);
        siteGirisi = new QLineEdit(this);
        siteGirisi->setText(site);
        duzenLayout->addWidget(siteGirisi);

        QLabel *sifreLabel = new QLabel("Sifre:");
        duzenLayout->addWidget(sifreLabel);
        sifreGirisi = new QLineEdit(this);
        sifreGirisi->setText(sifre);
        sifreGirisi->setEchoMode(QLineEdit::Password);
        duzenLayout->addWidget(sifreGirisi);

        QPushButton *kaydetButton = new QPushButton("Kaydet", this);
        duzenLayout->addWidget(kaydetButton);

        connect(kaydetButton, &QPushButton::clicked, this, &SifreDuzenleDialog::accept);
        setLayout(duzenLayout);
    }

    QString siteAl() const { return siteGirisi->text(); }
    QString sifreAl() const { return sifreGirisi->text(); }

private:
    QLineEdit *siteGirisi;
    QLineEdit *sifreGirisi;
    QString orijinalSite;
};

class SifreYonetici : public QWidget {
    Q_OBJECT

public:
    SifreYonetici() {
        QVBoxLayout *anaLayout = new QVBoxLayout(this);

        QHBoxLayout *butonLayout = new QHBoxLayout();
        QPushButton *ekleButton = new QPushButton("Ekle", this);
        QPushButton *kopyalaButton = new QPushButton("Kopyala", this);
        QPushButton *silButton = new QPushButton("Sil", this);
        QPushButton *duzenleButton = new QPushButton("Duzenle", this);
        butonLayout->addWidget(ekleButton);
        butonLayout->addWidget(kopyalaButton);
        butonLayout->addWidget(silButton);
        butonLayout->addWidget(duzenleButton);
        anaLayout->addLayout(butonLayout);

        QLabel *siteLabel = new QLabel("Site Adi:");
        anaLayout->addWidget(siteLabel);
        siteGirisi = new QLineEdit(this);
        anaLayout->addWidget(siteGirisi);

        QLabel *sifreLabel = new QLabel("Sifre:");
        anaLayout->addWidget(sifreLabel);
        sifreGirisi = new QLineEdit(this);
        sifreGirisi->setEchoMode(QLineEdit::Password);
        anaLayout->addWidget(sifreGirisi);

        sifreListesi = new QListWidget(this);
        anaLayout->addWidget(sifreListesi);

        connect(ekleButton, &QPushButton::clicked, this, &SifreYonetici::sifreEkle);
        connect(kopyalaButton, &QPushButton::clicked, this, &SifreYonetici::sifreKopyala);
        connect(silButton, &QPushButton::clicked, this, &SifreYonetici::sifreSil);
        connect(duzenleButton, &QPushButton::clicked, this, &SifreYonetici::sifreDuzenle);

        anahtarYukleVeyaOlustur();
        sifreleriYukle();

        setLayout(anaLayout);
        setWindowTitle("Sifre Yonetici");

        QDir dizin("pass");
        if (!dizin.exists()) {
            dizin.mkpath(".");
        }
    }

private slots:
    void sifreEkle() {
        QString site = siteGirisi->text();
        QString sifre = sifreGirisi->text();
        if (!site.isEmpty() && !sifre.isEmpty()) {
            if (!sifreMevcutMu(site)) {
                QString sifrelenmisSifre = sifreSifrele(sifre);
                sifreyiKaydet(site, sifrelenmisSifre);
                siteGirisi->clear();
                sifreGirisi->clear();
                sifreleriYukle();
            }
        }
    }

    void sifreDuzenle() {
        QListWidgetItem *oge = sifreListesi->currentItem();
        if (oge) {
            QString site = oge->text().split(":").first();
            QByteArray sifrelenmisSifre = sifreyiYukle(site);
            QString cozulenSifre = sifreCoze(sifrelenmisSifre);

            SifreDuzenleDialog dialog(site, cozulenSifre, this);
            if (dialog.exec() == QDialog::Accepted) {
                QString yeniSite = dialog.siteAl();
                QString yeniSifre = dialog.sifreAl();

                if (yeniSite != site && !sifreMevcutMu(yeniSite)) {
                    QString yeniSifrelenmisSifre = sifreSifrele(yeniSifre);
                    QFile::remove("pass/" + site + ".txt");
                    sifreyiKaydet(yeniSite, yeniSifrelenmisSifre);
                    sifreleriYukle();
                } else if (yeniSite == site) {
                    QString yeniSifrelenmisSifre = sifreSifrele(yeniSifre);
                    sifreyiKaydet(site, yeniSifrelenmisSifre);
                    sifreleriYukle();
                }
            }
        }
    }

    void sifreSil() {
        QListWidgetItem *oge = sifreListesi->currentItem();
        if (oge) {
            QString site = oge->text().split(":").first();
            QFile dosya("pass/" + site + ".txt");
            if (dosya.remove()) {
                sifreListesi->takeItem(sifreListesi->row(oge));
            }
        }
    }

    void sifreKopyala() {
        QListWidgetItem *oge = sifreListesi->currentItem();
        if (oge) {
            QString site = oge->text().split(":").first();
            QByteArray sifrelenmisSifre = sifreyiYukle(site);
            QString cozulenSifre = sifreCoze(sifrelenmisSifre);
            QGuiApplication::clipboard()->setText(cozulenSifre);
        }
    }

    void sifreleriYukle() {
        sifreListesi->clear();
        QDir dizin("pass");
        QStringList dosyalar = dizin.entryList(QStringList() << "*.txt", QDir::Files);
        for (const QString &dosya : dosyalar) {
            QFile f(dizin.filePath(dosya));
            if (f.open(QIODevice::ReadOnly)) {
                QByteArray sifrelenmisSifre = f.readAll();
                QString cozulenSifre = sifreCoze(sifrelenmisSifre);
                sifreListesi->addItem(dosya.left(dosya.length() - 4) + ": " + cozulenSifre);
                f.close();
            }
        }
    }

    QByteArray sifreyiYukle(const QString &site) {
        QFile dosya("pass/" + site + ".txt");
        if (dosya.open(QIODevice::ReadOnly)) {
            return dosya.readAll();
        }
        return QByteArray();
    }

    QString sifreSifrele(const QString &sifre) {
        QByteArray anahtar = anahtarYukle();
        unsigned char iv[AES_BLOCK_SIZE] = {0};
        memcpy(iv, "abcdef9876543210", 16);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)anahtar.data(), iv);

        unsigned char sifreMetni[128];
        int len;
        EVP_EncryptUpdate(ctx, sifreMetni, &len, (unsigned char*)sifre.toUtf8().data(), sifre.length());
        int sifrelenmisUzunluk = len;
        EVP_EncryptFinal_ex(ctx, sifreMetni + len, &len);
        sifrelenmisUzunluk += len;
        EVP_CIPHER_CTX_free(ctx);

        QString hexString;
        for (int i = 0; i < sifrelenmisUzunluk; ++i) {
            hexString.append(QString::number(sifreMetni[i], 16).rightJustified(2, '0'));
        }

        return hexString;
    }

    QString sifreCoze(const QByteArray &sifrelenmisSifre) {
        QByteArray anahtar = anahtarYukle();
        unsigned char iv[AES_BLOCK_SIZE] = {0};
        memcpy(iv, "abcdef9876543210", 16);

        QByteArray veri = QByteArray::fromHex(sifrelenmisSifre);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)anahtar.data(), iv);

        unsigned char acikMetin[128];
        int len;
        EVP_DecryptUpdate(ctx, acikMetin, &len, (unsigned char*)veri.data(), veri.size());
        int acikMetinUzunluk = len;
        EVP_DecryptFinal_ex(ctx, acikMetin + len, &len);
        acikMetinUzunluk += len;
        EVP_CIPHER_CTX_free(ctx);

        return QString::fromUtf8(QByteArray((char*)acikMetin, acikMetinUzunluk));
    }

    void sifreyiKaydet(const QString &site, const QString &sifrelenmisSifre) {
        QFile dosya("pass/" + site + ".txt");
        if (dosya.open(QIODevice::WriteOnly)) {
            dosya.write(sifrelenmisSifre.toUtf8());
            dosya.close();
        }
    }

    bool sifreMevcutMu(const QString &site) {
        QFile dosya("pass/" + site + ".txt");
        return dosya.exists();
    }

    void anahtarYukleVeyaOlustur() {
        QFile anahtarDosyasi("anahtar.txt");
        if (!anahtarDosyasi.exists()) {
            QByteArray anahtar(32, 0);
            RAND_bytes((unsigned char*)anahtar.data(), anahtar.size());

            QString hexAnahtar = anahtar.toHex();
            if (anahtarDosyasi.open(QIODevice::WriteOnly)) {
                anahtarDosyasi.write(hexAnahtar.toUtf8());
                anahtarDosyasi.close();
            }
        }
    }

    QByteArray anahtarYukle() {
        QFile anahtarDosyasi("anahtar.txt");
        if (anahtarDosyasi.open(QIODevice::ReadOnly)) {
            QByteArray hexAnahtar = anahtarDosyasi.readAll();
            return QByteArray::fromHex(hexAnahtar);
        }
        return QByteArray();
    }

private:
    QLineEdit *siteGirisi;
    QLineEdit *sifreGirisi;
    QListWidget *sifreListesi;
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    SifreYonetici yonetici;
    yonetici.resize(400, 300);
    yonetici.show();
    return app.exec();
}

#include "main.moc"

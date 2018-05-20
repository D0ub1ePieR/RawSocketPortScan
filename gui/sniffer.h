#ifndef SNIFFER_H
#define SNIFFER_H

#include <QDialog>

namespace Ui {
class sniffer;
}

class sniffer : public QDialog
{
    Q_OBJECT

public:
    explicit sniffer(QWidget *parent = 0);
    ~sniffer();
signals:
    void sendMessage(QString msg);

private slots:
    void on_pushButton_clicked();

    void on_auto_get_clicked();

    void on_set_clicked();
    void procedure(char *interface, int fd);

    void on_start_clicked();
    void tcp_viewer();

private:
    Ui::sniffer *ui;
};

#endif // SNIFFER_H

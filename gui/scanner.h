#ifndef SCANNER_H
#define SCANNER_H

#include <QDialog>

namespace Ui {
class Scanner;
}

class Scanner : public QDialog
{
    Q_OBJECT

public:
    explicit Scanner(QWidget *parent = 0);
    ~Scanner();

private slots:
    void on_pushButton_clicked();

    void on_getip_clicked();

    void on_pushButton_2_clicked();
    int ping_target_by_send_icmp(char *dst_ip);

    void on_checkip_clicked();


private:
    Ui::Scanner *ui;
};

#endif // scanner_H

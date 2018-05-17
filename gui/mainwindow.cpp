#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "scanner.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_scanner_button_clicked()
{
    close();
    Scanner s;
    if (s.exec()==QDialog::Accepted)
        show();
}

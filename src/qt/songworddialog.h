// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MOONWORDDIALOG_H
#define BITCOIN_QT_MOONWORDDIALOG_H

#include <qt/walletmodel.h>

#include <QDialog>
#include <QMessageBox>
#include <QString>
#include <QTimer>

class ClientModel;
class OptionsModel;
class PlatformStyle;
class SendCoinsRecipient;

namespace Ui {
    class SongWordDialog;
}

struct SongWordFrom {
    QString address;
    CAmount amount;
    uint256 txhash;
    uint32_t out;
};

QT_BEGIN_NAMESPACE
class QUrl;
QT_END_NAMESPACE

/** Dialog for sending bitcoins */
class SongWordDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SongWordDialog(const PlatformStyle *platformStyle, WalletModel *model);
    ~SongWordDialog();

    /** Set up the tab chain manually, as Qt messes up the tab chain by default in some cases (issue https://bugreports.qt-project.org/browse/QTBUG-10907).
     */
    QWidget *setupTabChain(QWidget *prev);

public Q_SLOTS:
    void clear();
    void reject();
    void accept();
    void updateTabsAndLabels();

    /* New transaction, or transaction changed status */
    void updateTransaction();

private:
    Ui::SongWordDialog *ui;
    WalletModel *model;
    std::unique_ptr<interfaces::Handler> m_handler_transaction_changed;
    bool fNewRecipientAllowed;
    const PlatformStyle *platformStyle;

    // Core signal will notify us of new TX to refresh the drop down lists
    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

    // Map of songword int to char http://songcoin.com/songword/songword.html
    std::map<int, char> songwordMap;

    // Holds all addresses used to send messages from
    std::multimap<int, SongWordFrom> fromAddressesMap;

    // Map of coin amounts calculated from the message to send
    std::vector<CAmount> songwords;

    // Set of outputs from the selected from address
    std::multimap<CAmount, COutPoint> fromOutputs;

    // Process WalletModel::SendCoinsReturn and generate a pair consisting
    // of a message and message flags for use in Q_EMIT message().
    // Additional parameter msgArg can be used via .arg(msgArg).
    void processSendCoinsReturn(const WalletModel::SendCoinsReturn &sendCoinsReturn, const QString &msgArg = QString());

    // Populate Songword drop downs
    void populateFromAddresses();
    void populateReceivedAddresses();
    void populateSentAddresses();

    // Songword lookups by char or int
    const int& songCharLookup(const char& c);
    const char& songCharLookup(const int& i);

    // Calculate bytes and fee for labels
    void getTransactionDetails(unsigned int& nBytes, CAmount& nPayFee);

    // Update list of Songword CAmounts outputs, return truncated string if message too long
    void updateSongwordOutputs(std::string &str, CAmount &total_amount);

    // Update inputs required to pay for message
    void updateSongwordInputs(unsigned int &tx_bytes, CAmount &tx_fee, CAmount &total_amount);

private Q_SLOTS:
    void deleteClicked();
    void on_addressBookButton_clicked();
    void on_sendButton_clicked();
    void on_pasteButton_clicked();
    void on_btn_generate_clicked();
    void on_btn_generate_sent_clicked();
    void generateTextReport(std::ofstream &textFile, std::string &addressStr, std::map<uint256, CWalletTx> &transactions);

    // Drop down of from addresses selected
    void selectFromAddress(int selection);

    // Change to the message to be sent via songwords
    void textChanged();

Q_SIGNALS:
    // Fired when a message should be reported to the user
    void message(const QString &title, const QString &message, unsigned int style);
};

class SendSongWordConfirmationDialog : public QMessageBox
{
    Q_OBJECT

public:
    SendSongWordConfirmationDialog(const QString &title, const QString &text, int secDelay = 0, QWidget *parent = nullptr);
    int exec();

    private Q_SLOTS:
    void countDown();
    void updateYesButton();
    
private:
    QAbstractButton * yesButton;
    QTimer countDownTimer;
    int secDelay;
};

#endif // BITCOIN_QT_MOONWORDDIALOG_H

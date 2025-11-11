// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/songworddialog.h>
#include <qt/forms/ui_songworddialog.h>

#include <qt/addressbookpage.h>
#include <qt/bitcoinunits.h>
#include <qt/coincontroldialog.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>

#include <consensus/consensus.h>
#include <interfaces/handler.h>
#include <interfaces/node.h>
#include <key_io.h>
#include <policy/policy.h>
#include <validation.h> // GetTransaction() and maxTxFee
#include <wallet/coincontrol.h>

#include <cctype> // isspace
#include <fstream>
#include <iostream>

#include <QApplication>
#include <QClipboard>
#include <QMessageBox>
#include <QScrollBar>
#include <QSettings>
#include <QTextDocument>
#include <QTimer>

#define SEND_CONFIRM_DELAY   3

namespace  {
std::string allowedChars()
{
    return " 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=*^%<>#-=.,:!?/_@()";
}

void populateSongwordMap(std::map<int, char>& songwordMap)
{
    songwordMap.emplace(0, ' ');
    songwordMap.emplace(10, '0');
    songwordMap.emplace(11, '1');
    songwordMap.emplace(12, '2');
    songwordMap.emplace(13, '3');
    songwordMap.emplace(14, '4');
    songwordMap.emplace(15, '5');
    songwordMap.emplace(16, '6');
    songwordMap.emplace(17, '7');
    songwordMap.emplace(18, '8');
    songwordMap.emplace(19, '9');
    songwordMap.emplace(20, 'A');
    songwordMap.emplace(21, 'B');
    songwordMap.emplace(22, 'C');
    songwordMap.emplace(23, 'D');
    songwordMap.emplace(24, 'E');
    songwordMap.emplace(25, 'F');
    songwordMap.emplace(26, 'G');
    songwordMap.emplace(27, 'H');
    songwordMap.emplace(28, 'I');
    songwordMap.emplace(29, 'J');
    songwordMap.emplace(30, 'K');
    songwordMap.emplace(31, 'L');
    songwordMap.emplace(32, 'M');
    songwordMap.emplace(33, 'N');
    songwordMap.emplace(34, 'O');
    songwordMap.emplace(35, 'P');
    songwordMap.emplace(36, 'Q');
    songwordMap.emplace(37, 'R');
    songwordMap.emplace(38, 'S');
    songwordMap.emplace(39, 'T');
    songwordMap.emplace(40, 'U');
    songwordMap.emplace(41, 'V');
    songwordMap.emplace(42, 'W');
    songwordMap.emplace(43, 'X');
    songwordMap.emplace(44, 'Y');
    songwordMap.emplace(45, 'Z');
    songwordMap.emplace(46, 'a');
    songwordMap.emplace(47, 'b');
    songwordMap.emplace(48, 'c');
    songwordMap.emplace(49, 'd');
    songwordMap.emplace(50, 'e');
    songwordMap.emplace(51, 'f');
    songwordMap.emplace(52, 'g');
    songwordMap.emplace(53, 'h');
    songwordMap.emplace(54, 'i');
    songwordMap.emplace(55, 'j');
    songwordMap.emplace(56, 'k');
    songwordMap.emplace(57, 'l');
    songwordMap.emplace(58, 'm');
    songwordMap.emplace(59, 'n');
    songwordMap.emplace(60, 'o');
    songwordMap.emplace(61, 'p');
    songwordMap.emplace(62, 'q');
    songwordMap.emplace(63, 'r');
    songwordMap.emplace(64, 's');
    songwordMap.emplace(65, 't');
    songwordMap.emplace(66, 'u');
    songwordMap.emplace(67, 'v');
    songwordMap.emplace(68, 'w');
    songwordMap.emplace(69, 'x');
    songwordMap.emplace(70, 'y');
    songwordMap.emplace(71, 'z');
    songwordMap.emplace(72, '=');
    songwordMap.emplace(73, '*');
    songwordMap.emplace(74, '^');
    songwordMap.emplace(75, '%');
    songwordMap.emplace(76, '<');
    songwordMap.emplace(77, '>');
    songwordMap.emplace(78, '#');
    songwordMap.emplace(79, '-');
    songwordMap.emplace(80, '+');
    songwordMap.emplace(81, '.');
    songwordMap.emplace(82, ',');
    songwordMap.emplace(83, ':');
    songwordMap.emplace(84, '!');
    songwordMap.emplace(85, '?');
    songwordMap.emplace(86, '/');
    songwordMap.emplace(87, '_');
    songwordMap.emplace(88, '@');
    songwordMap.emplace(89, '(');
    songwordMap.emplace(90, ')');
}

} // namespace

SongWordDialog::SongWordDialog(const PlatformStyle *platformStyle, WalletModel *model) :
    ui(new Ui::SongWordDialog),
    model(model),
    fNewRecipientAllowed(true),
    platformStyle(platformStyle)
{
    ui->setupUi(this);

    ui->addressBookButton->setIcon(platformStyle->SingleColorIcon(":/icons/address-book"));
    ui->pasteButton->setIcon(platformStyle->SingleColorIcon(":/icons/editpaste"));
    ui->deleteButton->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));

    if (!platformStyle->getImagesOnButtons()) {
        ui->labelsuffFunds->setVisible(false);
        ui->clearButton->setIcon(QIcon());
        ui->sendButton->setIcon(QIcon());
    } else {
        ui->clearButton->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));
        ui->sendButton->setIcon(platformStyle->SingleColorIcon(":/icons/send"));
        ui->labelsuffFunds->setVisible(false);
    }

    connect(ui->deleteButton, SIGNAL(clicked()), this, SLOT(deleteClicked()));
    connect(ui->clearButton, SIGNAL(clicked()), this, SLOT(clear()));

    populateSongwordMap(songwordMap);
    connect(ui->textEdit_message, SIGNAL(textChanged()), this, SLOT(textChanged()));

    if(model && model->getOptionsModel())
    {
        // songward dropdowns
        populateFromAddresses();
        populateReceivedAddresses();
        populateSentAddresses();
        connect(ui->cB_from, SIGNAL(currentIndexChanged(int)), this, SLOT(selectFromAddress(int)));

        subscribeToCoreSignals();
    }
}

SongWordDialog::~SongWordDialog()
{
    unsubscribeFromCoreSignals();

    delete ui;
}

void SongWordDialog::on_pasteButton_clicked()
{
    // Paste text from clipboard into recipient field
    ui->payTo->setText(QApplication::clipboard()->text());
}

void SongWordDialog::on_addressBookButton_clicked()
{
    if(!model)
        return;
    AddressBookPage dlg(platformStyle, AddressBookPage::ForSelection, AddressBookPage::SendingTab, this);
    dlg.setModel(model->getAddressTableModel());
    if(dlg.exec())
    {
        ui->payTo->setText(dlg.getReturnValue());
    }
}

void SongWordDialog::on_sendButton_clicked()
{
    if(!model || !model->getOptionsModel())
        return;

    QList<SendCoinsRecipient> recipients;
    bool valid = true;

    // Validate address in to field
    if (!model->validateAddress(ui->payTo->text()))
    {
        ui->payTo->setValid(false);
        valid = false;
    }

    // Check that there's a message to send
    if (ui->textEdit_message->document()->toPlainText().toStdString() == "" || songwords.empty())
    {
        valid = false;
    }

    // Check that the from address is not on the first empty entry (0) or has no items (-1)
    if (ui->cB_from->currentIndex() <= 0)
    {
        valid = false;
    }

    QString address = ui->payTo->text();

    for (const auto& amount : songwords)
    {
        SendCoinsRecipient recipient;
        recipient.address = address;
        recipient.amount = amount;
        recipients.append(recipient);
    }

    if(!valid || recipients.isEmpty())
    {
        return;
    }

    fNewRecipientAllowed = false;
    WalletModel::UnlockContext ctx(model->requestUnlock());
    if(!ctx.isValid())
    {
        // Unlock wallet was cancelled
        fNewRecipientAllowed = true;
        return;
    }

    // prepare transaction for getting txFee earlier
    WalletModelTransaction currentTransaction(recipients);
    WalletModel::SendCoinsReturn prepareStatus;
    prepareStatus = model->prepareTransaction(currentTransaction, *CoinControlDialog::coinControl(), true);

    // process prepareStatus and on error generate message shown to user
    processSendCoinsReturn(prepareStatus,
        BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), currentTransaction.getTransactionFee()));

    if(prepareStatus.status != WalletModel::OK) {
        fNewRecipientAllowed = true;
        return;
    }

    CAmount txFee = currentTransaction.getTransactionFee();

    QString questionString = tr("Are you sure you want to send?");

    if(txFee > 0)
    {
        // append fee string if a fee is required
        questionString.append("<hr /><span style='color:#aa0000;'>");
        questionString.append(BitcoinUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), txFee));
        questionString.append("</span> ");
        questionString.append(tr("added as transaction fee"));

        // append transaction size
        questionString.append(" (" + QString::number((double)currentTransaction.getTransactionSize() / 1000) + " kB)");
    }

    // add total amount in all subdivision units
    questionString.append("<hr />");
    CAmount totalAmount = currentTransaction.getTotalTransactionAmount() + txFee;
    QStringList alternativeUnits;
    Q_FOREACH(BitcoinUnits::Unit u, BitcoinUnits::availableUnits())
    {
        if(u != model->getOptionsModel()->getDisplayUnit())
            alternativeUnits.append(BitcoinUnits::formatHtmlWithUnit(u, totalAmount));
    }
    questionString.append(tr("Total Amount %1")
        .arg(BitcoinUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), totalAmount)));
    questionString.append(QString("<span style='font-size:10pt;font-weight:normal;'><br />(=%2)</span>")
        .arg(alternativeUnits.join(" " + tr("or") + "<br />")));

    SendSongWordConfirmationDialog confirmationDialog(tr("Confirm send coins"),
        questionString, SEND_CONFIRM_DELAY, this);
    confirmationDialog.exec();
    QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();

    if(retval != QMessageBox::Yes)
    {
        fNewRecipientAllowed = true;
        return;
    }

    // now send the prepared transaction
    WalletModel::SendCoinsReturn sendStatus = model->sendCoins(currentTransaction);
    // process sendStatus and on error generate message shown to user
    processSendCoinsReturn(sendStatus);

    if (sendStatus.status == WalletModel::OK)
    {
        accept();
    }
    fNewRecipientAllowed = true;
}

void SongWordDialog::deleteClicked()
{
    ui->payTo->clear();
}

void SongWordDialog::clear()
{
    ui->textEdit_message->clear();
    deleteClicked();
    songwords.clear();
    CoinControlDialog::coinControl()->UnSelectAll();
    ui->cB_from->setCurrentIndex(0);
    fromOutputs.clear();
    ui->cB_recipient->setCurrentIndex(0);
    ui->cB_sent->setCurrentIndex(0);
    updateTabsAndLabels();
}

void SongWordDialog::reject()
{
    clear();
}

void SongWordDialog::accept()
{
    clear();
}


void SongWordDialog::updateTabsAndLabels()
{
    setupTabChain(nullptr);
}

QWidget *SongWordDialog::setupTabChain(QWidget *prev)
{
    QWidget::setTabOrder(prev, ui->cB_from);
    QWidget::setTabOrder(ui->cB_from, ui->payTo);
    QWidget::setTabOrder(ui->payTo, ui->addressBookButton);
    QWidget::setTabOrder(ui->addressBookButton, ui->pasteButton);
    QWidget::setTabOrder(ui->pasteButton, ui->deleteButton);
    QWidget::setTabOrder(ui->deleteButton, ui->sendButton);
    QWidget::setTabOrder(ui->sendButton, ui->clearButton);
    QWidget::setTabOrder(ui->clearButton, ui->cB_recipient);
    QWidget::setTabOrder(ui->cB_recipient, ui->btn_generate);
    QWidget::setTabOrder(ui->btn_generate, ui->cB_sent);
    QWidget::setTabOrder(ui->cB_sent, ui->btn_generate_sent);
    return ui->btn_generate;
}

void SongWordDialog::processSendCoinsReturn(const WalletModel::SendCoinsReturn &sendCoinsReturn, const QString &msgArg)
{
    QPair<QString, CClientUIInterface::MessageBoxFlags> msgParams;
    // Default to a warning message, override if error message is needed
    msgParams.second = CClientUIInterface::MSG_WARNING;

    // This comment is specific to SongWordDialog usage of WalletModel::SendCoinsReturn.
    // WalletModel::TransactionCommitFailed is used only in WalletModel::sendCoins()
    // all others are used only in WalletModel::prepareTransaction()
    switch(sendCoinsReturn.status)
    {
    case WalletModel::InvalidAddress:
        msgParams.first = tr("The recipient address is not valid. Please recheck.");
        break;
    case WalletModel::InvalidAmount:
        msgParams.first = tr("Transaction has an output of 0 coins. Remove multiple spaces and remove unsupported chars as these translate to 00 in Songword code.");
        break;
    case WalletModel::AmountExceedsBalance:
        msgParams.first = tr("From address balance too low to send this message.");
        break;
    case WalletModel::AmountWithFeeExceedsBalance:
        msgParams.first = tr("The total exceeds your balance when the %1 transaction fee is included.").arg(msgArg);
        break;
    case WalletModel::DuplicateAddress:
        msgParams.first = tr("Duplicate address found: addresses should only be used once each.");
        break;
    case WalletModel::TransactionCreationFailed:
        msgParams.first = tr("Transaction creation failed!");
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    case WalletModel::TransactionCommitFailed:
        msgParams.first = tr("The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    case WalletModel::AbsurdFee:
        msgParams.first = tr("A fee higher than %1 is considered an absurdly high fee.").arg(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), maxTxFee));
        break;
    case WalletModel::PaymentRequestExpired:
        msgParams.first = tr("Payment request expired.");
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    // included to prevent a compiler warning.
    case WalletModel::OK:
    default:
        return;
    }

    Q_EMIT message(tr("Send Coins"), msgParams.first, msgParams.second);
}

void SongWordDialog::getTransactionDetails(unsigned int& nBytes, CAmount& nPayFee)
{
    if (!model)
        return;

    // nPayAmount
    CAmount nPayAmount = 0;
    bool fDust = false;
    CMutableTransaction txDummy;

    CoinControlDialog::payAmounts.clear();
    for (const auto& amount : songwords)
    {
        CoinControlDialog::payAmounts.append(amount);
    }

    for (const CAmount &amount : CoinControlDialog::payAmounts)
    {
        nPayAmount += amount;

        if (amount > 0)
        {
            CTxOut txout(amount, static_cast<CScript>(std::vector<unsigned char>(24, 0)));
            txDummy.vout.push_back(txout);
            fDust |= IsDust(txout, model->node().getDustRelayFee());
        }
    }

    CAmount nAmount = 0;
    CAmount nChange = 0;
    unsigned int nBytesInputs = 0;
    unsigned int nQuantity = 0;
    bool fWitness = false;


    std::vector<COutPoint> vCoinControl;
    std::vector<COutput>   vOutputs;
    CoinControlDialog::coinControl()->ListSelected(vCoinControl);

    size_t i = 0;
    for (const auto& out : model->wallet().getCoins(vCoinControl)) {
        if (out.depth_in_main_chain < 0) continue;

        // unselect already spent, very unlikely scenario, this could happen
        // when selected are spent elsewhere, like rpc or another computer
        const COutPoint& outpt = vCoinControl[i++];
        if (out.is_spent)
        {
            CoinControlDialog::coinControl()->UnSelect(outpt);
            continue;
        }

        // Quantity
        nQuantity++;

        // Amount
        nAmount += out.txout.nValue;

        // Bytes
        CTxDestination address;
        int witnessversion = 0;
        std::vector<unsigned char> witnessprogram;
        if (out.txout.scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram))
        {
            nBytesInputs += (32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4);
            fWitness = true;
        }
        else if(ExtractDestination(out.txout.scriptPubKey, address))
        {
            CPubKey pubkey;
            CKeyID *keyid = boost::get<CKeyID>(&address);
            if (keyid && model->wallet().getPubKey(*keyid, pubkey))
            {
                nBytesInputs += (pubkey.IsCompressed() ? 148 : 180);
            }
            else
                nBytesInputs += 148; // in all error cases, simply assume 148 here
        }
        else nBytesInputs += 148;
    }

    // Bytes
    nBytes = nBytesInputs + ((CoinControlDialog::payAmounts.size() > 0 ? CoinControlDialog::payAmounts.size() + 1 : 2) * 34) + 10; // always assume +1 output for change here
    if (fWitness)
    {
        // there is some fudging in these numbers related to the actual virtual transaction size calculation that will keep this estimate from being exact.
        // usually, the result will be an overestimate within a couple of satoshis so that the confirmation dialog ends up displaying a slightly smaller fee.
        // also, the witness stack size value value is a variable sized integer. usually, the number of stack items will be well under the single byte var int limit.
        nBytes += 2; // account for the serialized marker and flag bytes
        nBytes += nQuantity; // account for the witness byte that holds the number of stack items for each input.
    }

    // Fee
    nPayFee = model->wallet().getMinimumFee(nBytes, *CoinControlDialog::coinControl(), nullptr /* returned_target */, nullptr /* reason */);

    if (nPayAmount > 0)
    {
        nChange = nAmount - nPayAmount;
        nChange -= nPayFee;

        // Never create dust outputs; if we would, just add the dust to the fee.
        if (nChange > 0 && nChange < MIN_CHANGE)
        {
            CTxOut txout(nChange, static_cast<CScript>(std::vector<unsigned char>(24, 0)));
            if (IsDust(txout, model->node().getDustRelayFee()))
            {
                nPayFee += nChange;
                nChange = 0;
            }
        }

        if (nChange == 0)
            nBytes -= 34;
    }
}

void SongWordDialog::textChanged()
{
    std::string str = ui->textEdit_message->toPlainText().toStdString();
    std::string original_str = str;

    int nDisplayUnit = model->getOptionsModel()->getDisplayUnit();

    // Get labels
    QLabel *tx_count = findChild<QLabel *>("labelTransactionCount");
    QLabel *amount = findChild<QLabel *>("labelAmount");
    QLabel *fee = findChild<QLabel *>("labelFee");
    QLabel *bytes = findChild<QLabel *>("labelBytes");

    if (str.empty())
    {
        // Reset labels
        tx_count->setText("0");
        amount->setText(BitcoinUnits::formatWithUnit(nDisplayUnit, 0));
        fee->setText(BitcoinUnits::formatWithUnit(nDisplayUnit, 0));
        bytes->setText("0");

        return;
    }

    // Variables for totals and labels
    CAmount total_amount{0};
    unsigned int tx_bytes = 0;
    CAmount tx_fee = 0;

    // Total TX too large, pop top chars until under 100KB limit
    do
    {
        // Update songwords CAmounts outputs
        updateSongwordOutputs(str, total_amount);

        // Update inputs required used and tx_bytes
        updateSongwordInputs(tx_bytes, tx_fee, total_amount);

        if (tx_bytes > 100000)
        {
            // Remove last Songword from message text
            str = str.substr(0, (str.length() / 4) * 4 - 1);
        }
    }
    while (tx_bytes > 100000);

    // Text string has been changed, update text and exit. textChanged() will be called by the text update here.
    if (str != original_str)
    {
        QTextCursor cursor = ui->textEdit_message->textCursor();
        int cursor_pos = cursor.position();

        ui->textEdit_message->setPlainText(QString::fromStdString(str));

        cursor.setPosition(cursor_pos - (original_str.size() - str.size()));
        ui->textEdit_message->setTextCursor(cursor);

        return;
    }

    tx_count->setText("1"); // Only ever 1 or 0 at the moment
    amount->setText(BitcoinUnits::formatWithUnit(nDisplayUnit, total_amount));
    fee->setText(BitcoinUnits::formatWithUnit(nDisplayUnit, tx_fee));
    bytes->setText(tx_bytes > 0 ? QString::number(tx_bytes) : "0");
}

void SongWordDialog::updateSongwordInputs(unsigned int &tx_bytes, CAmount &tx_fee, CAmount &total_amount)
{
    CAmount selected = 0;
    std::set<COutPoint>::size_type numSelected = 0;
    getTransactionDetails(tx_bytes, tx_fee);
    CoinControlDialog::coinControl()->UnSelectAll();

    // Outside loop double checks selected against total as fee may have changed since inner loop check
    while(selected < total_amount + tx_fee && numSelected < fromOutputs.size())
    {
        for (const auto& outputs : fromOutputs)
        {
            if (selected < total_amount + tx_fee)
            {
                CoinControlDialog::coinControl()->Select(outputs.second);
                selected += outputs.first;
                ++numSelected;
                getTransactionDetails(tx_bytes, tx_fee);
            }
            else
            {
                break;
            }
        }
    }
}

void SongWordDialog::updateSongwordOutputs(std::string &str, CAmount &total_amount)
{
    songwords.clear();
    unsigned int nBytes{0};
    CAmount nPayFee{0};

    std::string::const_iterator it = str.cbegin();

    // Number of songwords required to send message
    std::string::size_type songwordsRequired = (str.size() / 4) + (str.size() % 4 ? 1 : 0);

    // Iterate for as many words as are required
    for (std::string::size_type i = 0; i < songwordsRequired; ++i)
    {
        std::string amountStr;

        // Work through four chars a time or until the end of message
        for (int j = 0; j < 4 && it != str.end();)
        {
            // Check that char is allowed
            bool illegal_char = (allowedChars().find(*it) == std::string::npos);

            // Check for double space. Check current pos first.
            if (isspace(*it))
            {
                // Compare against previous char
                if (it != str.begin() && isspace(*(std::prev(it))))
                {
                    illegal_char = true;
                }
                // Compare against next char
                if (std::next(it) != str.end() && isspace(*(std::next(it))))
                {
                    illegal_char = true;
                }
            }

            if (illegal_char)
            {
                // Delete char from our copy and update iterator
                it = str.erase(it);

                // Total number of required songwords may now be different
                songwordsRequired = str.size() / 4 + (str.size() % 4 ? 1 : 0);

                continue;
            }

            std::string songcharStr = std::to_string(songCharLookup(*it));

            // Single char so prefix with '0'
            if (songcharStr.size() == 1)
            {
                songcharStr.insert(0, "0");
            }

            amountStr.append(songcharStr);
            ++it;
            ++j;
        }

        std::string::size_type chars_added = amountStr.size();

        // If the amount is less than 8 chars fill with 0s
        amountStr.append(8 - amountStr.size(), '0');

        try{
            CAmount amount = std::stoll(amountStr);
            total_amount += amount;

            // amount could be zero if new word is a single space, in which case skip it.
            if (amount > 0)
            {
                songwords.push_back(std::stoll(amountStr));
            }
        }
        catch (const std::invalid_argument&) {} // Invalid arg supplied to stoll
        catch (const std::out_of_range&) {} // Range outside of long long

        getTransactionDetails(nBytes, nPayFee);

        // Oversized and inputs have not been added yet, break here.
        if (nBytes > 100000)
        {
            songwords.pop_back();
            str = std::string(str.cbegin(), it - (chars_added / 2));
            break;
        }
    }
}

void SongWordDialog::on_btn_generate_clicked()
{
    int selection = ui->cB_recipient->currentIndex();

    if (selection == 0)
    {
        return;
    }

    QString filename = GUIUtil::getSaveFileName(this, tr("Generate Songword Report"), QString(), tr("Text file (*.txt)"), nullptr);

    if (filename.isEmpty())
        return;

    const std::string& strDest = filename.toLocal8Bit().data();

    std::ofstream textFile;
    textFile.exceptions(std::ofstream::failbit);

    try
    {
        textFile.open(strDest);

        std::string addressStr = ui->cB_recipient->currentText().toStdString();
        std::map<uint256, CWalletTx> transactions = model->wallet().listSongwordReceviedTransactions();

        generateTextReport(textFile, addressStr, transactions);

        Q_EMIT message(tr("Report Generated Successful"), tr("The report successfully generated to %1.").arg(filename), CClientUIInterface::MSG_INFORMATION);
    }
    catch (std::ofstream::failure& e)
    {
        Q_EMIT message(tr("Report Generation Failed"), tr("There was an error trying to generate the report to %1.").arg(filename), CClientUIInterface::MSG_ERROR);
    }
}


void SongWordDialog::on_btn_generate_sent_clicked()
{
    int selection = ui->cB_sent->currentIndex();

    if (selection == 0)
    {
        return;
    }

    QString filename = GUIUtil::getSaveFileName(this, tr("Generate Songword Report"), QString(), tr("Text file (*.txt)"), nullptr);

    if (filename.isEmpty())
        return;

    const std::string& strDest = filename.toLocal8Bit().data();

    std::ofstream textFile;
    textFile.exceptions(std::ofstream::failbit);

    try
    {
        textFile.open(strDest);

        std::string addressStr = ui->cB_sent->currentText().toStdString();
        std::map<uint256, CWalletTx> transactions = model->wallet().listSongwordSentTransactions();

        generateTextReport(textFile, addressStr, transactions);

        Q_EMIT message(tr("Report Generated Successful"), tr("The report successfully generated to %1.").arg(filename), CClientUIInterface::MSG_INFORMATION);
    }
    catch (std::ofstream::failure& e)
    {
        Q_EMIT message(tr("Report Generation Failed"), tr("There was an error trying to generate the report to %1.").arg(filename), CClientUIInterface::MSG_ERROR);
    }
}

void SongWordDialog::generateTextReport(std::ofstream &textFile, std::string &addressStr, std::map<uint256, CWalletTx> &transactions)
{
    for(const auto& tx_pair : transactions)
    {
        const CWalletTx &wtx = tx_pair.second;
        bool print_info = false;
        std::string message;

        for (const auto& txout : wtx.tx->vout)
        {
            CTxDestination address;
            ExtractDestination(txout.scriptPubKey, address);
            const CAmount& value = txout.nValue;

            if (addressStr == EncodeDestination(address) && value < 100000000)
            {
                if (!print_info)
                {
                    print_info = true;
                    textFile << "Transaction hash: " << wtx.GetHash().ToString() << std::endl;

                    CTransactionRef tx;
                    uint256 hashBlock;

                     // Requires txindex if not in mempool
                    if (GetTransaction(wtx.tx->vin[0].prevout.hash, tx, Params().GetConsensus(), hashBlock))
                    {
                        CTxDestination fromAddress;
                        ExtractDestination(tx->vout[wtx.tx->vin[0].prevout.n].scriptPubKey, fromAddress);
                        textFile << "From: " << EncodeDestination(fromAddress) << std::endl;
                    }
                    textFile << "To: " << EncodeDestination(address) << std::endl;
                    textFile << "Time: " << GUIUtil::dateTimeStr(wtx.GetTxTime()).toStdString() << std::endl;
                }

                std::string valueStr = std::to_string(value);

                // If the amount is less than 8 chars fill with 0s
                valueStr.insert(0, 8 - valueStr.size(), '0');

                std::string subStr;
                for (std::string::size_type i = 0; i < valueStr.size(); ++i)
                {
                    subStr += valueStr[i];

                    if (i % 2)
                    {
                        textFile << songCharLookup(std::stoi(subStr));
                        subStr = "";
                    }
                }
            }
        }

        if (print_info)
        {
            textFile << std::endl;
            print_info = false;
        }
    }
}

void SongWordDialog::selectFromAddress(int selection)
{
    fromOutputs.clear();

    if (selection > 0)
    {
        std::pair <std::multimap<int, SongWordFrom>::iterator, std::multimap<int, SongWordFrom>::iterator> ret;
        ret = fromAddressesMap.equal_range(selection);

        // Iterate over outputs that can be used from the from address multimap and add to output set
        for (std::multimap<int, SongWordFrom>::iterator it = ret.first; it!=ret.second; ++it)
        {
            fromOutputs.emplace(it->second.amount, COutPoint(it->second.txhash, it->second.out));
        }
    }

    // Recalculate inputs and byte size/fee
    textChanged();
}

void SongWordDialog::populateReceivedAddresses()
{
    // Clear drop down list
    ui->cB_recipient->clear();

    // First drop down blank, should default to this if wallet addresses update
    ui->cB_recipient->addItem("Received");

    std::set<std::string> addresses;
    std::map<uint256, CWalletTx> transactions = model->wallet().listSongwordReceviedTransactions();

    for(const auto& tx_pair : transactions)
    {
        const CWalletTx &wtx = tx_pair.second;
        for (const auto& txout : wtx.tx->vout)
        {
            CTxDestination address;

            if (txout.nValue < 100000000 && // Less than 1 coin, Songword
                    ExtractDestination(txout.scriptPubKey, address) &&
                    model->wallet().isMine(address) && // Output belongs to our wallet
                    !model->wallet().isChange(txout)) // Output is not change
            {
                addresses.insert(EncodeDestination(address));
            }
        }
    }

    for (const auto& addr : addresses)
    {
        ui->cB_recipient->addItem(QString::fromStdString(addr));
    }
}

void SongWordDialog::populateSentAddresses()
{
    // Clear drop down list
    ui->cB_sent->clear();

    // First drop down blank, should default to this if wallet addresses update
    ui->cB_sent->addItem("Sent");

    std::set<std::string> addresses;
    std::map<uint256, CWalletTx> transactions = model->wallet().listSongwordSentTransactions();

    for(const auto& tx_pair : transactions)
    {
        const CWalletTx &wtx = tx_pair.second;
        for (const auto& txout : wtx.tx->vout)
        {
            CTxDestination address;

            if (txout.nValue < 100000000 && // Less than 1 coin, Songword
                    ExtractDestination(txout.scriptPubKey, address) &&
                    !model->wallet().isChange(txout)) // Output is not change
            {
                addresses.insert(EncodeDestination(address));
            }
        }
    }

    for (const auto& addr : addresses)
    {
        ui->cB_sent->addItem(QString::fromStdString(addr));
    }
}

void SongWordDialog::populateFromAddresses()
{
    // Clear drop down list
    ui->cB_from->clear();

    // First drop down blank, should default to this if wallet addresses update
    ui->cB_from->addItem("");

    if (!model || !model->getOptionsModel())
        return;

    fromOutputs.clear();
    fromAddressesMap.clear();

    // Holds whether the address is seen and what position it will have in the fromAddressMap and drop down
    std::map<QString, int> mapPosition;
    int position = 1;

    for (const auto& coins : model->wallet().listCoins())
    {
        for (const auto& outpair : coins.second)
        {
            const COutPoint& output = std::get<0>(outpair);
            const interfaces::WalletTxOut& out = std::get<1>(outpair);
            if (model->wallet().isLockedCoin(output))
                continue;

            CTxDestination outputAddress;
            QString sAddress = "";
            if(ExtractDestination(out.txout.scriptPubKey, outputAddress))
            {
                sAddress = QString::fromStdString(EncodeDestination(outputAddress));
            }

            // Try and add address to mapPosition to see if it is already present in fromAddressesMap
            auto result = mapPosition.emplace(sAddress, position);

            // Added new entry in mapPosition so create a new entry in fromAddressesMap using position
            if (result.second)
            {
                fromAddressesMap.insert(std::pair<int, SongWordFrom>(position, {sAddress, out.txout.nValue, output.hash, output.n}));
                ++position;
            }
            else // Already present so use the position of the previous entry
            {
                fromAddressesMap.insert(std::pair<int, SongWordFrom>(result.first->second, {sAddress, out.txout.nValue, output.hash, output.n}));
            }
        }
    }

    int nDisplayUnit = model->getOptionsModel()->getDisplayUnit();

    for (int i = 1; i <= mapPosition.size(); ++i)
    {
        QString address;
        CAmount sum = 0;
        std::pair <std::multimap<int, SongWordFrom>::const_iterator, std::multimap<int, SongWordFrom>::const_iterator> ret;
        ret = fromAddressesMap.equal_range(i);
        for (std::multimap<int, SongWordFrom>::const_iterator it = ret.first; it != ret.second; ++it)
        {
            sum += it->second.amount;
        }
        ui->cB_from->addItem(ret.first->second.address + " (" + BitcoinUnits::format(nDisplayUnit, sum) + ")");
    }

    // Recalculate inputs and byte size/fee
    textChanged();
}

const int& SongWordDialog::songCharLookup(const char& c)
{
    for (const auto& pair : songwordMap)
    {
        if (pair.second == c)
        {
            return pair.first;
        }
    }

    // If char is not found return the int that pairs with the space char,
    // reserved or unknown values will become spaces.
    return songwordMap.cbegin()->first;
}

const char& SongWordDialog::songCharLookup(const int& i)
{
    try
    {
        return songwordMap.at(i);
    }
    catch (const std::out_of_range&)
    {

        // If there's no value at i return the space char at 0,
        // reserved or unknown values will become spaces. Subscript
        // operator does not throw.
        return songwordMap[0];
    }
}

void SongWordDialog::updateTransaction()
{
    populateReceivedAddresses();
    populateSentAddresses();
    populateFromAddresses();
}

static void NotifyTransactionChanged(SongWordDialog *mwd, const uint256 &hash, ChangeType status)
{
    Q_UNUSED(hash);
    Q_UNUSED(status);
    QMetaObject::invokeMethod(mwd, "updateTransaction", Qt::QueuedConnection);
}

void SongWordDialog::subscribeToCoreSignals()
{
    // Connect signals to wallet
    m_handler_transaction_changed = model->wallet().handleTransactionChanged(std::bind(NotifyTransactionChanged, this, std::placeholders::_1, std::placeholders::_2));
}

void SongWordDialog::unsubscribeFromCoreSignals()
{
    // Disconnect signals from wallet
    m_handler_transaction_changed->disconnect();
}

SendSongWordConfirmationDialog::SendSongWordConfirmationDialog(const QString &title, const QString &text, int secDelay,
    QWidget *parent) :
    QMessageBox(QMessageBox::Question, title, text, QMessageBox::Yes | QMessageBox::Cancel, parent), secDelay(secDelay)
{
    setDefaultButton(QMessageBox::Cancel);
    yesButton = button(QMessageBox::Yes);
    updateYesButton();
    connect(&countDownTimer, &QTimer::timeout, this, &SendSongWordConfirmationDialog::countDown);
}

int SendSongWordConfirmationDialog::exec()
{
    updateYesButton();
    countDownTimer.start(1000);
    return QMessageBox::exec();
}

void SendSongWordConfirmationDialog::countDown()
{
    secDelay--;
    updateYesButton();

    if(secDelay <= 0)
    {
        countDownTimer.stop();
    }
}

void SendSongWordConfirmationDialog::updateYesButton()
{
    if(secDelay > 0)
    {
        yesButton->setEnabled(false);
        yesButton->setText(tr("Yes") + " (" + QString::number(secDelay) + ")");
    }
    else
    {
        yesButton->setEnabled(true);
        yesButton->setText(tr("Yes"));
    }
}

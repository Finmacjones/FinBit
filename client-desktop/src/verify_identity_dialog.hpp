// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Tier-11 MITM verification UI — displays the safety number that the
// current user and a specific peer should compare out-of-band (in
// person, over voice, over a separately-authenticated channel) to
// confirm no MITM has substituted either of their pubkeys. The crypto
// (fb::crypto::safety_number) is order-independent so both peers
// compute the same string; matching numbers = no MITM.
//
// The dialog reads from / writes to the ChatClient's verified-peer
// persistence (sqlite-backed). A "Mark Verified" button persists the
// flag so subsequent runs show a ✓ badge; "Unmark" clears it.

#include <QDialog>
#include <QString>
#include <QByteArray>

class QLabel;
class QPushButton;

namespace fb::desktop {

class ChatClient;

class VerifyIdentityDialog : public QDialog {
    Q_OBJECT
public:
    // `client` provides safetyNumberFor / isPeerVerified / setPeerVerified;
    // ownership stays with the caller.
    VerifyIdentityDialog(ChatClient*       client,
                          const QString&    peerLabel,    // username or fingerprint
                          const QByteArray& peerPubkey,   // 32-byte raw Ed25519 pubkey
                          QWidget*          parent = nullptr);
    ~VerifyIdentityDialog() override;

private slots:
    void toggleVerified();

private:
    void refresh();

    ChatClient*  client_;
    QByteArray   peer_pubkey_;
    QString      peer_label_;

    QLabel*      my_fp_label_       = nullptr;
    QLabel*      peer_fp_label_     = nullptr;
    QLabel*      safety_number_lbl_ = nullptr;
    QLabel*      verified_status_   = nullptr;
    QPushButton* verify_btn_        = nullptr;
};

}  // namespace fb::desktop

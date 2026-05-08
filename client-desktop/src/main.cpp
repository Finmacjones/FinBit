// SPDX-License-Identifier: AGPL-3.0-or-later
#include <QApplication>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMessageBox>
#include <QPixmap>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTimer>
#include <cstdlib>
#include <stdlib.h>   // random()

#include "discord_theme.hpp"
#include "identity_vault.hpp"
#include "login_dialog.hpp"
#include "main_window.hpp"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    QApplication::setApplicationName("FinBit");
    QApplication::setOrganizationName("FinBit");   // disambiguates AppLocalDataLocation
    app.setStyleSheet(fb::desktop::discord_qss());

    // FB_SNAPSHOT_LOGIN=path.png — render the LoginDialog and exit. Useful
    // for verifying the dialog's layout in CI without a real desktop.
    if (const char* snap = std::getenv("FB_SNAPSHOT_LOGIN")) {
        fb::desktop::LoginDialog dlg;
        dlg.show();
        QString out_path = QString::fromUtf8(snap);
        QTimer::singleShot(200, [&app, &dlg, out_path]() {
            QPixmap pm = dlg.grab();
            pm.save(out_path);
            app.quit();
        });
        return app.exec();
    }

    // FB_SNAPSHOT=path.png with FB_SNAPSHOT_NO_LOGIN=1 → skip the modal
    // login (which would block forever in offscreen mode) and snapshot the
    // main window with a throwaway in-memory identity. Dev-only.
    //
    // FB_AUTO_LOGIN_USER + FB_AUTO_LOGIN_PASS → unlock <user>.vault with the
    // given passphrase and adopt the session non-interactively. Used by
    // automation that drives two clients at once on the same box without
    // human input. Combined with FB_AUTO_CONNECT_HOST/PORT it also clicks
    // the Connect button on a delay so we land in the chat view directly.
    fb::desktop::MainWindow w;
    bool did_auto_login = false;
    if (std::getenv("FB_SNAPSHOT_NO_LOGIN")) {
        std::array<std::uint8_t, 32> dummy_seed{};
        for (int i = 0; i < 32; ++i) dummy_seed[i] = static_cast<std::uint8_t>(i);
        w.adopt_session("snapshot", dummy_seed);
    } else if (const char* auto_user = std::getenv("FB_AUTO_LOGIN_USER")) {
        const char* auto_pass = std::getenv("FB_AUTO_LOGIN_PASS");
        if (!auto_pass) {
            std::fprintf(stderr, "FB_AUTO_LOGIN_USER set but FB_AUTO_LOGIN_PASS missing\n");
            return 2;
        }
        const QString username = QString::fromUtf8(auto_user);
        const QString path = fb::desktop::vault_path_for(username);
        auto blob = fb::desktop::load_vault_file(path);
        fb::desktop::Seed seed{};
        if (blob) {
            auto opened = fb::desktop::open_seed(QString::fromUtf8(auto_pass), *blob);
            if (!opened) {
                std::fprintf(stderr, "auto-login: wrong passphrase for %s\n",
                             auto_user);
                return 2;
            }
            seed = *opened;
        } else if (std::getenv("FB_AUTO_REGISTER")) {
            // No vault yet AND register-on-missing requested — generate
            // a fresh seed, seal it under the given passphrase, persist
            // the vault, and proceed. Useful for headless smoke tests
            // that need to spin up brand-new identities each run.
            for (auto& b : seed) b = static_cast<std::uint8_t>(random());
            auto fresh_blob = fb::desktop::seal_seed(
                QString::fromUtf8(auto_pass), seed);
            fb::desktop::save_vault_file(path, fresh_blob);
            std::fprintf(stderr, "auto-login: registered fresh vault for %s\n",
                         auto_user);
        } else {
            std::fprintf(stderr,
                         "auto-login: no vault file at %s "
                         "(set FB_AUTO_REGISTER=1 to create one)\n",
                         path.toUtf8().constData());
            return 2;
        }
        w.adopt_session(username, seed);
        did_auto_login = true;
    } else {
        // Gate the chat window behind the identity vault. If the user closes
        // the dialog without signing in, exit — there's no anonymous mode.
        fb::desktop::LoginDialog dlg;
        if (dlg.exec() != QDialog::Accepted) return 0;
        w.adopt_session(dlg.selected_username(), dlg.selected_seed());
    }
    w.show();

    // Auto-connect after auto-login, simulating the user clicking the
    // Connect button. Host/port come from the standard env vars so the
    // same launcher script can drive any server.
    if (did_auto_login) {
        QTimer::singleShot(150, [&w]() {
            for (auto* b : w.findChildren<QPushButton*>()) {
                if (b->text() == "Connect") { b->click(); break; }
            }
        });

        // FB_AUTO_DM_PEER + FB_AUTO_DM_TEXT — once connected, type the text
        // into the compose row targeted at PEER and press Send. Bootstraps
        // a ratchet session so a follow-up auto-call has something to
        // derive SFrame keys against.
        if (const char* dm_peer = std::getenv("FB_AUTO_DM_PEER")) {
            const char* dm_text = std::getenv("FB_AUTO_DM_TEXT");
            const QString peer = QString::fromUtf8(dm_peer);
            const QString text = QString::fromUtf8(dm_text ? dm_text : "auto");
            QTimer::singleShot(2000, [&w, peer, text]() {
                if (auto* tgt = w.findChild<QLineEdit*>(/*default=*/{},
                        Qt::FindChildrenRecursively)) {
                    // Walk all line edits; the compose target field has
                    // placeholder "username  or  #channel".
                    (void)tgt;
                }
                for (auto* le : w.findChildren<QLineEdit*>()) {
                    if (le->placeholderText().contains("#channel")) {
                        le->setText(peer);
                        break;
                    }
                }
                if (auto* input = w.findChild<QPlainTextEdit*>("input")) {
                    input->setPlainText(text);
                }
                for (auto* b : w.findChildren<QPushButton*>()) {
                    if (b->text() == "Send" && b->isEnabled()) { b->click(); break; }
                }
            });
        }

        // FB_AUTO_CALL_PEER — after a longer delay (give the DM session
        // time to bootstrap), select the DM sidebar entry for PEER and
        // click the "Call" button.
        if (const char* call_peer = std::getenv("FB_AUTO_CALL_PEER")) {
            const QString peer = QString::fromUtf8(call_peer);
            QTimer::singleShot(4000, [&w, peer]() {
                for (auto* lw : w.findChildren<QListWidget*>("dmList")) {
                    for (int i = 0; i < lw->count(); ++i) {
                        if (lw->item(i)->text() == peer) {
                            lw->setCurrentRow(i);
                            break;
                        }
                    }
                }
                for (auto* b : w.findChildren<QPushButton*>()) {
                    if (b->text() == "Call" && b->isEnabled()) { b->click(); break; }
                }
            });
        }

        // FB_AUTO_CHANNEL_CREATE=name — create a channel locally (no
        // peer prompt). Fires shortly after auto-DM so the inviter has
        // a session ready for any subsequent invite.
        if (const char* chan_create = std::getenv("FB_AUTO_CHANNEL_CREATE")) {
            const QString chan = QString::fromUtf8(chan_create);
            QTimer::singleShot(3000, [&w, chan]() {
                w.test_create_local_channel(chan);
            });
        }
        // FB_AUTO_CHANNEL_INVITE=peer — after the channel is created,
        // DM the SenderKeys distribution to PEER so they see the channel
        // in their sidebar too. Combined with FB_AUTO_CHANNEL_CREATE.
        if (const char* chan_invite = std::getenv("FB_AUTO_CHANNEL_INVITE")) {
            const char* chan_name = std::getenv("FB_AUTO_CHANNEL_CREATE");
            if (chan_name) {
                const QString chan = QString::fromUtf8(chan_name);
                const QString peer = QString::fromUtf8(chan_invite);
                QTimer::singleShot(3500, [&w, chan, peer]() {
                    w.test_invite_peer_to_channel(chan, peer);
                });
            }
        }
        // FB_AUTO_CHANNEL_VOICE=name — after sessions + channel are
        // up, join the voice room for `#name`. Each participant launched
        // with this env var triggers RoomJoin → roster broadcast → mesh
        // dial of every other roster member with whom we have a session.
        if (const char* chan_voice = std::getenv("FB_AUTO_CHANNEL_VOICE")) {
            const QString chan = QString::fromUtf8(chan_voice);
            QTimer::singleShot(5500, [&w, chan]() {
                w.test_join_channel_voice(chan);
            });
        }

        // FB_AUTO_ACCEPT_CALLS=1 — when an incoming-call dialog pops up,
        // auto-click "Accept (voice)". Implementation: install an event
        // filter that watches for QMessageBox creation and clicks the
        // first AcceptRole button. Timer is a fallback poll loop.
        if (std::getenv("FB_AUTO_ACCEPT_CALLS")) {
            auto* poll = new QTimer(&w);
            QObject::connect(poll, &QTimer::timeout, [&app]() {
                for (auto* widget : QApplication::topLevelWidgets()) {
                    auto* mb = qobject_cast<QMessageBox*>(widget);
                    if (!mb) continue;
                    if (mb->windowTitle() != "Incoming call") continue;
                    // Click the first "Accept" button.
                    for (auto* btn : mb->findChildren<QPushButton*>()) {
                        if (btn->text().contains("Accept (voice)")) {
                            btn->click();
                            return;
                        }
                    }
                }
            });
            poll->start(200);
        }
    }

    if (const char* snap = std::getenv("FB_SNAPSHOT")) {
        QString out_path = QString::fromUtf8(snap);
        QTimer::singleShot(300, [&app, &w, out_path]() {
            QPixmap pm = w.grab();
            pm.save(out_path);
            app.quit();
        });
    }

    return app.exec();
}

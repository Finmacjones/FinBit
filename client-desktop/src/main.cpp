// SPDX-License-Identifier: AGPL-3.0-or-later
#include <QApplication>
#include <QPixmap>
#include <QTimer>
#include <cstdlib>

#include "discord_theme.hpp"
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
    fb::desktop::MainWindow w;
    if (std::getenv("FB_SNAPSHOT_NO_LOGIN")) {
        std::array<std::uint8_t, 32> dummy_seed{};
        for (int i = 0; i < 32; ++i) dummy_seed[i] = static_cast<std::uint8_t>(i);
        w.adopt_session("snapshot", dummy_seed);
    } else {
        // Gate the chat window behind the identity vault. If the user closes
        // the dialog without signing in, exit — there's no anonymous mode.
        fb::desktop::LoginDialog dlg;
        if (dlg.exec() != QDialog::Accepted) return 0;
        w.adopt_session(dlg.selected_username(), dlg.selected_seed());
    }
    w.show();

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

// SPDX-License-Identifier: AGPL-3.0-or-later
#include "discord_theme.hpp"

namespace fb::desktop {

QString discord_qss() {
    // Built up as a single QSS string applied via QApplication::setStyleSheet.
    // Object-name selectors (#serverRail, #channelPanel, etc.) target the
    // distinct widgets in MainWindow.
    return QString::fromLatin1(R"(
QMainWindow, QWidget { background: #36393f; color: #dcddde;
                       font-family: "Inter", "Noto Sans", sans-serif; }
QToolTip { background: #18191c; color: #dcddde; border: 1px solid #202225;
           padding: 4px 6px; }

/* ----- Left server rail ----- */
QWidget#serverRail { background: #202225; border: none; }
QListWidget#serverRailList { background: transparent; border: none;
                              outline: 0; padding-top: 8px; }
QListWidget#serverRailList::item { padding: 6px 0; margin: 4px 0;
                                    border-radius: 999px; }
QListWidget#serverRailList::item:hover { background: #36393f; }
QListWidget#serverRailList::item:selected { background: #5865f2; }

/* ----- Channels panel ----- */
QWidget#channelPanel { background: #2f3136; border: none; }
QLabel#channelPanelHeader { background: #2f3136; color: #ffffff;
                             font-weight: 700; font-size: 15px;
                             padding: 14px 16px; border-bottom: 1px solid #202225; }
QLabel#sidebarSectionLabel { color: #8e9297; font-size: 11px; font-weight: 700;
                              letter-spacing: 0.04em; padding: 16px 16px 4px 16px;
                              text-transform: uppercase; }

QListWidget#dmList, QListWidget#channelList {
    background: transparent; border: none; outline: 0;
    padding: 2px 8px; color: #8e9297;
}
QListWidget#dmList::item, QListWidget#channelList::item {
    padding: 6px 8px; margin: 1px 0; border-radius: 4px; color: #8e9297;
}
QListWidget#dmList::item:hover, QListWidget#channelList::item:hover {
    background: #34373c; color: #dcddde;
}
QListWidget#dmList::item:selected, QListWidget#channelList::item:selected {
    background: #393c43; color: #ffffff;
}

/* ----- User-status panel (bottom-left) ----- */
QWidget#userPanel { background: #292b2f; border-top: 1px solid #202225; }
QLabel#userPanelName { color: #ffffff; font-weight: 600; }
QLabel#userPanelFp   { color: #b9bbbe; font-size: 11px; font-family: monospace; }

/* ----- Main message area header ----- */
QWidget#chatHeader { background: #36393f; border-bottom: 1px solid #202225; }
QLabel#chatHeaderTitle { color: #ffffff; font-weight: 700; font-size: 15px;
                         padding-left: 16px; }
QLabel#chatHeaderSubtitle { color: #b9bbbe; padding-left: 12px; }

/* ----- Message list ----- */
QListWidget#messages { background: #36393f; border: none; outline: 0;
                       padding: 0 0 8px 0; }
QListWidget#messages::item { background: transparent; padding: 0; }

/* ----- Compose row ----- */
QWidget#composeRow { background: #36393f; padding: 0 16px 16px 16px; }
QLineEdit#targetEdit, QPlainTextEdit#input,
QLineEdit, QPlainTextEdit, QSpinBox {
    background: #40444b; color: #dcddde; border: 1px solid transparent;
    border-radius: 8px; padding: 10px 12px; selection-background-color: #5865f2;
}
QLineEdit:focus, QPlainTextEdit:focus, QSpinBox:focus { border-color: #5865f2; }

QPlainTextEdit#input { padding: 10px 14px; }

QPushButton {
    background: #5865f2; color: #ffffff; border: none; border-radius: 4px;
    padding: 8px 14px; font-weight: 600;
}
QPushButton:hover { background: #4752c4; }
QPushButton:pressed { background: #3c45a5; }
QPushButton:disabled { background: #4f545c; color: #8e9297; }

QPushButton#secondaryBtn { background: #4f545c; color: #ffffff; }
QPushButton#secondaryBtn:hover { background: #5d6269; }
QPushButton#dangerBtn { background: #ed4245; }
QPushButton#dangerBtn:hover { background: #c33d3f; }

/* Login modal banner across the top */
QGroupBox#loginGroup { background: #2f3136; border: 1px solid #202225;
                        border-radius: 6px; margin: 8px; padding-top: 12px; }
QGroupBox#loginGroup::title { color: #b9bbbe; subcontrol-origin: margin;
                               left: 12px; padding: 0 4px; }
QLabel#statusLabel { color: #8e9297; }

/* ----- Log pane ----- */
QPlainTextEdit#logView {
    background: #18191c; color: #b9bbbe; font-family: monospace;
    border-top: 1px solid #202225; border-radius: 0;
}

/* Scrollbars — Discord uses a thin dark scrollbar */
QScrollBar:vertical { background: #2e3338; width: 10px; }
QScrollBar::handle:vertical { background: #202225; min-height: 32px;
                               border-radius: 4px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QScrollBar:horizontal { background: #2e3338; height: 10px; }
QScrollBar::handle:horizontal { background: #202225; min-width: 32px;
                                  border-radius: 4px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
)");
}

}  // namespace fb::desktop

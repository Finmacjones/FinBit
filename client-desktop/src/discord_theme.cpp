// SPDX-License-Identifier: AGPL-3.0-or-later
#include "discord_theme.hpp"

namespace fb::desktop {

QString discord_qss() {
    // Built up as a single QSS string applied via QApplication::setStyleSheet.
    // Object-name selectors (#serverRail, #channelPanel, etc.) target the
    // distinct widgets in MainWindow.
    // Matrix / CRT / phosphor-terminal theme — mirrors design/tokens.css.
    // Qt QSS can't do text-shadow / box-shadow / animation / ::before, so the
    // phosphor "glow" is carried by bright mint text on pure-black surfaces +
    // phosphor hairline borders. The animated CRT layer (scanlines + flicker)
    // is the separate CrtOverlay widget, painted over the window.
    return QString::fromLatin1(R"(
QMainWindow, QWidget { background: #0a0f0c; color: #9fd9b8;
                       font-family: "IBM Plex Mono", "DejaVu Sans Mono", monospace; }
QToolTip { background: #000000; color: #00ff9d; border: 1px solid #163322;
           padding: 4px 6px; }

/* ----- Left server rail ----- */
QWidget#serverRail { background: #050807; border-right: 1px solid #163322; }
QListWidget#serverRailList { background: transparent; border: none;
                              outline: 0; padding-top: 8px; }
QListWidget#serverRailList::item { padding: 6px 0; margin: 4px 0;
                                    border-radius: 2px; }
QListWidget#serverRailList::item:hover { background: #0d1311; color: #c8ffe1; }
QListWidget#serverRailList::item:selected { background: #112019; color: #00ff9d;
                                    border: 1px solid #00ff9d; }

/* ----- Channels panel ----- */
QWidget#channelPanel { background: #080c0a; border-right: 1px solid #163322; }
QLabel#channelPanelHeader { background: #080c0a; color: #00ff9d;
                             font-weight: 600; font-size: 13px;
                             padding: 14px 16px; border-bottom: 1px solid #163322; }
QLabel#sidebarSectionLabel { color: #4f8568; font-size: 10px; font-weight: 500;
                              letter-spacing: 0.08em; padding: 16px 16px 4px 16px; }

QListWidget#dmList, QListWidget#channelList {
    background: transparent; border: none; outline: 0;
    padding: 2px 8px; color: #4f8568;
}
QListWidget#dmList::item, QListWidget#channelList::item {
    padding: 5px 8px; margin: 1px 0; border-radius: 2px; color: #4f8568;
}
QListWidget#dmList::item:hover, QListWidget#channelList::item:hover {
    background: #0d1311; color: #9fd9b8;
}
QListWidget#dmList::item:selected, QListWidget#channelList::item:selected {
    background: #112019; color: #00ff9d;
}

/* ----- User-status panel (bottom-left) ----- */
QWidget#userPanel { background: #070a08; border-top: 1px solid #163322; }
QLabel#userPanelName { color: #00ff9d; font-weight: 500; }
QLabel#userPanelFp   { color: #4f8568; font-size: 10px; font-family: "IBM Plex Mono", monospace; }

/* ----- Main message area header ----- */
QWidget#chatHeader { background: #0a0f0c; border-bottom: 1px solid #163322; }
QLabel#chatHeaderTitle { color: #00ff9d; font-weight: 600; font-size: 14px;
                         padding-left: 16px; }
QLabel#chatHeaderSubtitle { color: #4f8568; padding-left: 12px; }

/* ----- Message list ----- */
QListWidget#messages { background: #0a0f0c; border: none; outline: 0;
                       padding: 0 0 8px 0; }
QListWidget#messages::item { background: transparent; padding: 0; }

/* ----- Compose row ----- */
QWidget#composeRow { background: #0a0f0c; padding: 0 16px 16px 16px; }
QLineEdit#targetEdit, QPlainTextEdit#input,
QLineEdit, QPlainTextEdit, QSpinBox {
    background: #000000; color: #00ff9d; border: 1px solid #163322;
    border-radius: 2px; padding: 9px 12px; selection-background-color: #00ff9d;
    selection-color: #000000;
}
QLineEdit:focus, QPlainTextEdit:focus, QSpinBox:focus { border-color: #00ff9d; }

QPlainTextEdit#input { padding: 9px 14px; }

QPushButton {
    background: #00ff9d; color: #001b10; border: 1px solid #00ff9d; border-radius: 2px;
    padding: 7px 14px; font-weight: 600;
}
QPushButton:hover { background: #0a0f0c; color: #00ff9d; }
QPushButton:pressed { background: #112019; color: #00ff9d; }
QPushButton:disabled { background: transparent; color: #2f5a44; border-color: #163322; }

QPushButton#secondaryBtn { background: transparent; color: #4f8568; border: 1px solid #163322; }
QPushButton#secondaryBtn:hover { background: transparent; color: #00ff9d; border-color: #00ff9d; }
QPushButton#dangerBtn { background: #ff3b6b; color: #000000; border: 1px solid #ff3b6b; }
QPushButton#dangerBtn:hover { background: #0a0f0c; color: #ff3b6b; }
/* Borderless inline link buttons (e.g. "I have a recovery code"). */
QPushButton#linkBtn { background: transparent; color: #00ff9d; padding: 4px 8px;
                       font-weight: 500; border: none; text-decoration: underline; }
QPushButton#linkBtn:hover  { color: #c8ffe1; background: transparent; }
QPushButton#linkBtn:pressed { color: #00b873; background: transparent; }

/* Login modal banner across the top */
QGroupBox#loginGroup { background: #080c0a; border: 1px solid #00ff9d;
                        border-radius: 2px; margin: 8px; padding-top: 12px; }
QGroupBox#loginGroup::title { color: #00ff9d; subcontrol-origin: margin;
                               left: 12px; padding: 0 4px; }
QLabel#statusLabel { color: #4f8568; }

/* ----- Log pane ----- */
QPlainTextEdit#logView {
    background: #000000; color: #4f8568; font-family: "IBM Plex Mono", monospace;
    border-top: 1px solid #163322; border-radius: 0;
}

/* Menus (CRT-effects toggle lives here) */
QMenuBar { background: #050807; color: #4f8568; }
QMenuBar::item:selected { background: #112019; color: #00ff9d; }
QMenu { background: #050807; color: #9fd9b8; border: 1px solid #163322; }
QMenu::item:selected { background: #112019; color: #00ff9d; }
QMenu::indicator:checked { background: #00ff9d; }

/* Scrollbars — thin phosphor */
QScrollBar:vertical { background: transparent; width: 10px; }
QScrollBar::handle:vertical { background: #1a3024; min-height: 32px;
                               border-radius: 2px; }
QScrollBar::handle:vertical:hover { background: #1f5036; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QScrollBar:horizontal { background: transparent; height: 10px; }
QScrollBar::handle:horizontal { background: #1a3024; min-width: 32px;
                                  border-radius: 2px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
)");
}

}  // namespace fb::desktop

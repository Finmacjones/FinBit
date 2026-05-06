// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <QString>

namespace fb::desktop {

// Returns the application-wide QSS that paints FinBit in Discord's dark
// theme: server rail, channels panel, message area, compose, dialogs.
[[nodiscard]] QString discord_qss();

namespace dc {
inline constexpr const char* bg_tertiary  = "#202225";
inline constexpr const char* bg_secondary = "#2f3136";
inline constexpr const char* bg_alt       = "#292b2f";
inline constexpr const char* bg_primary   = "#36393f";
inline constexpr const char* bg_hover     = "#34373c";
inline constexpr const char* bg_selected  = "#393c43";
inline constexpr const char* bg_floating  = "#18191c";
inline constexpr const char* bg_input     = "#40444b";
inline constexpr const char* text_normal  = "#dcddde";
inline constexpr const char* text_muted   = "#72767d";
inline constexpr const char* text_header  = "#ffffff";
inline constexpr const char* text_chan    = "#8e9297";
inline constexpr const char* blurple      = "#5865f2";
inline constexpr const char* blurple_hover = "#4752c4";
inline constexpr const char* online_green = "#3ba55d";
inline constexpr const char* error_red    = "#ed4245";
}  // namespace dc

}  // namespace fb::desktop

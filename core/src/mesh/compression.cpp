// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/mesh/bridge.hpp"

#include <stdexcept>
#include <string_view>

#if FB_HAVE_BROTLI
#  include <brotli/decode.h>
#  include <brotli/encode.h>
#endif

// =============================================================================
// Brotli compression for mesh-bridged channels.
//
// Mesh links (LoRa) carry tiny payloads — typically ~200 bytes per frame on
// MeshCore / Meshtastic. We compress aggressively so a chat message + small
// metadata fits inside one frame. The static dictionary below is a small
// corpus of high-frequency chat tokens. A larger dictionary tuned to the
// project's actual traffic should replace this in Phase 4.5.
// =============================================================================

namespace fb::mesh {
namespace {

// Static dictionary — concatenation of common chat tokens (no separators).
// brotli looks up substrings of recent input here when no good back-reference
// exists in the stream. Keep this small (<16 KB) to limit code size.
constexpr std::string_view kStaticDict =
    " the and you for that this with have not from they will would your what "
    "say said get got see now then about think know like just well good okay "
    "right yeah really thanks please sorry hey hi bye lol omg btw imo "
    "FinBit channel message msg send sent recv user peer group call meeting "
    "today tomorrow yesterday morning evening night time soon later "
    "https://github.com/ image jpg png gif pdf https:// http:// "
    "node device serial mesh meshtastic meshcore lora signal hop snr";

}  // namespace

std::vector<std::uint8_t> compress_for_mesh(std::span<const std::uint8_t> in) {
#if !FB_HAVE_BROTLI
    (void)in;
    throw std::runtime_error("compress_for_mesh: built without brotli (FB_HAVE_BROTLI=0)");
#else
    if (in.empty()) return {};
    // Worst-case compressed size estimator from brotli.
    const std::size_t max_out = BrotliEncoderMaxCompressedSize(in.size());
    std::vector<std::uint8_t> out(max_out > 0 ? max_out : in.size() + 64);

    auto* enc = BrotliEncoderCreateInstance(nullptr, nullptr, nullptr);
    if (!enc) throw std::runtime_error("BrotliEncoderCreateInstance failed");

    // Maximum quality + small window (mesh frames are tiny; large window is
    // wasted memory).
    BrotliEncoderSetParameter(enc, BROTLI_PARAM_QUALITY, 11);
    BrotliEncoderSetParameter(enc, BROTLI_PARAM_LGWIN, 16);  // 64 KiB window
    BrotliEncoderSetParameter(enc, BROTLI_PARAM_MODE, BROTLI_MODE_TEXT);
    BrotliEncoderAttachPreparedDictionary(
        enc,
        BrotliEncoderPrepareDictionary(BROTLI_SHARED_DICTIONARY_RAW, kStaticDict.size(),
                                       reinterpret_cast<const std::uint8_t*>(kStaticDict.data()),
                                       BROTLI_MAX_QUALITY, nullptr, nullptr, nullptr));

    std::size_t avail_in = in.size();
    const std::uint8_t* next_in = in.data();
    std::size_t avail_out = out.size();
    std::uint8_t* next_out = out.data();
    if (!BrotliEncoderCompressStream(enc, BROTLI_OPERATION_FINISH, &avail_in, &next_in,
                                     &avail_out, &next_out, nullptr)) {
        BrotliEncoderDestroyInstance(enc);
        throw std::runtime_error("BrotliEncoderCompressStream failed");
    }
    if (!BrotliEncoderIsFinished(enc)) {
        BrotliEncoderDestroyInstance(enc);
        throw std::runtime_error("brotli encoder not finished — output buffer too small?");
    }
    out.resize(out.size() - avail_out);
    BrotliEncoderDestroyInstance(enc);
    return out;
#endif
}

std::vector<std::uint8_t> decompress_from_mesh(std::span<const std::uint8_t> in) {
#if !FB_HAVE_BROTLI
    (void)in;
    throw std::runtime_error("decompress_from_mesh: built without brotli (FB_HAVE_BROTLI=0)");
#else
    if (in.empty()) return {};
    auto* dec = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
    if (!dec) throw std::runtime_error("BrotliDecoderCreateInstance failed");
    BrotliDecoderAttachDictionary(
        dec, BROTLI_SHARED_DICTIONARY_RAW, kStaticDict.size(),
        reinterpret_cast<const std::uint8_t*>(kStaticDict.data()));

    std::vector<std::uint8_t> out;
    out.reserve(in.size() * 4);
    std::size_t avail_in = in.size();
    const std::uint8_t* next_in = in.data();
    constexpr std::size_t kChunk = 1024;
    std::vector<std::uint8_t> chunk(kChunk);
    BrotliDecoderResult rc = BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT;
    while (rc == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT ||
           rc == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT) {
        std::size_t avail_out = chunk.size();
        std::uint8_t* next_out = chunk.data();
        rc = BrotliDecoderDecompressStream(dec, &avail_in, &next_in, &avail_out, &next_out,
                                           nullptr);
        out.insert(out.end(), chunk.data(), chunk.data() + (chunk.size() - avail_out));
        if (rc == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT && avail_in == 0) {
            BrotliDecoderDestroyInstance(dec);
            throw std::runtime_error("brotli decoder needs more input but stream ended");
        }
    }
    BrotliDecoderDestroyInstance(dec);
    if (rc != BROTLI_DECODER_RESULT_SUCCESS) {
        throw std::runtime_error("brotli decompress failed");
    }
    return out;
#endif
}

}  // namespace fb::mesh

use crate::{Browser, Os};

use super::{Coverage, Reference};

pub(crate) const CHROMIUM_OLD_ALPS: Reference = Reference {
    id: "chromium-old-alps",
    source: "Chromium 131-134 (ALPS codepoint 0x4469): real Chrome 131-134 captures",
    ja4: Some("t13d1516h2_8daaf6152771_02713d6af862"),
    ja3n_hash: Some("dee19b855b658c6aa0f575eda2525e19"),
    ja3_hash: None,
    akamai_hash: Some("52d84b11737d980aef856699f885ca86"),
    akamai_text: Some("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"),
    quic_ja4: None,
};

pub(crate) const CHROMIUM_NEW_ALPS: Reference = Reference {
    id: "chromium-new-alps",
    source: "Chromium 135-149 (ALPS codepoint 0x44CD): real Chrome 135-140, Chrome 135-149 on Android, Edge and Opera 124-125 captures; Samsung Internet 29 and 30 (Chromium 136 and 143) on Android",
    ja4: Some("t13d1516h2_8daaf6152771_d8a2da3f94cd"),
    ja3n_hash: Some("8e19337e7524d2573be54efb2b0784c9"),
    ja3_hash: None,
    akamai_hash: Some("52d84b11737d980aef856699f885ca86"),
    akamai_text: Some("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"),
    quic_ja4: None,
};

pub(crate) const CHROMIUM_MLDSA_TRUST_ANCHORS: Reference = Reference {
    id: "chromium-mldsa-trust-anchors",
    source: "Chromium 152+ with trust_anchors (ML-DSA signature algorithms): real Chrome 153 and Opera 136 captures, Chrome 152 and 154 on Android; Chrome 155 from tls.browserleaks.com and a ClientHello capture; Chrome 156.0.8078.80 on Windows and 156.0.8078.79 on Android, Opera 137-139 (Chromium 153-155), Chrome for Testing 157.0.8103.15 without the field trial testing config, Chrome 157.0.8103.38 and 158.0.8127.18 on Windows (tls.browserleaks.com)",
    ja4: Some("t13d1517h2_8daaf6152771_cb7bf5808d99"),
    ja3n_hash: Some("bd4930bd9b000ee684830e44bab76fdf"),
    ja3_hash: None,
    akamai_hash: Some("52d84b11737d980aef856699f885ca86"),
    akamai_text: Some("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"),
    quic_ja4: None,
};

pub(crate) const CHROMIUM_MLDSA: Reference = Reference {
    id: "chromium-mldsa",
    source: "Chromium 150+ without trust_anchors (ML-DSA signature algorithms): real Opera 134-135 (JA4), Edge 152-154, Edge 153 and Chrome 150-151 on Android (JA4, JA3N, Akamai) captures; desktop Chrome 151 and Edge 151 stable (koon 0.8.1); Brave 1.95.104 and 1.96.59 on Windows, 1.96.59 on Android; Edge 156.0.4314.58 and 157.0.4341.42, Brave 1.97.59, 1.98.63 and 1.99.55 on Windows, 1.97.56 on Android (tls.browserleaks.com)",
    ja4: Some("t13d1516h2_8daaf6152771_806a8c22fdea"),
    ja3n_hash: Some("8e19337e7524d2573be54efb2b0784c9"),
    ja3_hash: None,
    akamai_hash: Some("52d84b11737d980aef856699f885ca86"),
    akamai_text: Some("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"),
    quic_ja4: None,
};

pub(crate) const CHROME_QUIC: Reference = Reference {
    id: "chrome-quic",
    source: "QUIC JA4 computed from the QUIC ClientHello of a real Chrome 153 (tests/quic_initial.rs); Chrome 154 only sorts its trust anchor IDs; Chrome 155 from quic.browserleaks.com and a QUIC capture; Chrome 154/155 and Opera 136.0.6008.52 on Linux and macOS from quic.browserleaks.com; Chrome 156 on Windows and Android, Opera 137-139, Chrome for Testing 157.0.8103.15, Chrome 157.0.8103.38 and 158.0.8127.18 on Windows from quic.browserleaks.com",
    ja4: None,
    ja3n_hash: None,
    ja3_hash: None,
    akamai_hash: None,
    akamai_text: None,
    quic_ja4: Some("q13d0312h3_55b375c5d22e_178839b6cec1"),
};

pub(crate) const CHROME_SERVER_PADDING: Reference = Reference {
    id: "chrome-server-padding",
    source: "Chrome 152+ with trust_anchors and the server_padding extension of the PqcBandwidthExperiment field trial: real Chrome 153.0.8010.52 and the 154 and 155 betas on a Pixel 9 Pro XL with Android 17 (tls.browserleaks.com and ClientHello captures)",
    ja4: Some("t13d1518h2_8daaf6152771_4980c97edce0"),
    ja3n_hash: Some("a3a3161a080b73bda9cc285fb367fcc0"),
    ja3_hash: None,
    akamai_hash: Some("52d84b11737d980aef856699f885ca86"),
    akamai_text: Some("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"),
    quic_ja4: None,
};

pub(crate) const CHROME_QUIC_SERVER_PADDING: Reference = Reference {
    id: "chrome-quic-server-padding",
    source: "QUIC JA4 of real Chrome 153.0.8010.52 and the 152 and 155 betas on Android 17 (quic.browserleaks.com)",
    ja4: None,
    ja3n_hash: None,
    ja3_hash: None,
    akamai_hash: None,
    akamai_text: None,
    quic_ja4: Some("q13d0313h3_55b375c5d22e_eb028bd37c08"),
};

pub(crate) const CHROME_QUIC_OLD_ALPS: Reference = Reference {
    id: "chrome-quic-old-alps",
    source: "QUIC JA4 of the real Chrome 134 beta on Android 17 (quic.browserleaks.com)",
    ja4: None,
    ja3n_hash: None,
    ja3_hash: None,
    akamai_hash: None,
    akamai_text: None,
    quic_ja4: Some("q13d0311h3_55b375c5d22e_5a1f323ef56d"),
};

pub(crate) const OPERA_MOBILE: Reference = Reference {
    id: "opera-mobile",
    source: "Opera for Android 102.1.5206.90382 (Chromium 152.0.7977.82) on a Pixel 9 Pro XL with Android 17 (tls.browserleaks.com and ClientHello captures)",
    ja4: Some("t13d1516h2_8daaf6152771_806a8c22fdea"),
    ja3n_hash: Some("8e19337e7524d2573be54efb2b0784c9"),
    ja3_hash: None,
    akamai_hash: Some("4f04edce68a7ecbe689edce7bf5f23f3"),
    akamai_text: Some("1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p"),
    quic_ja4: None,
};

pub(crate) const CHROMIUM_QUIC_NO_TRUST_ANCHORS: Reference = Reference {
    id: "chromium-quic-no-trust-anchors",
    source: "QUIC JA4 of the real Chrome 135, 140, 141, 149, 150 and 151 betas on Android 17, Edge 153 and 154 on Windows and macOS (154 also from quic.browserleaks.com), Edge 153 on Android and Brave 1.95.104 and 1.96.59 on Windows and 1.96.59 on Android; Opera for Android 102 sent it with pre_shared_key and early_data in its resumed hello (q13d0313h3_55b375c5d22e_226f3f127bbe), its full one was not captured; Edge 156.0.4314.58 and 157.0.4341.42, Brave 1.97.59, 1.98.63 and 1.99.55 on Windows, 1.97.56 on Android (quic.browserleaks.com)",
    ja4: None,
    ja3n_hash: None,
    ja3_hash: None,
    akamai_hash: None,
    akamai_text: None,
    quic_ja4: Some("q13d0311h3_55b375c5d22e_653d80c3fe9d"),
};

pub(crate) const FIREFOX_135: Reference = Reference {
    id: "firefox-135",
    source: "Firefox 135-150: real Firefox captures",
    ja4: Some("t13d1717h2_5b57614c22b0_3cbfd9057e0d"),
    ja3n_hash: Some("e4147a4860c1f347354f0a84d8787c02"),
    ja3_hash: None,
    akamai_hash: Some("6ea73faa8fc5aac76bded7bd238f6433"),
    akamai_text: Some("1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s"),
    quic_ja4: None,
};

pub(crate) const FIREFOX_151: Reference = Reference {
    id: "firefox-151",
    source: "Firefox 151-153 (without cipher 0xc009): real Firefox captures",
    ja4: Some("t13d1617h2_86a278354501_3cbfd9057e0d"),
    ja3n_hash: Some("8099457c290ccfe8c6d958826c26b023"),
    ja3_hash: None,
    akamai_hash: Some("6ea73faa8fc5aac76bded7bd238f6433"),
    akamai_text: Some("1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s"),
    quic_ja4: None,
};

pub(crate) const FIREFOX_154: Reference = Reference {
    id: "firefox-154",
    source: "Firefox 154-155 (without cipher 0xc00a): JA3 and JA3N computed from real Firefox 154.0 and 155.0 ClientHellos",
    ja4: Some("t13d1517h2_8daaf6152771_3cbfd9057e0d"),
    ja3n_hash: Some("1d9334692003212ed6c01718554b1b1c"),
    ja3_hash: Some("424f6d9c8b8928c0a0489a4f1a0f3e89"),
    akamai_hash: Some("6ea73faa8fc5aac76bded7bd238f6433"),
    akamai_text: Some("1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s"),
    quic_ja4: None,
};

pub(crate) const FIREFOX_156: Reference = Reference {
    id: "firefox-156",
    source: "Firefox 156-159 (without ffdhe groups): real Firefox 156.0.1 and 159.0.1 captures; 157 and 158 from the 157.0 and 158.0b5 betas (ClientHello capture and tls.browserleaks.com)",
    ja4: Some("t13d1517h2_8daaf6152771_3cbfd9057e0d"),
    ja3n_hash: Some("f9c6a2c424206e61efb6c1a6325596b5"),
    ja3_hash: Some("9d42e90b0225e779f03141ddcd699df2"),
    akamai_hash: Some("6ea73faa8fc5aac76bded7bd238f6433"),
    akamai_text: Some("1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s"),
    quic_ja4: None,
};

pub(crate) const FIREFOX_QUIC: Reference = Reference {
    id: "firefox-quic",
    source: "QUIC JA4 of real Firefox 155.0.1, 157.0 beta, 158.0b5 and 159.0.1 QUIC ClientHellos (157 to 159 also from quic.browserleaks.com); on Android from the 146.0b9, 147.0b9, 150.0b10, 151.0b10, 153.0b13, 154.0b10, 155.0b5, 157.0b5 and 158.0b5 betas and 159.0 (quic.browserleaks.com)",
    ja4: None,
    ja3n_hash: None,
    ja3_hash: None,
    akamai_hash: None,
    akamai_text: None,
    quic_ja4: Some("q13d0315h3_55b375c5d22e_dc5437974b47"),
};

pub(crate) const FIREFOX_156_QUIC: Reference = Reference {
    id: "firefox-156-quic",
    source: "QUIC JA4 computed from the QUIC ClientHello of a real Firefox 156 (tests/quic_initial.rs); on Android from 156.0.1 and the 156.0b5 beta (quic.browserleaks.com)",
    ja4: None,
    ja3n_hash: None,
    ja3_hash: None,
    akamai_hash: None,
    akamai_text: None,
    quic_ja4: Some("q13d0315h3_55b375c5d22e_bb76f32061e3"),
};

pub(crate) const FIREFOX_ANDROID_146: Reference = Reference {
    id: "firefox-android-146",
    source: "Firefox 146-150 on Android (without signed_certificate_timestamp): real 146.0b9, 147.0b9 and 150.0b10 betas on Android 17 (tls.browserleaks.com and ClientHello captures)",
    ja4: Some("t13d1716h2_5b57614c22b0_eeeea6562960"),
    ja3n_hash: Some("90634f51dcf65fc506946108904d6913"),
    ja3_hash: Some("2d692a4485ca2f5f2b10ecb2d2909ad3"),
    akamai_hash: Some("41a06cadb1c6385e6d08c8d0dbbea818"),
    akamai_text: Some("1:4096;2:0;4:32768;5:16384|12517377|0|m,p,a,s"),
    quic_ja4: None,
};

pub(crate) const FIREFOX_ANDROID_151: Reference = Reference {
    id: "firefox-android-151",
    source: "Firefox 151-153 on Android (without cipher 0xc009 and signed_certificate_timestamp): real 151.0b10 and 153.0b13 betas on Android 17 (tls.browserleaks.com and ClientHello captures)",
    ja4: Some("t13d1616h2_86a278354501_eeeea6562960"),
    ja3n_hash: Some("9fdfb10f9cb8fce80779f8ffb5a34f4a"),
    ja3_hash: Some("c43da27af379abb70ab285d8ef656f71"),
    akamai_hash: Some("41a06cadb1c6385e6d08c8d0dbbea818"),
    akamai_text: Some("1:4096;2:0;4:32768;5:16384|12517377|0|m,p,a,s"),
    quic_ja4: None,
};

pub(crate) const FIREFOX_ANDROID_154: Reference = Reference {
    id: "firefox-android-154",
    source: "Firefox 154 on Android (without cipher 0xc00a and signed_certificate_timestamp): real 154.0b10 beta on Android 17 (tls.browserleaks.com and ClientHello capture)",
    ja4: Some("t13d1516h2_8daaf6152771_eeeea6562960"),
    ja3n_hash: Some("8c3237398318fb048d0bc301bc804de5"),
    ja3_hash: Some("a1d7243639bf3eccacd288639c620582"),
    akamai_hash: Some("41a06cadb1c6385e6d08c8d0dbbea818"),
    akamai_text: Some("1:4096;2:0;4:32768;5:16384|12517377|0|m,p,a,s"),
    quic_ja4: None,
};

pub(crate) const FIREFOX_ANDROID_155: Reference = Reference {
    id: "firefox-android-155",
    source: "Firefox 155 on Android (signed_certificate_timestamp from 155 on): real 155.0b5 beta on Android 17 (tls.browserleaks.com and ClientHello capture)",
    ja4: Some("t13d1517h2_8daaf6152771_3cbfd9057e0d"),
    ja3n_hash: Some("1d9334692003212ed6c01718554b1b1c"),
    ja3_hash: Some("424f6d9c8b8928c0a0489a4f1a0f3e89"),
    akamai_hash: Some("41a06cadb1c6385e6d08c8d0dbbea818"),
    akamai_text: Some("1:4096;2:0;4:32768;5:16384|12517377|0|m,p,a,s"),
    quic_ja4: None,
};

pub(crate) const FIREFOX_ANDROID_156: Reference = Reference {
    id: "firefox-android-156",
    source: "Firefox 156-159 on Android (without ffdhe groups): real 156.0.1, 156.0b5, 157.0b5, 158.0b5 and 159.0 on Android 17 (tls.browserleaks.com and ClientHello captures)",
    ja4: Some("t13d1517h2_8daaf6152771_3cbfd9057e0d"),
    ja3n_hash: Some("f9c6a2c424206e61efb6c1a6325596b5"),
    ja3_hash: Some("9d42e90b0225e779f03141ddcd699df2"),
    akamai_hash: Some("41a06cadb1c6385e6d08c8d0dbbea818"),
    akamai_text: Some("1:4096;2:0;4:32768;5:16384|12517377|0|m,p,a,s"),
    quic_ja4: None,
};

pub(crate) const SAFARI_MACOS12_13: Reference = Reference {
    id: "safari-macos12-13",
    source: "Safari on macOS 12 and 13 (ecdsa_sha1, no SETTINGS_ENABLE_PUSH): real Safari 15.6 on macOS 12.5, 16.0 (Safari16.0MontereyAuto.pkg, Apple-signed) and 15.6.1 on macOS 12.6, and 16.1 on macOS 13.0",
    ja4: Some("t13d2014h2_a09f3c656075_14788d8d241b"),
    ja3n_hash: Some("44f7ed5185d22c92b96da72dbe68d307"),
    ja3_hash: Some("773906b0efdefa24a7f2b8eb6985bf37"),
    akamai_hash: Some("dda308d35f4e5db7b52a61720ca1b122"),
    akamai_text: Some("4:4194304;3:100|10485760|0|m,s,p,a"),
    quic_ja4: None,
};

pub(crate) const SAFARI_MACOS14: Reference = Reference {
    id: "safari-macos14",
    source: "Safari on macOS 14 and 15.0 (ecdsa_sha1, 4 MB HTTP/2 window): real Safari 17.6 on macOS 14.6, 18.0 on macOS 14.7 and 15.0, and Safari 26.6 on macOS 14.8.9",
    ja4: Some("t13d2014h2_a09f3c656075_14788d8d241b"),
    ja3n_hash: Some("44f7ed5185d22c92b96da72dbe68d307"),
    ja3_hash: Some("773906b0efdefa24a7f2b8eb6985bf37"),
    akamai_hash: Some("959a7e813b79b909a1a0b00a38e8bba3"),
    akamai_text: Some("2:0;4:4194304;3:100|10485760|0|m,s,p,a"),
    quic_ja4: None,
};

pub(crate) const SAFARI_IOS16: Reference = Reference {
    id: "safari-ios16",
    source: "Safari on iOS 16.0 and 16.1 (ecdsa_sha1, no SETTINGS_ENABLE_PUSH): real Safari on the iOS 16.0 (20A360) and 16.1 (20B72) simulators",
    ja4: Some("t13d2014h2_a09f3c656075_14788d8d241b"),
    ja3n_hash: Some("44f7ed5185d22c92b96da72dbe68d307"),
    ja3_hash: Some("773906b0efdefa24a7f2b8eb6985bf37"),
    akamai_hash: Some("d5fcbdc393757341115a861bf8d23265"),
    akamai_text: Some("4:2097152;3:100|10485760|0|m,s,p,a"),
    quic_ja4: None,
};

pub(crate) const SAFARI_IOS17: Reference = Reference {
    id: "safari-ios17",
    source: "Safari on iOS 17 (ecdsa_sha1, 2 MB HTTP/2 window): real Safari on the iOS 17.0.1 and 17.5 simulators",
    ja4: Some("t13d2014h2_a09f3c656075_14788d8d241b"),
    ja3n_hash: Some("44f7ed5185d22c92b96da72dbe68d307"),
    ja3_hash: Some("773906b0efdefa24a7f2b8eb6985bf37"),
    akamai_hash: Some("ad8424af1cc590e09f7b0c499bf7fcdb"),
    akamai_text: Some("2:0;4:2097152;3:100|10485760|0|m,s,p,a"),
    quic_ja4: None,
};

pub(crate) const SAFARI_15_1: Reference = Reference {
    id: "safari-15.1",
    source: "Safari on macOS 15.1 and iOS 18.0-18.1 (ecdsa_sha1, ENABLE_CONNECT_PROTOCOL): real Safari 18.1.1 on macOS 15.1.1 and the iOS 18.0 and 18.1 simulators",
    ja4: Some("t13d2014h2_a09f3c656075_14788d8d241b"),
    ja3n_hash: Some("44f7ed5185d22c92b96da72dbe68d307"),
    ja3_hash: Some("773906b0efdefa24a7f2b8eb6985bf37"),
    akamai_hash: Some("d4a2dcbfde511b5040ed5a5190a8d78b"),
    akamai_text: Some("2:0;3:100;4:2097152;8:1;9:1|10420225|0|m,s,a,p"),
    quic_ja4: None,
};

pub(crate) const SAFARI_15_2: Reference = Reference {
    id: "safari-15.2",
    source: "Safari on macOS 15.2 and iOS 18.2-18.3 (ENABLE_CONNECT_PROTOCOL): real Safari 18.2 on macOS 15.2 and the iOS 18.2 and 18.3.1 simulators",
    ja4: Some("t13d2014h2_a09f3c656075_e42f34c56612"),
    ja3n_hash: Some("44f7ed5185d22c92b96da72dbe68d307"),
    ja3_hash: Some("773906b0efdefa24a7f2b8eb6985bf37"),
    akamai_hash: Some("d4a2dcbfde511b5040ed5a5190a8d78b"),
    akamai_text: Some("2:0;3:100;4:2097152;8:1;9:1|10420225|0|m,s,a,p"),
    quic_ja4: None,
};

pub(crate) const SAFARI_15_4: Reference = Reference {
    id: "safari-15.4",
    source: "Safari on macOS 15.4-15.8 and iOS 18.4-18.5: real Safari 18.4 and 18.5 on macOS 15.4 and 15.5, 18.6 on macOS 15.6.1 and 15.8, 26.0.1 on macOS 15.7, 26.6.1 on macOS 15.7.9, and the iOS 18.4 and 18.5 simulators",
    ja4: Some("t13d2014h2_a09f3c656075_e42f34c56612"),
    ja3n_hash: Some("44f7ed5185d22c92b96da72dbe68d307"),
    ja3_hash: Some("773906b0efdefa24a7f2b8eb6985bf37"),
    akamai_hash: Some("c52879e43202aeb92740be6e8c86ea96"),
    akamai_text: Some("2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p"),
    quic_ja4: None,
};

pub(crate) const SAFARI_26: Reference = Reference {
    id: "safari-26",
    source: "Safari on macOS and iOS 26 and 27 (X25519MLKEM768): real Safari 26.1 to 26.5, 26.6.2 and 27.0 on macOS 26.1 to 27.0, and the iOS 26.0 to 27.0 simulators",
    ja4: Some("t13d2013h2_a09f3c656075_7f0f34a4126d"),
    ja3n_hash: Some("63eaa93caec132011d68ceb96955c1ee"),
    ja3_hash: Some("ecdf4f49dd59effc439639da29186671"),
    akamai_hash: Some("c52879e43202aeb92740be6e8c86ea96"),
    akamai_text: Some("2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p"),
    quic_ja4: None,
};

pub(crate) const SAFARI_QUIC_SHA1: Reference = Reference {
    id: "safari-quic-sha1",
    source: "QUIC JA4 of real Safari 17.6 on macOS 14.6, 18.0 on macOS 14.7 and 15.0, and the iOS 17.0.1 and 17.5 simulators",
    ja4: None,
    ja3n_hash: None,
    ja3_hash: None,
    akamai_hash: None,
    akamai_text: None,
    quic_ja4: Some("q13d0311h3_55b375c5d22e_0e9637bee5d3"),
};

pub(crate) const SAFARI_QUIC: Reference = Reference {
    id: "safari-quic",
    source: "QUIC JA4 of real Safari on macOS 15.2 to 27.0 and the iOS 18.3.1 to 27.0 simulators",
    ja4: None,
    ja3n_hash: None,
    ja3_hash: None,
    akamai_hash: None,
    akamai_text: None,
    quic_ja4: Some("q13d0311h3_55b375c5d22e_f2a83c8e78ae"),
};

pub(crate) const OKHTTP4: Reference = Reference {
    id: "okhttp4",
    source: "OkHttp 4.12.0 (default OkHttpClient) on a Pixel 9 Pro XL with Android 17 (tls.browserleaks.com and ClientHello captures)",
    ja4: Some("t13d1513h2_8daaf6152771_eca864cca44a"),
    ja3n_hash: Some("b6c462146270c94ed8e339bcf4fff25f"),
    ja3_hash: Some("f79b6bad2ad0641e1921aef10262856b"),
    akamai_hash: Some("605a1154008045d7e3cb3c6fb062c0ce"),
    akamai_text: Some("4:16777216|16711681|0|m,p,a,s"),
    quic_ja4: None,
};

pub(crate) const OKHTTP5: Reference = Reference {
    id: "okhttp5",
    source: "OkHttp 5.5.0 (default OkHttpClient) on a Pixel 9 Pro XL with Android 17 (tls.browserleaks.com and ClientHello captures)",
    ja4: Some("t13d1513h2_8daaf6152771_eca864cca44a"),
    ja3n_hash: Some("ab22845823d9af0946cb87050d0a5679"),
    ja3_hash: Some("1d714db2228763eab228fc28ce7f8e4f"),
    akamai_hash: Some("605a1154008045d7e3cb3c6fb062c0ce"),
    akamai_text: Some("4:16777216|16711681|0|m,p,a,s"),
    quic_ja4: None,
};

pub(super) const SERVER_PADDING_VARIANTS: &[(&Reference, &Reference)] = &[
    (&CHROMIUM_MLDSA_TRUST_ANCHORS, &CHROME_SERVER_PADDING),
    (&CHROME_QUIC, &CHROME_QUIC_SERVER_PADDING),
];

pub(super) const COVERAGE: &[Coverage] = &[
    Coverage { browser: Browser::Chrome, from: (131, 0), to: (134, 0), os: &[Os::Windows, Os::MacOS, Os::Linux, Os::Android], reference: &CHROMIUM_OLD_ALPS },
    Coverage { browser: Browser::Edge, from: (131, 0), to: (134, 0), os: &[Os::Windows, Os::MacOS, Os::Android], reference: &CHROMIUM_OLD_ALPS },
    Coverage { browser: Browser::Chrome, from: (135, 0), to: (149, 0), os: &[Os::Windows, Os::MacOS, Os::Linux, Os::Android], reference: &CHROMIUM_NEW_ALPS },
    Coverage { browser: Browser::Edge, from: (135, 0), to: (149, 0), os: &[Os::Windows, Os::MacOS, Os::Android], reference: &CHROMIUM_NEW_ALPS },
    Coverage { browser: Browser::Opera, from: (124, 0), to: (133, 0), os: &[Os::Windows, Os::MacOS, Os::Linux], reference: &CHROMIUM_NEW_ALPS },
    Coverage { browser: Browser::Samsung, from: (29, 0), to: (30, 0), os: &[Os::Android], reference: &CHROMIUM_NEW_ALPS },
    Coverage { browser: Browser::Chrome, from: (152, 0), to: (158, 0), os: &[Os::Windows, Os::MacOS, Os::Linux, Os::Android], reference: &CHROMIUM_MLDSA_TRUST_ANCHORS },
    Coverage { browser: Browser::Opera, from: (136, 0), to: (139, 0), os: &[Os::Windows, Os::MacOS, Os::Linux], reference: &CHROMIUM_MLDSA_TRUST_ANCHORS },
    Coverage { browser: Browser::Chrome, from: (150, 0), to: (151, 0), os: &[Os::Windows, Os::MacOS, Os::Linux, Os::Android], reference: &CHROMIUM_MLDSA },
    Coverage { browser: Browser::Edge, from: (150, 0), to: (157, 0), os: &[Os::Windows, Os::MacOS, Os::Android], reference: &CHROMIUM_MLDSA },
    Coverage { browser: Browser::Opera, from: (134, 0), to: (135, 0), os: &[Os::Windows, Os::MacOS, Os::Linux], reference: &CHROMIUM_MLDSA },
    Coverage { browser: Browser::Brave, from: (153, 0), to: (157, 0), os: &[Os::Windows, Os::MacOS, Os::Linux, Os::Android], reference: &CHROMIUM_MLDSA },
    Coverage { browser: Browser::OperaMobile, from: (102, 0), to: (102, 0), os: &[Os::Android], reference: &OPERA_MOBILE },
    Coverage { browser: Browser::Firefox, from: (135, 0), to: (150, 0), os: &[Os::Windows, Os::MacOS, Os::Linux], reference: &FIREFOX_135 },
    Coverage { browser: Browser::Firefox, from: (151, 0), to: (153, 0), os: &[Os::Windows, Os::MacOS, Os::Linux], reference: &FIREFOX_151 },
    Coverage { browser: Browser::Firefox, from: (154, 0), to: (155, 0), os: &[Os::Windows, Os::MacOS, Os::Linux], reference: &FIREFOX_154 },
    Coverage { browser: Browser::Firefox, from: (156, 0), to: (159, 0), os: &[Os::Windows, Os::MacOS, Os::Linux], reference: &FIREFOX_156 },
    Coverage { browser: Browser::Firefox, from: (146, 0), to: (150, 0), os: &[Os::Android], reference: &FIREFOX_ANDROID_146 },
    Coverage { browser: Browser::Firefox, from: (151, 0), to: (153, 0), os: &[Os::Android], reference: &FIREFOX_ANDROID_151 },
    Coverage { browser: Browser::Firefox, from: (154, 0), to: (154, 0), os: &[Os::Android], reference: &FIREFOX_ANDROID_154 },
    Coverage { browser: Browser::Firefox, from: (155, 0), to: (155, 0), os: &[Os::Android], reference: &FIREFOX_ANDROID_155 },
    Coverage { browser: Browser::Firefox, from: (156, 0), to: (159, 0), os: &[Os::Android], reference: &FIREFOX_ANDROID_156 },
    Coverage { browser: Browser::OkHttp, from: (4, 0), to: (4, 0), os: &[Os::Android], reference: &OKHTTP4 },
    Coverage { browser: Browser::OkHttp, from: (5, 0), to: (5, 0), os: &[Os::Android], reference: &OKHTTP5 },
    Coverage { browser: Browser::Chrome, from: (152, 0), to: (158, 0), os: &[Os::Windows, Os::MacOS, Os::Linux, Os::Android], reference: &CHROME_QUIC },
    Coverage { browser: Browser::Opera, from: (136, 0), to: (139, 0), os: &[Os::Windows, Os::MacOS, Os::Linux], reference: &CHROME_QUIC },
    Coverage { browser: Browser::Chrome, from: (134, 0), to: (134, 0), os: &[Os::Windows, Os::MacOS, Os::Linux, Os::Android], reference: &CHROME_QUIC_OLD_ALPS },
    Coverage { browser: Browser::Chrome, from: (135, 0), to: (151, 0), os: &[Os::Windows, Os::MacOS, Os::Linux, Os::Android], reference: &CHROMIUM_QUIC_NO_TRUST_ANCHORS },
    Coverage { browser: Browser::Edge, from: (153, 0), to: (157, 0), os: &[Os::Windows, Os::MacOS, Os::Android], reference: &CHROMIUM_QUIC_NO_TRUST_ANCHORS },
    Coverage { browser: Browser::Brave, from: (153, 0), to: (157, 0), os: &[Os::Windows, Os::MacOS, Os::Linux, Os::Android], reference: &CHROMIUM_QUIC_NO_TRUST_ANCHORS },
    Coverage { browser: Browser::OperaMobile, from: (102, 0), to: (102, 0), os: &[Os::Android], reference: &CHROMIUM_QUIC_NO_TRUST_ANCHORS },
    Coverage { browser: Browser::Firefox, from: (155, 0), to: (155, 0), os: &[Os::Windows, Os::MacOS, Os::Linux], reference: &FIREFOX_QUIC },
    Coverage { browser: Browser::Firefox, from: (157, 0), to: (159, 0), os: &[Os::Windows, Os::MacOS, Os::Linux], reference: &FIREFOX_QUIC },
    Coverage { browser: Browser::Firefox, from: (146, 0), to: (155, 0), os: &[Os::Android], reference: &FIREFOX_QUIC },
    Coverage { browser: Browser::Firefox, from: (157, 0), to: (159, 0), os: &[Os::Android], reference: &FIREFOX_QUIC },
    Coverage { browser: Browser::Firefox, from: (156, 0), to: (156, 0), os: &[Os::Windows, Os::MacOS, Os::Linux], reference: &FIREFOX_156_QUIC },
    Coverage { browser: Browser::Firefox, from: (156, 0), to: (156, 0), os: &[Os::Android], reference: &FIREFOX_156_QUIC },
];

use super::{IosProfile, SafariVersion, derived, IOS_16, IOS_16_4, IOS_17, IOS_18_0, IOS_18_1, IOS_18_2, IOS_18_3, IOS_18_4, IOS_18_5, IOS_26_0, IOS_26_1, IOS_26_2, IOS_26_3, IOS_26_4, IOS_26_5, IOS_27, MACOS_12, MACOS_13, MACOS_13_6, MACOS_14, MACOS_15_0, MACOS_15_1, MACOS_15_2, MACOS_15_3, MACOS_15_4, MACOS_15_5, MACOS_26, MACOS_26_0, MACOS_26_1, MACOS_26_2, MACOS_26_3, MACOS_26_4, MACOS_26_5, MACOS_27};

/// Every supported Safari version, oldest first: the resolver, its error messages and the CLI's profile listing read it.
pub const SAFARI_VERSIONS: &[SafariVersion] = &[
    SafariVersion { tag: "156", version: "15.6", ios: None, macos_ua_version: "15.6", fetch_metadata: false, macos: MACOS_12 },
    SafariVersion { tag: "160", version: "16.0", ios: Some(IosProfile { ua_os: "16_0", release: IOS_16 }), macos_ua_version: "16.0", fetch_metadata: false, macos: MACOS_12 },
    SafariVersion { tag: "161", version: "16.1", ios: Some(IosProfile { ua_os: "16_1", release: IOS_16 }), macos_ua_version: "16.1", fetch_metadata: false, macos: MACOS_13 },
    SafariVersion { tag: "166", version: "16.6", ios: Some(IosProfile { ua_os: "16_6", release: derived(IOS_16_4) }), macos_ua_version: "16.6", fetch_metadata: true, macos: MACOS_13_6 },
    SafariVersion { tag: "170", version: "17.0", ios: Some(IosProfile { ua_os: "17_0", release: IOS_17 }), macos_ua_version: "17.0", fetch_metadata: true, macos: MACOS_14 },
    SafariVersion { tag: "176", version: "17.6", ios: Some(IosProfile { ua_os: "17_6", release: derived(IOS_17) }), macos_ua_version: "17.6", fetch_metadata: true, macos: MACOS_14 },
    SafariVersion { tag: "180", version: "18.0", ios: Some(IosProfile { ua_os: "18_0", release: IOS_18_0 }), macos_ua_version: "18.0", fetch_metadata: true, macos: MACOS_15_0 },
    SafariVersion { tag: "181", version: "18.1", ios: Some(IosProfile { ua_os: "18_1", release: IOS_18_1 }), macos_ua_version: "18.1.1", fetch_metadata: true, macos: MACOS_15_1 },
    SafariVersion { tag: "182", version: "18.2", ios: Some(IosProfile { ua_os: "18_2", release: IOS_18_2 }), macos_ua_version: "18.2", fetch_metadata: true, macos: MACOS_15_2 },
    SafariVersion { tag: "183", version: "18.3", ios: Some(IosProfile { ua_os: "18_3", release: IOS_18_3 }), macos_ua_version: "18.3", fetch_metadata: true, macos: MACOS_15_3 },
    SafariVersion { tag: "184", version: "18.4", ios: Some(IosProfile { ua_os: "18_4", release: IOS_18_4 }), macos_ua_version: "18.4", fetch_metadata: true, macos: MACOS_15_4 },
    SafariVersion { tag: "185", version: "18.5", ios: Some(IosProfile { ua_os: "18_5", release: IOS_18_5 }), macos_ua_version: "18.5", fetch_metadata: true, macos: MACOS_15_5 },
    SafariVersion { tag: "186", version: "18.6", ios: Some(IosProfile { ua_os: "18_6", release: derived(IOS_18_5) }), macos_ua_version: "18.6", fetch_metadata: true, macos: MACOS_15_5 },
    SafariVersion { tag: "260", version: "26.0", ios: Some(IosProfile { ua_os: "18_6", release: IOS_26_0 }), macos_ua_version: "26.0", fetch_metadata: true, macos: MACOS_26_0 },
    SafariVersion { tag: "261", version: "26.1", ios: Some(IosProfile { ua_os: "18_7", release: IOS_26_1 }), macos_ua_version: "26.1", fetch_metadata: true, macos: MACOS_26_1 },
    SafariVersion { tag: "262", version: "26.2", ios: Some(IosProfile { ua_os: "18_7", release: IOS_26_2 }), macos_ua_version: "26.2", fetch_metadata: true, macos: MACOS_26_2 },
    SafariVersion { tag: "263", version: "26.3", ios: Some(IosProfile { ua_os: "18_7", release: IOS_26_3 }), macos_ua_version: "26.3", fetch_metadata: true, macos: MACOS_26_3 },
    SafariVersion { tag: "264", version: "26.4", ios: Some(IosProfile { ua_os: "18_7", release: IOS_26_4 }), macos_ua_version: "26.4", fetch_metadata: true, macos: MACOS_26_4 },
    SafariVersion { tag: "265", version: "26.5", ios: Some(IosProfile { ua_os: "18_7", release: IOS_26_5 }), macos_ua_version: "26.5", fetch_metadata: true, macos: MACOS_26_5 },
    SafariVersion { tag: "266", version: "26.6", ios: Some(IosProfile { ua_os: "18_7", release: derived(MACOS_26) }), macos_ua_version: "26.6.2", fetch_metadata: true, macos: MACOS_26 },
    SafariVersion { tag: "270", version: "27.0", ios: Some(IosProfile { ua_os: "18_7", release: IOS_27 }), macos_ua_version: "27.0", fetch_metadata: true, macos: MACOS_27 },
];

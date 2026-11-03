use crate::profile::Os;

const CHROMIUM_JXL_VERSION: u32 = 155;

pub(super) fn chromium_navigation_accept(chromium_major: u32) -> String {
    let jxl = if chromium_major >= CHROMIUM_JXL_VERSION {
        "image/jxl,"
    } else {
        ""
    };
    format!(
        "text/html,application/xhtml+xml,application/xml;q=0.9,{jxl}image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
    )
}

pub struct ChromiumHeaders<'a> {
    pub os: Os,
    pub chromium_major: u32,
    pub brand: &'a str,
    pub brand_major: u32,
    pub ua_product: &'a str,
}

pub fn chromium_headers(params: ChromiumHeaders<'_>) -> Vec<(String, String)> {
    let ChromiumHeaders {
        os,
        chromium_major,
        brand,
        brand_major,
        ua_product,
    } = params;
    let (platform, ua_os) = match os {
        Os::Windows => ("\"Windows\"", "Windows NT 10.0; Win64; x64"),
        Os::MacOS => ("\"macOS\"", "Macintosh; Intel Mac OS X 10_15_7"),
        Os::Linux => ("\"Linux\"", "X11; Linux x86_64"),
        Os::Android => ("\"Android\"", "Linux; Android 10; K"),
        Os::Ios => unreachable!("no Chromium profile for iOS"),
    };
    let mobile = os == Os::Android;
    let safari = if mobile {
        "Mobile Safari/537.36"
    } else {
        "Safari/537.36"
    };
    let user_agent = format!(
        "Mozilla/5.0 ({ua_os}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chromium_major}.0.0.0 {safari}{ua_product}"
    );
    vec![
        (
            "sec-ch-ua".into(),
            chromium_sec_ch_ua(chromium_major, brand, brand_major),
        ),
        (
            "sec-ch-ua-mobile".into(),
            if mobile { "?1" } else { "?0" }.into(),
        ),
        ("sec-ch-ua-platform".into(), platform.into()),
        ("upgrade-insecure-requests".into(), "1".into()),
        ("user-agent".into(), user_agent),
        ("accept".into(), chromium_navigation_accept(chromium_major)),
        ("sec-fetch-site".into(), "none".into()),
        ("sec-fetch-mode".into(), "navigate".into()),
        ("sec-fetch-user".into(), "?1".into()),
        ("sec-fetch-dest".into(), "document".into()),
        ("accept-encoding".into(), "gzip, deflate, br, zstd".into()),
        ("accept-language".into(), "en-US,en;q=0.9".into()),
        ("priority".into(), "u=0, i".into()),
    ]
}

fn chromium_sec_ch_ua(chromium_major: u32, brand: &str, brand_major: u32) -> String {
    chromium_brand_list(
        chromium_major,
        brand,
        &brand_major.to_string(),
        &chromium_major.to_string(),
        BrandListKind::Short,
    )
}

pub fn set_header(headers: &mut [(String, String)], name: &str, value: impl Into<String>) {
    if let Some((_, v)) = headers.iter_mut().find(|(k, _)| k == name) {
        *v = value.into();
    }
}

pub const CHROMIUM_ACCEPT_ENCODING_NO_ZSTD: &str = "gzip, deflate, br";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BrandListKind {
    Short,
    Full,
}

pub fn chromium_brand_list(
    chromium_major: u32,
    brand: &str,
    brand_version: &str,
    chromium_version: &str,
    kind: BrandListKind,
) -> String {
    const GREASE_CHARS: [char; 11] = [' ', '(', ':', '-', '.', '/', ')', ';', '=', '?', '_'];
    const GREASE_VERSIONS: [&str; 3] = ["8", "99", "24"];
    const ORDERS: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];

    let seed = chromium_major as usize;
    let grease_brand = format!(
        "Not{}A{}Brand",
        GREASE_CHARS[seed % 11],
        GREASE_CHARS[(seed + 1) % 11]
    );
    let grease_version = GREASE_VERSIONS[seed % 3];
    let grease_version = if kind == BrandListKind::Full {
        format!("{grease_version}.0.0.0")
    } else {
        grease_version.to_string()
    };
    let order = ORDERS[seed % 6];

    let items: [String; 3] = [
        format!("\"{grease_brand}\";v=\"{grease_version}\""),
        format!("\"Chromium\";v=\"{chromium_version}\""),
        format!("\"{brand}\";v=\"{brand_version}\""),
    ];

    let mut shuffled: [&str; 3] = [""; 3];
    for i in 0..3 {
        shuffled[order[i]] = &items[i];
    }

    format!("{}, {}, {}", shuffled[0], shuffled[1], shuffled[2])
}

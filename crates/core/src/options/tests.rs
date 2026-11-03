use super::*;

fn options(
    scope: Scope,
    target: Target,
    pairs: Vec<(&str, Value)>,
) -> Result<Options, OptionError> {
    let mut options = Options::new(scope, target);
    for (key, value) in pairs {
        options.set(key, value)?;
    }
    Ok(options)
}

fn message(result: Result<Options, OptionError>) -> String {
    match result {
        Ok(_) => panic!("accepted"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn an_unknown_key_suggests_the_targets_spelling() {
    let node = options(
        Scope::Client,
        Target::Node,
        vec![("max_redirects", Value::Int(3))],
    );
    assert_eq!(
        message(node),
        "unknown option 'max_redirects' (did you mean 'maxRedirects'?)"
    );
    let python = options(
        Scope::Client,
        Target::Python,
        vec![("maxRedirects", Value::Int(3))],
    );
    assert_eq!(
        message(python),
        "unknown option 'maxRedirects' (did you mean 'max_redirects'?)"
    );
    let typo = options(
        Scope::Client,
        Target::Python,
        vec![("folow", Value::Bool(true))],
    );
    assert_eq!(message(typo), "unknown option 'folow'");
}

#[test]
fn an_option_of_another_scope_is_unknown() {
    let result = options(
        Scope::Request,
        Target::Node,
        vec![("cookieJar", Value::Bool(false))],
    );
    assert!(matches!(result, Err(OptionError::Unknown(_))));
    let result = options(
        Scope::Client,
        Target::Node,
        vec![("decode", Value::Bool(false))],
    );
    assert!(matches!(result, Err(OptionError::Unknown(_))));
    assert!(
        options(
            Scope::Stream,
            Target::Node,
            vec![("decode", Value::Bool(false))]
        )
        .is_ok()
    );
}

#[test]
fn null_keeps_the_default() {
    let options = options(
        Scope::Stream,
        Target::Python,
        vec![("decode", Value::Null), ("timeout", Value::Null)],
    )
    .unwrap();
    assert!(options.decode());
    assert!(options.request_options().timeout.is_none());
}

#[test]
fn counts_take_whole_numbers_of_either_type() {
    let ok = options(
        Scope::Client,
        Target::Node,
        vec![("maxRedirects", Value::Float(4.0))],
    )
    .unwrap();
    assert_eq!(ok.max_redirects, Some(4));
    let fraction = options(
        Scope::Client,
        Target::Node,
        vec![("maxRedirects", Value::Float(1.5))],
    );
    assert_eq!(
        message(fraction),
        "maxRedirects must be a whole number >= 0, not 1.5"
    );
    let negative = options(
        Scope::Client,
        Target::Python,
        vec![("retries", Value::Int(-1))],
    );
    assert!(matches!(
        negative,
        Err(OptionError::Invalid(Error::InvalidArgument(..)))
    ));
    let too_large = options(
        Scope::Client,
        Target::R,
        vec![("retries", Value::Int(1 << 40))],
    );
    assert_eq!(message(too_large), "retries is too large: 1099511627776");
    let text = options(
        Scope::Client,
        Target::Python,
        vec![("retries", Value::Text("3".into()))],
    );
    assert!(matches!(text, Err(OptionError::Type(_))));
}

#[test]
fn a_bool_is_named_as_the_target_writes_it() {
    let r = options(
        Scope::Client,
        Target::R,
        vec![("cookie_jar", Value::Int(1))],
    );
    assert_eq!(message(r), "cookie_jar must be TRUE or FALSE");
    let python = options(
        Scope::Client,
        Target::Python,
        vec![("cookie_jar", Value::Int(1))],
    );
    assert_eq!(message(python), "cookie_jar must be True or False");
}

#[test]
fn ip_version_takes_numbers_and_names() {
    for value in [
        Value::Int(4),
        Value::Float(4.0),
        Value::Text("v4".into()),
        Value::Text("IPv4".into()),
    ] {
        let options = options(Scope::Client, Target::Node, vec![("ipVersion", value)]).unwrap();
        assert_eq!(options.connection.ip_version, Some(IpVersion::V4));
    }
    let six = options(
        Scope::Client,
        Target::R,
        vec![("ip_version", Value::Text("ipv6".into()))],
    );
    assert_eq!(six.unwrap().connection.ip_version, Some(IpVersion::V6));
    let five = options(
        Scope::Client,
        Target::Node,
        vec![("ipVersion", Value::Int(5))],
    );
    assert!(matches!(five, Err(OptionError::Invalid(_))));
}

#[test]
fn a_single_string_and_a_list_of_one_convert_into_each_other() {
    let options = options(
        Scope::Client,
        Target::R,
        vec![
            ("proxies", Value::Text("http://127.0.0.1:1".into())),
            ("locale", Value::Texts(vec!["de-AT".into()])),
        ],
    )
    .unwrap();
    assert_eq!(options.connection.proxies, ["http://127.0.0.1:1"]);
    assert_eq!(options.connection.locale.as_deref(), Some("de-AT"));
}

#[test]
fn pem_lines_are_joined() {
    let options = options(
        Scope::Client,
        Target::R,
        vec![("proxy_ca_certs", Value::Texts(vec!["a".into(), "b".into()]))],
    )
    .unwrap();
    assert_eq!(
        options.connection.proxy_ca_certs.as_deref(),
        Some(&b"a\nb"[..])
    );
}

#[test]
fn auth_takes_each_bindings_form() {
    let forms = [
        (
            Target::Python,
            Value::Texts(vec!["user".into(), "pass".into()]),
        ),
        (Target::Cli, Value::Text("user:pass".into())),
        (
            Target::Node,
            Value::Pairs(vec![
                ("username".into(), "user".into()),
                ("password".into(), "pass".into()),
            ]),
        ),
    ];
    for (target, value) in forms {
        let key = OPTIONS
            .iter()
            .find(|s| s.name == "auth")
            .unwrap()
            .key(target);
        let auth = options(Scope::Proxy, target, vec![(&key, value)])
            .unwrap()
            .auth
            .unwrap();
        assert_eq!(
            (auth.username.as_str(), auth.password.as_str()),
            ("user", "pass")
        );
    }
}

#[test]
fn the_request_proxy_is_not_the_clients() {
    let request = options(
        Scope::Request,
        Target::Node,
        vec![("proxy", Value::Text("http://127.0.0.1:1".into()))],
    )
    .unwrap();
    assert_eq!(
        request.request_options().proxy.as_deref(),
        Some("http://127.0.0.1:1")
    );
}

#[test]
fn proxy_options_build_the_proxy_config() {
    let config = options(
        Scope::Proxy,
        Target::Python,
        vec![
            ("header_mode", Value::Text("PassThrough".into())),
            ("max_connections", Value::Int(8)),
        ],
    )
    .unwrap()
    .proxy_config()
    .unwrap();
    assert_eq!(config.header_mode, HeaderMode::Passthrough);
    assert_eq!(config.max_connections, 8);
    assert_eq!(config.listen_addr, "127.0.0.1:0");
}

#[test]
fn every_name_and_scope_is_unique_and_settable() {
    for scope in [
        Scope::Client,
        Scope::Request,
        Scope::Stream,
        Scope::Proxy,
        Scope::Verify,
    ] {
        let mut seen = std::collections::HashSet::new();
        for spec in options_in(scope) {
            assert!(seen.insert(spec.name), "{} twice in {scope:?}", spec.name);
            let mut options = Options::new(scope, Target::Python);
            options.set_option(spec, Value::Null).unwrap();
        }
    }
}

#[test]
fn documented_defaults_match_the_proxy_config() {
    let config = ProxyServerConfig::default();
    for spec in options_in(Scope::Proxy) {
        let documented = match spec.name {
            "listen_addr" => {
                DefaultValue::Text(Box::leak(config.listen_addr.clone().into_boxed_str()))
            }
            "header_mode" => DefaultValue::Text("impersonate"),
            "allow_non_loopback" => DefaultValue::Bool(config.allow_non_loopback),
            "max_connections" => DefaultValue::Number(Box::leak(
                config.max_connections.to_string().into_boxed_str(),
            )),
            _ => continue,
        };
        assert_eq!(spec.default, Some(documented), "{}", spec.name);
    }
    assert_eq!(config.header_mode, HeaderMode::Impersonate);
}

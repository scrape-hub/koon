//! The flags of the core's option table (`koon_core::options::OPTIONS`) for one command: their
//! names, help, defaults and value checks all come from the table.

use std::marker::PhantomData;

use clap::{Arg, ArgAction, ArgMatches, Args, Command, FromArgMatches};
use koon_core::options::{
    CliFlag, CliForm, DefaultValue, Kind, OptionSpec, Options, Scope, Target, Value, options_in,
    render,
};

use crate::{CliError, parse_header, read_file, redact_proxy_url};

/// The scope of a command, and the options of it the command takes as flags of its own.
pub trait FlagScope {
    const SCOPE: Scope;
    const OWN: &'static [&'static str] = &[];
}

pub struct RequestFlags;
pub struct ProxyFlags;
pub struct VerifyFlags;

impl FlagScope for RequestFlags {
    const SCOPE: Scope = Scope::Client;
}

impl FlagScope for ProxyFlags {
    const SCOPE: Scope = Scope::Proxy;
}

impl FlagScope for VerifyFlags {
    const SCOPE: Scope = Scope::Verify;
    const OWN: &'static [&'static str] = &["browser"];
}

/// The table's flags given on the command line, in table order, as given.
pub struct TableArgs<S> {
    given: Vec<(&'static OptionSpec, Given)>,
    scope: PhantomData<S>,
}

enum Given {
    Switch,
    One(String),
    Many(Vec<String>),
}

fn flags<S: FlagScope>() -> impl Iterator<Item = (&'static OptionSpec, CliFlag)> {
    options_in(S::SCOPE)
        .filter(|spec| !S::OWN.contains(&spec.name))
        .filter_map(|spec| spec.cli.map(|flag| (spec, flag)))
}

/// One value of a flag as the core's option [`Value`]; numbers are parsed here, everything else
/// is checked by the core.
fn flag_value(kind: Kind, raw: &str) -> Result<Value, String> {
    match kind {
        Kind::Count | Kind::Size | Kind::Seconds => raw
            .trim()
            .parse::<f64>()
            .map(Value::Float)
            .map_err(|_| format!("'{raw}' is not a number")),
        Kind::Headers => parse_header(raw).map(|pair| Value::Pairs(vec![pair])),
        _ => Ok(Value::Text(raw.to_string())),
    }
}

/// Checks one value as the core takes it, so that clap rejects an invalid one with exit code 2.
fn check(spec: &'static OptionSpec, scope: Scope, raw: &str) -> Result<String, String> {
    let value = flag_value(spec.kind, raw)?;
    Options::new(scope, Target::Cli)
        .set_option(spec, value)
        .map(|()| raw.to_string())
        .map_err(|e| e.to_string())
}

fn help(spec: &OptionSpec, flag: CliFlag) -> (String, String) {
    let doc = match flag.form {
        CliForm::Off(text) => text.to_string(),
        _ => render(spec.doc, Target::Cli),
    };
    let summary = doc
        .split_once(". ")
        .map_or(doc.trim_end_matches('.'), |(first, _)| first)
        .to_string();
    let default = match (flag.form, spec.default) {
        (
            CliForm::Value,
            Some(DefaultValue::Number(n) | DefaultValue::Text(n) | DefaultValue::Words(n)),
        ) => {
            format!(" [default: {n}]")
        }
        _ => String::new(),
    };
    (format!("{summary}{default}"), format!("{doc}{default}"))
}

fn arg<S: FlagScope>(spec: &'static OptionSpec, flag: CliFlag) -> Arg {
    let (summary, long) = help(spec, flag);
    let mut arg = Arg::new(spec.name)
        .long(flag.long)
        .help(summary)
        .long_help(long);
    if let Some(short) = flag.short {
        arg = arg.short(short);
    }
    let checked = move |raw: &str| check(spec, S::SCOPE, raw);
    match flag.form {
        CliForm::Switch | CliForm::Off(_) => arg.action(ArgAction::SetTrue),
        CliForm::Value => arg
            .value_name(flag.value_name)
            .action(ArgAction::Set)
            .value_parser(checked),
        CliForm::File => arg.value_name(flag.value_name).action(ArgAction::Set),
        CliForm::Repeated => arg
            .value_name(flag.value_name)
            .action(ArgAction::Append)
            .value_parser(checked),
        CliForm::List => arg
            .value_name(flag.value_name)
            .action(ArgAction::Append)
            .value_delimiter(',')
            .value_parser(checked),
    }
}

impl<S: FlagScope> Args for TableArgs<S> {
    fn augment_args(cmd: Command) -> Command {
        flags::<S>().fold(cmd, |cmd, (spec, flag)| cmd.arg(arg::<S>(spec, flag)))
    }

    fn augment_args_for_update(cmd: Command) -> Command {
        Self::augment_args(cmd)
    }
}

impl<S: FlagScope> FromArgMatches for TableArgs<S> {
    fn from_arg_matches(matches: &ArgMatches) -> Result<Self, clap::Error> {
        let given = flags::<S>()
            .filter_map(|(spec, flag)| {
                let given = match flag.form {
                    CliForm::Switch | CliForm::Off(_) => {
                        matches.get_flag(spec.name).then_some(Given::Switch)
                    }
                    CliForm::Value | CliForm::File => matches
                        .get_one::<String>(spec.name)
                        .cloned()
                        .map(Given::One),
                    CliForm::Repeated | CliForm::List => matches
                        .get_many::<String>(spec.name)
                        .map(|values| Given::Many(values.cloned().collect())),
                }?;
                Some((spec, given))
            })
            .collect();
        Ok(Self {
            given,
            scope: PhantomData,
        })
    }

    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), clap::Error> {
        *self = Self::from_arg_matches(matches)?;
        Ok(())
    }
}

impl<S: FlagScope> TableArgs<S> {
    /// The options given, files read.
    pub fn options(&self) -> Result<Options, CliError> {
        let mut options = Options::new(S::SCOPE, Target::Cli);
        for (spec, given) in &self.given {
            let flag = spec.cli.expect("a flag of the table");
            let value = match (flag.form, given) {
                (CliForm::Switch, _) => Value::Bool(true),
                (CliForm::Off(_), _) => Value::Bool(false),
                (CliForm::File, Given::One(path)) => {
                    let bytes = read_file(path)?;
                    match spec.kind {
                        Kind::ProfileJson => {
                            Value::Text(String::from_utf8(bytes).map_err(|_| {
                                CliError::other(format!("Failed to read '{path}': not UTF-8"))
                            })?)
                        }
                        _ => Value::Bytes(bytes),
                    }
                }
                (_, Given::One(raw)) => flag_value(spec.kind, raw).map_err(usage)?,
                (_, Given::Many(raws)) if spec.kind == Kind::Headers => Value::Pairs(
                    raws.iter()
                        .map(|raw| parse_header(raw))
                        .collect::<Result<_, _>>()
                        .map_err(usage)?,
                ),
                (_, Given::Many(raws)) => Value::Texts(raws.clone()),
                (_, Given::Switch) => unreachable!("a switch has no value"),
            };
            options
                .set_option(spec, value)
                .map_err(|e| CliError::from(koon_core::Error::from(e)))?;
        }
        Ok(options)
    }

    /// Report the connection options given to stderr, one `* ` line each, with proxy credentials
    /// masked.
    pub fn print_settings(&self) {
        for (spec, given) in &self.given {
            let one = match given {
                Given::One(raw) => raw.as_str(),
                _ => "",
            };
            let many = match given {
                Given::Many(raws) => raws.as_slice(),
                _ => &[],
            };
            match spec.name {
                "proxy" => eprintln!("* Proxy: {}", redact_proxy_url(one)),
                "proxies" => {
                    let proxies: Vec<_> = many.iter().map(|p| redact_proxy_url(p)).collect();
                    eprintln!("* Proxies: {} (round-robin)", proxies.join(", "));
                }
                "doh" => eprintln!("* DoH: {one}"),
                "locale" => eprintln!("* Locale: {one}"),
                "local_address" => eprintln!("* Local address: {one}"),
                "ip_version" => eprintln!("* IP version: {one}"),
                "resolve" => many
                    .iter()
                    .for_each(|entry| eprintln!("* Resolve: {entry}")),
                "retries" => eprintln!("* Retries: {one}"),
                "ignore_tls_errors" => eprintln!("* TLS verification: disabled"),
                "proxy_ca_certs" => eprintln!("* Proxy CA certificates: {one}"),
                "ignore_proxy_tls_errors" => eprintln!("* Proxy TLS verification: disabled"),
                "max_response_body" if one.trim() == "0" => {
                    eprintln!("* Max response body: unlimited");
                }
                "max_response_body" => eprintln!("* Max response body: {one} bytes"),
                "server_padding" => eprintln!("* Server padding: {one}"),
                _ => {}
            }
        }
    }
}

fn usage(message: String) -> CliError {
    CliError {
        message,
        exit_code: 2,
    }
}

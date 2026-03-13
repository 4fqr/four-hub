


use four_hub::config::AppConfig;
use four_hub::db::Severity;
use four_hub::tools::{
    parser,
    registry::ToolRegistry,
    spec::ToolSpec,
};


fn make_spec(name: &str, binary: &str, args: Vec<&str>, proxychains: bool) -> ToolSpec {
    ToolSpec {
        name:         name.to_owned(),
        binary:       binary.to_owned(),
        description:  String::new(),
        category:     "Test".to_owned(),
        default_args: args.into_iter().map(|s| s.to_owned()).collect(),
        wrapper:      None,
        needs_root:   false,
        proxychains,
        interactive:  false,
        tags:         vec![],
    }
}

#[test]
fn spec_build_argv_target_substitution() {
    let spec = make_spec("nmap", "nmap", vec!["-sV", "-p-", "{target}"], false);

    let argv = spec.build_argv("192.168.1.5", "", false);
    assert_eq!(argv.last().map(|s| s.as_str()), Some("192.168.1.5"),
               "target placeholder must be replaced");
    assert!(!argv.iter().any(|a| a == "{target}"),
            "no raw placeholders should remain");
}

#[test]
fn spec_build_argv_proxychains_prefix() {
    let spec = make_spec("test-tool", "mytool", vec!["--target", "{target}"], true);

    let argv = spec.build_argv("example.com", "proxychains4", true);
    assert_eq!(argv[0], "proxychains4", "proxychains must be first arg");
    assert_eq!(argv[1], "mytool",       "binary must follow proxychains");
}

#[test]
fn parser_nmap_open_port_line() {
    let spec    = make_spec("nmap", "nmap", vec![], false);
    let line    = "22/tcp   open  ssh      OpenSSH 9.3 (protocol 2.0)";
    let results = parser::parse_line(&spec, line, "10.0.0.1");

    assert!(!results.is_empty(), "should extract at least one finding");
    let finding = &results[0];
    assert_eq!(finding.tool, "nmap");
    assert!(finding.title.contains("22"), "port number must appear in title");
}

#[test]
fn parser_hydra_credential_line() {
    let spec    = make_spec("hydra", "hydra", vec![], false);
    let line    = "[22][ssh] host: 10.0.0.5   login: root   password: toor";
    let results = parser::parse_line(&spec, line, "10.0.0.5");

    assert!(!results.is_empty());
    assert!(results[0].description.contains("root"));
    assert!(results[0].description.contains("toor"));
}

#[test]
fn parser_gobuster_directory_line() {
    let spec    = make_spec("gobuster", "gobuster", vec![], false);
    let line    = "/admin                (Status: 200) [Size: 4321]";
    let results = parser::parse_line(&spec, line, "http://10.0.0.1");

    assert!(!results.is_empty());
    assert!(
        results[0].severity == Severity::High || results[0].severity == Severity::Medium,
        "admin path should be at least medium severity"
    );
}

#[test]
fn parser_unknown_tool_returns_empty() {
    let spec    = make_spec("unknown-tool-xyz", "unknown-tool-xyz", vec![], false);
    let results = parser::parse_line(&spec, "some output line", "target");
    assert!(results.is_empty(), "unknown tool must return no findings");
}

#[tokio::test]
async fn registry_loads_builtin_tools() {
    let cfg      = AppConfig::default();
    let registry = ToolRegistry::load(&cfg).await.expect("load registry");
    let all      = registry.all_tools();

    assert!(!all.is_empty(), "registry must contain built-in tools");
    assert!(all.iter().any(|t| t.name == "nmap"),     "nmap must be present");
    assert!(all.iter().any(|t| t.name == "nikto"),    "nikto must be present");
    assert!(all.iter().any(|t| t.name == "hydra"),    "hydra must be present");
    assert!(all.iter().any(|t| t.name == "sqlmap"),   "sqlmap must be present");
}

#[tokio::test]
async fn registry_category_names_non_empty() {
    let cfg      = AppConfig::default();
    let registry = ToolRegistry::load(&cfg).await.unwrap();
    let cats     = registry.category_names();

    assert!(!cats.is_empty(), "at least one category must exist");
    assert!(cats.iter().any(|c| c == "Recon"), "Recon category must exist");
}

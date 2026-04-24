pub struct Alias {
    pub name: &'static str,
    pub repo: &'static str,
    pub binaries: &'static [&'static str],
    pub asset_hint: Option<&'static str>,
}

pub const ALIASES: &[Alias] = &[
    Alias {
        name: "uv",
        repo: "astral-sh/uv",
        binaries: &["uv", "uvx"],
        asset_hint: Some("musl"),
    },
    Alias {
        name: "pandoc",
        repo: "jgm/pandoc",
        binaries: &["pandoc"],
        asset_hint: None,
    },
    Alias {
        name: "tectonic",
        repo: "tectonic-typesetting/tectonic",
        binaries: &["tectonic"],
        asset_hint: Some("musl"),
    },
    Alias {
        name: "ripgrep",
        repo: "BurntSushi/ripgrep",
        binaries: &["rg"],
        asset_hint: Some("musl"),
    },
    Alias {
        name: "fd",
        repo: "sharkdp/fd",
        binaries: &["fd"],
        asset_hint: Some("musl"),
    },
    Alias {
        name: "ghp",
        repo: "malbarbo/ghp",
        binaries: &["ghp"],
        asset_hint: None,
    },
];

pub fn lookup(name: &str) -> Option<&'static Alias> {
    ALIASES.iter().find(|a| a.name == name)
}

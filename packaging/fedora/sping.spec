# Application spec using the Fedora cargo RPM macros (cargo-rpm-macros).
# Dependencies are resolved from the bundled Cargo.lock; for an official
# Fedora review the crates would instead be pulled from packaged rust-*-devel.
%global crate sping

Name:           sping
Version:        1.5.3
Release:        %autorelease
Summary:        Terminal-native real-time connectivity monitor with network context diagnostics

License:        MIT
URL:            https://github.com/LambdaBytes/sping
Source:         %{url}/archive/refs/tags/v%{version}.tar.gz#/sping-%{version}.tar.gz

BuildRequires:  cargo-rpm-macros >= 24

%global _description %{expand:
sping is a terminal-native real-time connectivity monitor written in Rust. It
interprets network context - not just RTT and packet loss - and produces
quality grades, trend hysteresis, spike detection and outage timing. On Linux
it uses unprivileged datagram ICMP sockets, so no special privileges are
required for the common case.}

%description %{_description}

%prep
%autosetup -n sping-%{version} -p1
%cargo_prep

%build
%cargo_build
# build.rs renders the man page and shell completions during the build; locate
# them afterwards (the cargo target dir layout varies between macro versions).
man=$(find target -path '*assets*' -name sping.1 | head -n1)
cp "$man" sping.1
bash=$(find target -path '*assets*' -name sping.bash | head -n1); cp "$bash" sping.bash
zsh=$(find target -path '*assets*' -name _sping | head -n1);     cp "$zsh"  _sping
fish=$(find target -path '*assets*' -name sping.fish | head -n1); cp "$fish" sping.fish

%install
%cargo_install
install -Dpm0644 sping.1   %{buildroot}%{_mandir}/man1/sping.1
install -Dpm0644 sping.bash %{buildroot}%{_datadir}/bash-completion/completions/sping
install -Dpm0644 _sping     %{buildroot}%{_datadir}/zsh/site-functions/_sping
install -Dpm0644 sping.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/sping.fish

%check
%cargo_test

%files
%license LICENSE
%doc README.md CHANGELOG.md
%{_bindir}/sping
%{_mandir}/man1/sping.1*
%{_datadir}/bash-completion/completions/sping
%{_datadir}/zsh/site-functions/_sping
%{_datadir}/fish/vendor_completions.d/sping.fish

%changelog
%autochangelog

# Homebrew formula for sping. .github/workflows/publish.yml renders it when a
# release is published (@REPOSITORY@, @VERSION@ and @SHA256@ are that
# release's) and writes it to the tap, <owner>/homebrew-tap.
#
# The source is the tag's archive. GitHub keeps its contents, not
# necessarily its compressed bytes: if the checksum ever stops matching, the
# formula needs the new one.
class Sping < Formula
  desc "Terminal-native real-time connectivity monitor"
  homepage "https://github.com/@REPOSITORY@"
  url "https://github.com/@REPOSITORY@/archive/refs/tags/v@VERSION@.tar.gz"
  sha256 "@SHA256@"
  license "MIT"

  depends_on "rust" => :build

  def install
    # build.rs writes the man page and the shell completions here.
    ENV["SPING_ASSETS_DIR"] = (buildpath/"assets").to_s
    system "cargo", "install", *std_cargo_args
    man1.install "assets/man/sping.1"
    bash_completion.install "assets/completions/sping.bash" => "sping"
    zsh_completion.install "assets/completions/_sping"
    fish_completion.install "assets/completions/sping.fish"
  end

  test do
    assert_match "sping #{version}", shell_output("#{bin}/sping --version")
  end
end

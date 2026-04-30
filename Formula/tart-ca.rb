class TartCa < Formula
  desc "Tart fork with TART_EXTRA_CA_CERTS support for private/internal OCI registries"
  homepage "https://github.com/Operationrange/tart-ca"
  url "https://github.com/Operationrange/tart-ca/archive/refs/tags/v2.32.1-ca.1.tar.gz"
  version "2.32.1-ca.1"
  sha256 "aca4be126437774d18a74eb74b9c7bd0ccfa3232f2b070720c2178eaced0fbd7"
  license "Fair-Source-100"

  head "https://github.com/Operationrange/tart-ca.git", branch: "extra-ca"

  depends_on xcode: ["15.0", :build]
  depends_on macos: :ventura
  depends_on arch: :arm64

  conflicts_with "tart", because: "both install a `tart` binary"

  def install
    system "swift", "build", "--disable-sandbox", "--configuration", "release", "--arch", "arm64"
    bin.install ".build/release/tart" => "tart"
  end

  def caveats
    <<~EOS
      Set TART_EXTRA_CA_CERTS to a PEM/DER file, a directory of such files,
      or a colon-separated list of either to add custom CAs on top of the
      system trust store:

        export TART_EXTRA_CA_CERTS=/etc/ssl/internal-ca.pem
    EOS
  end

  test do
    assert_match "OVERVIEW:", shell_output("#{bin}/tart --help")
  end
end

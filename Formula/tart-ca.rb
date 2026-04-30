class TartCa < Formula
  desc "Tart fork with TART_EXTRA_CA_CERTS support for private/internal OCI registries"
  homepage "https://github.com/Operationrange/tart-ca"
  url "https://github.com/Operationrange/tart-ca/archive/refs/tags/v2.32.1-ca.2.tar.gz"
  version "2.32.1-ca.2"
  sha256 "8f0c55c16f014d7d2d31718f09af376d4ee0e22cec6760071669a2deb5b3908b"
  license "Fair-Source-100"

  head "https://github.com/Operationrange/tart-ca.git", branch: "extra-ca"

  depends_on xcode: ["15.0", :build]
  depends_on macos: :ventura
  depends_on arch: :arm64

  conflicts_with "tart", because: "both install a `tart` binary"

  def install
    system "swift", "build", "--disable-sandbox", "--configuration", "release", "--arch", "arm64"
    bin.install ".build/release/tart" => "tart"
    # Virtualization.framework requires the binary to be signed with the
    # com.apple.security.virtualization entitlement. Ad-hoc sign locally —
    # the upstream cask is signed with cirruslabs's Developer ID, which we
    # cannot reproduce here.
    system "codesign", "--force", "--sign", "-",
           "--entitlements", "Resources/tart-dev.entitlements",
           "--options", "runtime",
           "--timestamp=none",
           bin/"tart"
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

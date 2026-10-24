# Homebrew formula for Kleos
#
# To use, create a tap repo at github.com/Ghost-Frame/homebrew-kleos
# containing this file as Formula/kleos.rb, then:
#
#   brew tap ghost-frame/kleos
#   brew install kleos
#
# The SHA256 values below are placeholders. The release workflow should
# update them automatically, or run:
#   shasum -a 256 kleos-server-<platform>

class Kleos < Formula
  desc "Persistent semantic memory and cognitive infrastructure for AI agents"
  homepage "https://github.com/Ghost-Frame/Kleos"
  version "0.3.1"
  license "PolyForm-Noncommercial-1.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Ghost-Frame/Kleos/releases/download/v#{version}/kleos-server-darwin-arm64"
      sha256 "PLACEHOLDER"

      def install
        bin.install "kleos-server-darwin-arm64" => "kleos-server"
        # Fetch additional binaries
        %w[kleos-cli kleos-mcp].each do |tool|
          tool_url = "https://github.com/Ghost-Frame/Kleos/releases/download/v#{version}/#{tool}-darwin-arm64"
          system "curl", "-fsSL", "-o", "#{tool}", tool_url
          bin.install tool
        end
      end
    else
      url "https://github.com/Ghost-Frame/Kleos/releases/download/v#{version}/kleos-server-darwin-x64"
      sha256 "PLACEHOLDER"

      def install
        bin.install "kleos-server-darwin-x64" => "kleos-server"
        %w[kleos-cli kleos-mcp].each do |tool|
          tool_url = "https://github.com/Ghost-Frame/Kleos/releases/download/v#{version}/#{tool}-darwin-x64"
          system "curl", "-fsSL", "-o", "#{tool}", tool_url
          bin.install tool
        end
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/Ghost-Frame/Kleos/releases/download/v#{version}/kleos-server-linux-arm64"
      sha256 "PLACEHOLDER"

      def install
        bin.install "kleos-server-linux-arm64" => "kleos-server"
        %w[kleos-cli kleos-mcp].each do |tool|
          tool_url = "https://github.com/Ghost-Frame/Kleos/releases/download/v#{version}/#{tool}-linux-arm64"
          system "curl", "-fsSL", "-o", "#{tool}", tool_url
          bin.install tool
        end
      end
    else
      url "https://github.com/Ghost-Frame/Kleos/releases/download/v#{version}/kleos-server-linux-x64"
      sha256 "PLACEHOLDER"

      def install
        bin.install "kleos-server-linux-x64" => "kleos-server"
        %w[kleos-cli kleos-mcp].each do |tool|
          tool_url = "https://github.com/Ghost-Frame/Kleos/releases/download/v#{version}/#{tool}-linux-x64"
          system "curl", "-fsSL", "-o", "#{tool}", tool_url
          bin.install tool
        end
      end
    end
  end

  test do
    assert_match "kleos-server", shell_output("#{bin}/kleos-server --version 2>&1", 0)
  end
end

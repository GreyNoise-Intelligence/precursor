class PrecursorBin < Formula
  version '0.1.0'
  desc "A data analysis tool for text and binary tagging and filtering with similarity comparisons."
  homepage "https://github.com/GreyNoise-Intelligence/precursor"

  if OS.mac?
      url "https://github.com/GreyNoise-Intelligence/precursor/releases/download/#{version}/precursor-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "?"
  elsif OS.linux?
      url "https://github.com/GreyNoise-Intelligence/precursor/releases/download/#{version}/precursor-#{version}-x86_64-unknown-linux-musl.tar.gz"
      sha256 "?"
  end

  conflicts_with "precursor"

  def install
    bin.install "precursor"
  end
end

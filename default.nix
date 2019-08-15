with import (builtins.fetchGit {
  # Descriptive name to make the store path easier to identify
  name = "nixos-unstable-2019-08-15";
  url = https://github.com/nixos/nixpkgs/;
  # Commit hash for nixos-unstable as of 2018-09-12
  # `git ls-remote https://github.com/nixos/nixpkgs-channels nixos-unstable`
  rev = "8746c77a383f5c76153c7a181f3616d273acfa2a";
}) {};
  pkgs.rustPlatform.buildRustPackage rec {
  name = "rtahin-${version}";
  version = "0.1.0";
  src = ./.;
  cargoSha256 = "06j2pcicm2pmyf6p12dlizmxz6bj9mxwg76isfdc8gjsd7919h5f";
  meta = with stdenv.lib; {
    description = "Password Generator";
    homepage = https://github.com/mtesseract/rtahin;
    license = licenses.bsd;
    maintainers = [ maintainers.tailhook ];
    platforms = platforms.all;
  };
}
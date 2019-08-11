with import <nixpkgs> {};
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
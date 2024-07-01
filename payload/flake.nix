{
  description = "A basic flake with a shell";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = {
    nixpkgs,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      devShells.default = pkgs.stdenvNoCC.mkDerivation {
        name = "parasyte payload";

        # [other code omitted]
        # LOCALE_ARCHIVE = "${pkgs.glibcLocales}/lib/locale/locale-archive";
        nativeBuildInputs = with pkgs; [
          gdb
          cmake
          # ninja
          clang-tools
          clang
          # boost183
          # boost183.dev
        ];

        env = {
          # CMAKE_GENERATOR = "Ninja";
          # Boost_DIR= "/home/sehe/custom/boost/stage/lib/cmake";
          Boost_DIR= "${pkgs.boost183.dev}/lib/cmake";
        };
      };
    });
}

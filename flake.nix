{
  description = "BashLume — lightweight native completion and syntax highlighting for Bash";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "bashlume";
            version = "0.2.0";
            src = self;
            cargoLock.lockFile = ./Cargo.lock;

            dontCargoInstall = true;
            installPhase = ''
              runHook preInstall
              library=$(find target -type f -path '*/release/libbashlume.so' -print -quit)
              test -n "$library"
              install -Dm755 "$library" "$out/lib/bash/libbashlume.so"
              install -Dm755 target/release/bashlume-pack "$out/bin/bashlume-pack"
              install -Dm644 shell/bashlume.bash "$out/share/bashlume/bashlume.bash"
              substituteInPlace "$out/share/bashlume/bashlume.bash" \
                --replace-fail '@BASHLUME_LIBRARY@' "$out/lib/bash/libbashlume.so"
              runHook postInstall
            '';

            meta = {
              description = "Lightweight native completion and syntax highlighting for Bash";
              homepage = "https://github.com/Fadouse/BashLume";
              license = pkgs.lib.licenses.gpl2Plus;
              platforms = pkgs.lib.platforms.linux;
            };
          };
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              cargo
              rustc
              rustfmt
              clippy
              gcc
              pkg-config
              bashInteractive
              shellcheck
              python3
            ];
          };
        }
      );

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt);
    };
}

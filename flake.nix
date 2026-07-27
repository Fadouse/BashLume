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
          packLock = builtins.fromJSON (builtins.readFile ./rules/packs.lock);

          bashlumeCore = pkgs.rustPlatform.buildRustPackage {
            pname = "bashlume-core";
            version = "0.2.0";
            src = self;
            cargoLock.lockFile = ./Cargo.lock;

            dontCargoInstall = true;
            installPhase = ''
              runHook preInstall
              library=$(find target -type f -path '*/release/libbashlume.so' -print -quit)
              test -n "$library"
              pack_tool=$(find target -type f -path '*/release/bashlume-pack' -print -quit)
              test -n "$pack_tool"
              probe_helper=$(find target -type f -path '*/release/bashlume-probe' -print -quit)
              test -n "$probe_helper"
              install -Dm755 "$library" "$out/lib/bash/libbashlume.so"
              install -Dm755 "$probe_helper" "$out/lib/bash/bashlume-probe"
              install -Dm755 "$pack_tool" "$out/bin/bashlume-pack"
              install -Dm644 shell/bashlume.bash "$out/share/bashlume/bashlume.bash"
              mkdir -p "$out/share/bashlume/rules" "$out/share/bashlume/trusted-keys"
              install -m644 rules/trusted-keys/*.pub "$out/share/bashlume/trusted-keys/"
              substituteInPlace "$out/share/bashlume/bashlume.bash" \
                --replace-fail '@BASHLUME_LIBRARY@' "$out/lib/bash/libbashlume.so" \
                --replace-fail '@BASHLUME_RULE_PATH@' "$out/share/bashlume/rules" \
                --replace-fail '@BASHLUME_TRUSTED_KEY_PATH@' "$out/share/bashlume/trusted-keys"
              runHook postInstall
            '';

            meta = {
              description = "Lightweight native completion and syntax highlighting for Bash";
              homepage = "https://github.com/Fadouse/BashLume";
              license = pkgs.lib.licenses.gpl2Plus;
              platforms = supportedSystems;
            };
          };

          mkRulePack =
            source: license:
            let
              locked = packLock.packs.${source};
            in
            assert locked.channel == "stable";
            assert locked.asset == "${source}.blp";
            pkgs.stdenvNoCC.mkDerivation {
              pname = "bashlume-rules-${source}-stable";
              version = pkgs.lib.removePrefix "v" locked.version;
              src = pkgs.fetchurl {
                inherit (locked) url sha256;
              };
              dontUnpack = true;
              dontConfigure = true;
              dontBuild = true;
              installPhase = ''
                runHook preInstall
                verification=$(${bashlumeCore}/bin/bashlume-pack verify \
                  "$src" ${./rules/trusted-keys}/${source}-rules.pub)
                printf '%s\n' "$verification"
                grep -Fqx 'pack: org.bashlume.rules.${source}' <<<"$verification"
                grep -Fqx 'version: ${locked.version}' <<<"$verification"
                grep -Fqx 'stale: 0' <<<"$verification"
                install -Dm644 "$src" "$out/share/bashlume/rules/${locked.asset}"
                runHook postInstall
              '';
              meta = {
                description = "Pinned Stable ${source} completion rules for BashLume";
                homepage = "https://github.com/${locked.repository}";
                inherit license;
                platforms = supportedSystems;
              };
              passthru = {
                inherit (locked) repository sha256 url;
                release = locked.version;
              };
            };

          bashRules = mkRulePack "bash" pkgs.lib.licenses.gpl2Plus;
          fishRules = mkRulePack "fish" pkgs.lib.licenses.gpl2Only;
          zshRules = mkRulePack "zsh" {
            fullName = "GPL-2.0-only AND GPL-2.0-or-later AND LicenseRef-Zsh";
            shortName = "BashLume Zsh rule-pack licenses";
            free = true;
            redistributable = true;
          };
          packTool = pkgs.runCommand "bashlume-pack-tool-0.2.0" { } ''
            mkdir -p "$out/bin"
            ln -s ${bashlumeCore}/bin/bashlume-pack "$out/bin/bashlume-pack"
          '';
          bashlume = pkgs.symlinkJoin {
            name = "bashlume-0.2.0";
            paths = [
              bashlumeCore
              bashRules
            ];
            meta = bashlumeCore.meta // {
              description = "BashLume with pinned Stable Bash completion rules";
            };
          };
          bashlumeAllRules = pkgs.symlinkJoin {
            name = "bashlume-with-all-rules-0.2.0";
            paths = [
              bashlumeCore
              bashRules
              fishRules
              zshRules
            ];
            meta = bashlumeCore.meta // {
              description = "BashLume with pinned Stable Bash, Fish, and Zsh completion rules";
            };
          };
        in
        {
          default = bashlume;
          "bashlume-core" = bashlumeCore;
          "bashlume-pack-tool" = packTool;
          "bashlume-rules-bash-stable" = bashRules;
          "bashlume-rules-fish-stable" = fishRules;
          "bashlume-rules-zsh-stable" = zshRules;
          "bashlume-with-all-rules" = bashlumeAllRules;
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

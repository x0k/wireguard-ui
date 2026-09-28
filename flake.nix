{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-26.05";
    # golangci-lint can only analyse code with a Go version lower than or equal
    # to the one it was built with (golangci-lint#6643). The release in
    # nixos-26.05 is built with go 1.26 and refuses a go 1.27 module, so take
    # golangci-lint from unstable until 26.05 catches up.
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    mk.url = "github:x0k/mk";
  };
  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-unstable,
      mk,
    }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      pkgsUnstable = import nixpkgs-unstable { inherit system; };
    in
    {
      devShells.${system} = {
        default = pkgs.mkShell {
          buildInputs = [
            mk.packages.${system}.default
            pkgs.go_1_27
            pkgs.air
            pkgsUnstable.golangci-lint
          ];
        };
      };
    };
}

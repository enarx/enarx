let
  lock = builtins.fromJSON (builtins.readFile ./flake.lock);

  fetchInputFromGithub = name: with lock.nodes.${name}.locked; builtins.fetchTarball {
    url = "https://github.com/${owner}/${repo}/archive/${rev}.tar.gz";
    sha256 = narHash;
  };
  flakeCompat = fetchInputFromGithub "flake-compat";

  flake = import flakeCompat { src = ./.; };
in
flake.shellNix

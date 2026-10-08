# SPDX-License-Identifier: EUPL-1.2

{
  lib,
  dockerTools,
  bagel,
  cacert,
}:
dockerTools.streamLayeredImage {
  name = "bagel";
  tag = "latest";

  contents = [
    bagel
    cacert
  ];

  extraCommands = "mkdir -p var/lib/bagel";
  fakeRootCommands = "chown 1000:1000 var/lib/bagel";

  config = {
    User = "1000:1000";
    # The image never touches nftables; handle bans from `bagel bans`.
    Entrypoint = [
      (lib.getExe bagel)
      "--disable-firewall"
    ];
    Env = [
      "BAGEL_CONFIG=/etc/bagel/bagel.kdl"
      "PATH=/bin"
      "BAGEL_ADMIN_SOCKET=/var/lib/bagel/admin.sock"
      "XDG_DATA_HOME=/var/lib"
      "XDG_CACHE_HOME=/var/lib/bagel/cache"
    ];
    WorkingDir = "/var/lib/bagel";
  };
}

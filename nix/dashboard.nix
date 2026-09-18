# SPDX-License-Identifier: EUPL-1.2
#
# An example Grafana dashboard, which is rendered to contrib/grafana/bagel.json.

{
  lib,
  pkgs,
}:
let
  ds = {
    type = "prometheus";
    uid = "\${datasource}";
  };

  web = ''instance=~"$instance", site=~"$site"'';
  host = ''instance=~"$instance"'';

  rate =
    metric: by: sel:
    "sum by (${by}) (rate(${metric}{${sel}}[$__rate_interval]))";
  inRange = metric: sel: "sum(increase(${metric}{${sel}}[$__range])) or vector(0)";

  refIds = [
    "A"
    "B"
    "C"
    "D"
  ];

  grid =
    {
      x,
      y,
      w,
      h,
    }:
    {
      inherit
        x
        y
        w
        h
        ;
    };

  steps = warn: crit: [
    {
      color = "green";
      value = null;
    }
    {
      color = "orange";
      value = warn;
    }
    {
      color = "red";
      value = crit;
    }
  ];

  flat = [
    {
      color = "text";
      value = null;
    }
  ];

  stat =
    {
      title,
      description,
      expr,
      x,
      y ? 0,
      w ? 3,
      h ? 3,
      thresholds ? steps 1 1,
      unit ? "short",
      mappings ? [ ],
      noValue ? null,
    }:
    {
      inherit title description;
      type = "stat";
      datasource = ds;
      gridPos = grid {
        inherit
          x
          y
          w
          h
          ;
      };
      targets = [
        {
          refId = "A";
          datasource = ds;
          instant = true;
          inherit expr;
        }
      ];
      options = {
        colorMode = "value";
        graphMode = "none";
        textMode = "value";
        justifyMode = "center";
        wideLayout = true;
        reduceOptions = {
          calcs = [ "lastNotNull" ];
          fields = "";
          values = false;
        };
      };
      fieldConfig = {
        defaults = {
          inherit unit mappings;
          color.mode = "thresholds";
          thresholds = {
            mode = "absolute";
            steps = thresholds;
          };
        }
        // lib.optionalAttrs (noValue != null) { inherit noValue; };
        overrides = [ ];
      };
    };

  series =
    {
      title,
      description ? null,
      queries,
      x,
      y,
      w ? 8,
      h ? 9,
      unit ? "reqps",
      stack ? false,
      legend ? "bottom",
      overrides ? [ ],
    }:
    {
      inherit title;
      type = "timeseries";
      datasource = ds;
      gridPos = grid {
        inherit
          x
          y
          w
          h
          ;
      };
      targets = lib.imap0 (i: q: {
        inherit (q) expr;
        legendFormat = q.legend;
        refId = lib.elemAt refIds i;
        datasource = ds;
      }) queries;
      options = {
        legend = {
          displayMode = "list";
          placement = legend;
          showLegend = true;
          calcs = [ ];
        };
        tooltip = {
          mode = "multi";
          sort = "desc";
        };
      };
      fieldConfig = {
        defaults = {
          inherit unit;
          custom = {
            lineWidth = 1;
            fillOpacity = if stack then 35 else 8;
            gradientMode = "none";
            showPoints = "never";
            spanNulls = false;
            stacking.mode = if stack then "normal" else "none";
            axisSoftMin = 0;
          };
        };
        inherit overrides;
      };
    }
    // lib.optionalAttrs (description != null) { inherit description; };

  ranked =
    {
      title,
      description,
      expr,
      x,
      y,
      w ? 8,
      h ? 9,
    }:
    {
      inherit title description;
      type = "bargauge";
      datasource = ds;
      gridPos = grid {
        inherit
          x
          y
          w
          h
          ;
      };
      targets = [
        {
          refId = "A";
          datasource = ds;
          instant = true;
          format = "table";
          inherit expr;
        }
      ];
      transformations = [
        {
          id = "sortBy";
          options.sort = [
            {
              field = "Value";
              desc = true;
            }
          ];
        }
      ];
      options = {
        orientation = "horizontal";
        displayMode = "basic";
        valueMode = "color";
        namePlacement = "left";
        showUnfilled = true;
        sizing = "auto";
        minVizHeight = 14;
        maxVizHeight = 28;
        reduceOptions = {
          calcs = [ "lastNotNull" ];
          fields = "/^Value$/";
          values = true;
        };
      };
      fieldConfig = {
        defaults = {
          unit = "short";
          decimals = 0;
          min = 0;
          color.mode = "continuous-BlPu";
        };
        overrides = [ ];
      };
    };

  heatmap =
    {
      title,
      description,
      expr,
      x,
      y,
      w,
      h ? 9,
    }:
    {
      inherit title description;
      type = "heatmap";
      datasource = ds;
      gridPos = grid {
        inherit
          x
          y
          w
          h
          ;
      };
      targets = [
        {
          refId = "A";
          datasource = ds;
          format = "heatmap";
          legendFormat = "{{le}}";
          inherit expr;
        }
      ];
      options = {
        calculate = false;
        cellGap = 1;
        color = {
          mode = "scheme";
          scheme = "Oranges";
          steps = 48;
          reverse = false;
          exponent = 0.5;
          fill = "dark-orange";
        };
        yAxis = {
          axisPlacement = "left";
          reverse = false;
          unit = "short";
        };
        rowsFrame.layout = "auto";
        showValue = "never";
        legend.show = true;
        tooltip = {
          mode = "single";
          yHistogram = true;
          showColorScale = false;
        };
        exemplars.color = "rgba(255,0,255,0.7)";
        filterValues.le = 1.0e-9;
      };
      fieldConfig = {
        defaults.custom = {
          hideFrom = {
            legend = false;
            tooltip = false;
            viz = false;
          };
          scaleDistribution.type = "linear";
        };
        overrides = [ ];
      };
    };

  row =
    {
      title,
      y,
      collapsed ? false,
      panels ? [ ],
    }:
    {
      inherit title collapsed panels;
      type = "row";
      gridPos = grid {
        x = 0;
        inherit y;
        w = 24;
        h = 1;
      };
    };

  fixedColor = name: color: colorOverride "byName" name color;
  regexColor = pattern: color: colorOverride "byRegexp" "/${pattern}/" color;

  colorOverride = matcher: options: color: {
    matcher = {
      id = matcher;
      inherit options;
    };
    properties = [
      {
        id = "color";
        value = {
          mode = "fixed";
          fixedColor = color;
        };
      }
    ];
  };

  # The effective action is what the client saw, so it keeps one color
  # everywhere it appears.
  actionColors = [
    (fixedColor "proxy" "green")
    (fixedColor "pass" "dark-green")
    (fixedColor "challenge" "yellow")
    (fixedColor "check" "dark-yellow")
    (fixedColor "deny" "red")
    (fixedColor "block" "dark-red")
    (fixedColor "code" "orange")
    (fixedColor "drop" "dark-red")
    (fixedColor "tarpit" "purple")
    (fixedColor "smear" "blue")
    (fixedColor "unknown" "text")
  ];

  variable =
    {
      name,
      label,
      query,
      refresh,
    }:
    {
      inherit
        name
        label
        query
        refresh
        ;
      type = "query";
      datasource = ds;
      includeAll = true;
      allValue = ".*";
      multi = true;
      sort = 1;
      current = {
        text = "All";
        value = "$__all";
      };
    };

  health = [
    (stat {
      title = "Hosts down";
      description = "Scrape targets in the `bagel` job that are not up.";
      expr = ''count(up{job="bagel", ${host}} == 0) or vector(0)'';
      x = 0;
    })
    (stat {
      title = "Firewall";
      description = "nftables blocklist readiness on the least ready host. Off means no host exports the defense plane.";
      expr = "min(bagel_firewall_ready{${host}})";
      x = 3;
      noValue = "off";
      mappings = [
        {
          type = "value";
          options = {
            "0" = {
              text = "down";
              color = "red";
              index = 0;
            };
            "1" = {
              text = "ready";
              color = "green";
              index = 1;
            };
          };
        }
      ];
      thresholds = [
        {
          color = "red";
          value = null;
        }
        {
          color = "green";
          value = 1;
        }
      ];
    })
    (stat {
      title = "Blocked IPs";
      description = "Addresses currently in the firewall set.";
      expr = "sum(bagel_blocked_ips{${host}})";
      x = 6;
      thresholds = flat;
    })
    (stat {
      title = "Source lag";
      description = "Age of the newest record the defense plane has ingested.";
      expr = "max(bagel_source_lag_seconds{${host}})";
      x = 9;
      unit = "s";
      thresholds = steps 60 300;
    })
    (stat {
      title = "Signal errors";
      description = "Scoring signals whose condition failed at runtime, over the dashboard range. Any value is a policy bug.";
      expr = inRange "bagel_scoring_signal_error_total" web;
      x = 12;
    })
    (stat {
      title = "Dropped offenses";
      description = "Verdicts the web plane could not hand to defense because the queue was full, over the dashboard range.";
      expr = inRange "bagel_offenses_total" ''${web}, result="dropped"'';
      x = 15;
    })
    (stat {
      title = "Reconcile failures";
      description = "nftables reconciliations that failed, over the dashboard range.";
      expr = inRange "bagel_reconciliations_total" ''${host}, result="failure"'';
      x = 18;
    })
    (stat {
      title = "Solver fallbacks";
      description = "Challenges that handed out the static solver because the variant pool was empty or exhausted, over the dashboard range.";
      expr = inRange "bagel_solver_issued_total" ''${host}, source!="variant"'';
      x = 21;
    })
  ];

  traffic = [
    (row {
      title = "Traffic";
      y = 3;
    })
    (series {
      title = "Requests by outcome";
      description = "Every policy request once, by the action the client ended up with. `proxy` is the default when no rule or threshold handled it.";
      x = 0;
      y = 4;
      w = 16;
      stack = true;
      overrides = actionColors;
      queries = [
        {
          expr = rate "bagel_requests_total" "action" web;
          legend = "{{action}}";
        }
      ];
    })
    (ranked {
      title = "Rules";
      description = "Rule hits over the dashboard range. A request can match several nested rules, so these do not sum to a request count.";
      expr = ''topk(15, sum by (rule) (increase(bagel_rule_results{${web}, result="hit"}[$__range])))'';
      x = 16;
      y = 4;
    })
  ];

  scoring = [
    (row {
      title = "Scoring";
      y = 13;
    })
    (heatmap {
      title = "Score";
      description = "Scores of every scored request. Threshold bands show up as horizontal stripes, the top row is everything past 200.";
      expr = ''sum by (le) (rate(bagel_scoring_score_bucket{${web}, le!~"300.0|500.0"}[$__rate_interval]))'';
      x = 0;
      y = 14;
      w = 12;
    })
    (series {
      title = "Decisions";
      description = "`applied` means the threshold action ran. `suppressed_by_rule` means a terminal rule decided first. `no_candidate` is a score below every threshold, `observed` an observe-mode scorecard.";
      x = 12;
      y = 14;
      w = 12;
      stack = true;
      overrides = [
        (regexColor "^applied" "orange")
        (regexColor "^suppressed_by_rule" "blue")
        (regexColor "^no_candidate" "green")
        (regexColor "^observed" "purple")
      ];
      queries = [
        {
          expr = rate "bagel_scoring_decision_total" "status, action" web;
          legend = "{{status}} {{action}}";
        }
      ];
    })
    (series {
      title = "Signals";
      description = "Matched signals, weighted or observe-only. Signals overlap, one request can match several.";
      x = 0;
      y = 23;
      w = 16;
      queries = [
        {
          expr = rate "bagel_scoring_signal_total" "scorecard, signal" web;
          legend = "{{scorecard}} {{signal}}";
        }
      ];
    })
    (ranked {
      title = "Signals";
      description = "Signal matches over the dashboard range.";
      expr = "topk(15, sum by (scorecard, signal) (increase(bagel_scoring_signal_total{${web}}[$__range])))";
      x = 16;
      y = 23;
    })
  ];

  challenges = [
    (row {
      title = "Challenges";
      y = 33;
    })
    (series {
      title = "Challenges";
      description = "`issued` counts pages and embedded checks. `passed` includes reuse of a valid proof cookie, so it is not a solve rate.";
      x = 0;
      y = 34;
      queries = [
        {
          expr = rate "bagel_challenge_results" "challenge, action" web;
          legend = "{{challenge}} {{action}}";
        }
      ];
    })
    (series {
      title = "Proofs by level";
      description = "Verified proofs of work by the difficulty they were sealed at. One row per solve, so this is the real solve rate.";
      x = 8;
      y = 34;
      stack = true;
      queries = [
        {
          expr = rate "bagel_pow_verified_total" "challenge, level" web;
          legend = "{{challenge}} @{{level}}";
        }
      ];
    })
    (series {
      title = "Solver delivery";
      description = "`variant` is a per-challenge rewrite from the vela pool, `static` the build-time module. Issued above served is normal, an embedded check issues without a fetch.";
      x = 16;
      y = 34;
      queries = [
        {
          expr = rate "bagel_solver_issued_total" "source" host;
          legend = "issued {{source}}";
        }
        {
          expr = rate "bagel_solver_served_total" "source" host;
          legend = "served {{source}}";
        }
      ];
    })
    (series {
      title = "Render beacons";
      description = "`render` is a cleared session whose style engine fetched the beacon. `never` is a session that loaded documents and never rendered one, the shape of a headless fetcher.";
      x = 0;
      y = 43;
      w = 12;
      queries = [
        {
          expr = rate "bagel_beacon_total" "kind" web;
          legend = "{{kind}}";
        }
      ];
    })
    (series {
      title = "Maze";
      description = "Requests into the maze by what their token said, plus renderer outcomes other than ok.";
      x = 12;
      y = 43;
      w = 12;
      queries = [
        {
          expr = rate "bagel_poison_requests_total" "classification" web;
          legend = "{{classification}}";
        }
        {
          expr = rate "bagel_maze_renderer_requests_total" "result" ''${web}, result!="ok"'';
          legend = "render {{result}}";
        }
      ];
    })
  ];

  defense = [
    (row {
      title = "Defense";
      y = 52;
    })
    (series {
      title = "Offenses";
      description = "Verdicts the web plane sends to the escalation ladder, and what the defense side made of them. `unmatched` is a record no policy detector claimed.";
      x = 0;
      y = 53;
      queries = [
        {
          expr = rate "bagel_offenses_total" "kind, result" web;
          legend = "{{kind}} {{result}}";
        }
        {
          expr = rate "bagel_source_records_total" "outcome" host;
          legend = "ingest {{outcome}}";
        }
      ];
    })
    (series {
      title = "Policy matches";
      description = "`accepted` counts toward a ban, `ignored` fell outside the find time, `protected` was an allowlisted address.";
      x = 8;
      y = 53;
      queries = [
        {
          expr = rate "bagel_policy_matches_total" "policy" ''${host}, disposition="accepted"'';
          legend = "{{policy}}";
        }
        {
          expr = rate "bagel_policy_matches_total" "disposition" ''${host}, disposition!="accepted"'';
          legend = "{{disposition}}";
        }
      ];
    })
    (series {
      title = "Active leases";
      description = "Addresses currently banned, by the policy that banned them.";
      x = 16;
      y = 53;
      unit = "short";
      stack = true;
      queries = [
        {
          expr = "sum by (policy) (bagel_active_leases{${host}})";
          legend = "{{policy}}";
        }
      ];
    })
  ];

  tarpits = [
    (row {
      title = "Tarpit endpoints";
      y = 62;
      collapsed = true;
      panels = [
        (series {
          title = "Hits by category";
          description = "Connections classified by what the client probed for.";
          x = 0;
          y = 63;
          stack = true;
          queries = [
            {
              expr = rate "bagel_endpoint_hits_total" "category" host;
              legend = "{{category}}";
            }
          ];
        })
        (series {
          title = "Held connections";
          description = "Connections currently sitting in a tarpit, against the configured capacity.";
          x = 8;
          y = 63;
          unit = "short";
          queries = [
            {
              expr = "sum by (endpoint) (bagel_endpoint_active_connections{${host}})";
              legend = "{{endpoint}}";
            }
            {
              expr = "sum by (endpoint) (bagel_endpoint_tarpit_capacity{${host}})";
              legend = "{{endpoint}} capacity";
            }
          ];
        })
        (series {
          title = "Rejected";
          description = "Connections turned away because an endpoint or a single address hit its capacity.";
          x = 16;
          y = 63;
          queries = [
            {
              expr = rate "bagel_endpoint_rejected_total" "endpoint, reason" host;
              legend = "{{endpoint}} {{reason}}";
            }
          ];
        })
      ];
    })
  ];

  numbered =
    panels:
    lib.imap1 (
      id: panel:
      panel
      // {
        inherit id;
      }
      // lib.optionalAttrs (panel.type == "row") {
        panels = lib.imap1 (n: inner: inner // { id = id * 10 + n; }) panel.panels;
      }
    ) panels;

  dashboard = {
    uid = "bagel";
    title = "bagel";
    description = "Traffic, scoring, challenges and the defense plane of a bagel deployment.";
    tags = [ "bagel" ];
    editable = true;
    graphTooltip = 1;
    timezone = "browser";
    schemaVersion = 39;
    refresh = "1m";
    time = {
      from = "now-6h";
      to = "now";
    };
    templating.list = [
      {
        name = "datasource";
        label = "Datasource";
        type = "datasource";
        query = "prometheus";
        refresh = 1;
        current = { };
      }
      (variable {
        name = "instance";
        label = "Host";
        query = "label_values(bagel_rule_results, instance)";
        refresh = 1;
      })
      (variable {
        name = "site";
        label = "Site";
        query = ''label_values(bagel_rule_results{instance=~"$instance"}, site)'';
        refresh = 2;
      })
    ];
    panels = numbered (health ++ traffic ++ scoring ++ challenges ++ defense ++ tarpits);
  };
in
pkgs.runCommand "bagel-dashboard.json" { nativeBuildInputs = [ pkgs.jq ]; } ''
  jq --indent 2 . ${pkgs.writeText "bagel-dashboard-raw.json" (builtins.toJSON dashboard)} > $out
''

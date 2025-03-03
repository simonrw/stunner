# Stunner

Stunner is a small Go CLI tool which will send requests to multiple Tailscale DERP servers and provide you information about the results.

This will help you figure out what type of NAT you're behind.

```
+----------------------------+-------+----------------+
|        STUN SERVER         | PORT  |       IP       |
+----------------------------+-------+----------------+
| derp21b.tailscale.com:3478 | 54320 | <redacted>     |
| derp17d.tailscale.com:3478 | 54320 | <redacted>     |
+----------------------------+-------+----------------+
+--------+-----------+-----------+--------------------------------+
| RESULT | NAT TYPE  | EASY/HARD |             DETAIL             |
+--------+-----------+-----------+--------------------------------+
| Final  | Full Cone | Easy      | No inbound restrictions once   |
|        |           |           | mapped.                        |
+--------+-----------+-----------+--------------------------------+
```
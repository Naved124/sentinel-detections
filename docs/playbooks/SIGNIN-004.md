# SIGNIN-004: Impossible travel between successful sign-ins

**Severity:** Medium · **Tactics:** Initial Access · **Techniques:** [T1078.004](https://attack.mitre.org/techniques/T1078/004/) · **Data:** SigninLogs

Two successful sign-ins for the same account came from places at least 500 km apart, closer
together in time than a commercial flight could cover (over 900 km/h). This usually means the
credentials or a session token are being used by someone else, or the user is behind a VPN.

## Triage steps

1. Look up both IPs. If either belongs to a VPN, proxy or cloud provider, check whether the user or company uses that service.
2. Ask the user where they were at FirstTime and SecondTime and which devices they used.
3. Compare user agents and devices for the two sign-ins. A device the user has never used before is a strong signal.
4. Review activity from the second session - mailbox access, file downloads, MFA changes, app consents.
5. If the user cannot explain it, revoke sessions and reset the password.

## Common false positives

- Corporate or personal VPNs and secure web gateways that exit in another country.
- Mobile carriers that geolocate phones to a distant gateway city.
- IP geolocation errors, which are common for new or reassigned IP ranges.

## Escalate when

Escalate if the user did not travel, does not use a VPN that explains the second location,
and the second session did anything beyond reading mail.

## Query

```kql
let lookback = 1d;
let max_speed_kmh = 900.0;
let min_distance_km = 500.0;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == "0"
| extend Lat = todouble(LocationDetails.geoCoordinates.latitude),
         Lon = todouble(LocationDetails.geoCoordinates.longitude),
         Place = strcat(tostring(LocationDetails.city), ", ", tostring(LocationDetails.countryOrRegion))
| where isnotnull(Lat) and isnotnull(Lon)
| project TimeGenerated, UserPrincipalName, IPAddress, Lat, Lon, Place
| sort by UserPrincipalName asc, TimeGenerated asc
| extend PrevUser = prev(UserPrincipalName), PrevTime = prev(TimeGenerated), PrevIP = prev(IPAddress),
         PrevLat = prev(Lat), PrevLon = prev(Lon), PrevPlace = prev(Place)
| where PrevUser == UserPrincipalName
| extend DistanceKm = geo_distance_2points(PrevLon, PrevLat, Lon, Lat) / 1000.0,
         Hours = (TimeGenerated - PrevTime) / 1h
| extend SpeedKmh = iff(Hours <= 0.0, real(+inf), DistanceKm / Hours)
| where DistanceKm >= min_distance_km and SpeedKmh > max_speed_kmh
| project UserPrincipalName, FirstTime = PrevTime, FirstIP = PrevIP, FirstPlace = PrevPlace,
    SecondTime = TimeGenerated, IPAddress, SecondPlace = Place,
    DistanceKm = round(DistanceKm, 0), SpeedKmh = round(SpeedKmh, 0)
```

Runs every 1h over the last 1d. Source: [`rules/SIGNIN-004.yaml`](../../rules/SIGNIN-004.yaml)
